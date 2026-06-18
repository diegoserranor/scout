//! TUI application state and the async event loop driving the Discover → Scope → Inspect flow.

use std::error::Error;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

use super::ui;
use crate::core::{self, Host, HostReport, PortSpec};

/// How often the loop wakes to advance the spinner (and otherwise idle-redraw).
const SPINNER_TICK: Duration = Duration::from_millis(100);

/// Port presets offered on the Scope screen, in display order.
pub const PRESET_LABELS: [&str; 3] = ["Web", "Common", "All"];

/// The [`PortSpec`] for a preset index (clamped to [`PortSpec::All`]).
fn preset_spec(index: usize) -> PortSpec {
    match index {
        0 => PortSpec::Web,
        1 => PortSpec::Common,
        _ => PortSpec::All,
    }
}

/// Human-readable summary of the ports a preset covers, for the Scope footnote.
/// Derived from [`PortSpec::resolve`] so it can't drift from the core port lists.
pub fn preset_hint(index: usize) -> String {
    match preset_spec(index) {
        PortSpec::All => "1-65535".to_string(),
        spec => spec
            .resolve()
            .map(|ports| {
                ports
                    .iter()
                    .map(|port| port.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
    }
}

/// Which screen of the flow is currently shown.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Discover,
    Scope,
    Inspect,
}

/// State of the background discover scan.
pub enum Scan {
    Running,
    Done(Vec<Host>),
    Failed(String),
}

/// State of the inspect run for the selected host.
pub enum Inspection {
    Running,
    /// Finished; `None` means the host had no open ports.
    Done(Option<HostReport>),
    Failed(String),
}

/// Side effect the event loop must perform after handling an event.
enum Action {
    None,
    Inspect { host: Host, spec: PortSpec },
}

/// The TUI's mutable state, owned by the event loop.
pub struct App {
    pub screen: Screen,
    pub discover: Scan,
    pub host_list: TableState,
    /// Host chosen on Discover, carried through Scope and Inspect.
    pub target: Option<Host>,
    /// Selected preset index on the Scope screen.
    pub preset: usize,
    pub inspection: Inspection,
    pub spinner_frame: usize,
    should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Discover,
            discover: Scan::Running,
            host_list: TableState::default(),
            target: None,
            preset: 0,
            inspection: Inspection::Running,
            spinner_frame: 0,
            should_quit: false,
        }
    }

    /// Run the event loop until the user quits, redrawing on every wake-up.
    pub async fn run(mut self, terminal: &mut DefaultTerminal) -> Result<(), Box<dyn Error>> {
        // Kick off discover as a task. Map its error to a String so the task's
        // output is `Send` (the core error is a bare `Box<dyn Error>`).
        let mut discover_task =
            tokio::spawn(async move { core::discover().await.map_err(|e| e.to_string()) });
        let mut discover_done = false;

        // Inspect runs on demand once the user picks a host + preset.
        let mut inspect_task: Option<JoinHandle<Result<Option<HostReport>, String>>> = None;

        // crossterm reads are blocking, so pull input on a dedicated thread and
        // forward each event over a channel the loop can select on.
        let mut input = spawn_input_reader();
        let mut ticker = time::interval(SPINNER_TICK);

        while !self.should_quit {
            terminal.draw(|frame| ui::draw(frame, &mut self))?;

            tokio::select! {
                Some(event) = input.recv() => {
                    if let Action::Inspect { host, spec } = self.on_event(&event) {
                        // Abandon any in-flight inspect before starting a new one.
                        if let Some(task) = inspect_task.take() {
                            task.abort();
                        }
                        let targets = vec![host.ip];
                        inspect_task = Some(tokio::spawn(async move {
                            let plan = core::scope(targets, spec).map_err(|e| e.to_string())?;
                            let reports = core::inspect(plan).await.map_err(|e| e.to_string())?;
                            Ok(reports.into_iter().next())
                        }));
                    }
                }
                _ = ticker.tick() => self.spinner_frame = self.spinner_frame.wrapping_add(1),
                result = &mut discover_task, if !discover_done => {
                    discover_done = true;
                    self.discover = match result {
                        Ok(Ok(hosts)) => {
                            if !hosts.is_empty() {
                                self.host_list.select(Some(0));
                            }
                            Scan::Done(hosts)
                        }
                        Ok(Err(err)) => Scan::Failed(err),
                        Err(err) => Scan::Failed(format!("scan task failed: {err}")),
                    };
                }
                result = async { inspect_task.as_mut().unwrap().await }, if inspect_task.is_some() => {
                    inspect_task = None;
                    let outcome = match result {
                        Ok(Ok(report)) => Inspection::Done(report),
                        Ok(Err(err)) => Inspection::Failed(err),
                        Err(err) => Inspection::Failed(format!("inspect task failed: {err}")),
                    };
                    // Drop the result if the user has already left the Inspect screen.
                    if self.screen == Screen::Inspect {
                        self.inspection = outcome;
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle a single input event, returning any side effect for the loop to run.
    fn on_event(&mut self, event: &Event) -> Action {
        let Event::Key(key) = event else {
            return Action::None;
        };
        if key.kind != KeyEventKind::Press {
            return Action::None;
        }

        // `q` / Ctrl-C quit from any screen.
        let ctrl_c =
            key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        if key.code == KeyCode::Char('q') || ctrl_c {
            self.should_quit = true;
            return Action::None;
        }

        match self.screen {
            Screen::Discover => self.on_discover_key(key.code),
            Screen::Scope => return self.on_scope_key(key.code),
            Screen::Inspect => self.on_inspect_key(key.code),
        }
        Action::None
    }

    fn on_discover_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_previous(),
            KeyCode::Enter => {
                if let Some(host) = self.selected_host() {
                    self.target = Some(host);
                    self.preset = 0;
                    self.screen = Screen::Scope;
                }
            }
            _ => {}
        }
    }

    fn on_scope_key(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::Left => {
                self.preset = self.preset.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Right => {
                self.preset = (self.preset + 1).min(PRESET_LABELS.len() - 1);
            }
            KeyCode::Esc => self.screen = Screen::Discover,
            KeyCode::Enter => {
                if let Some(host) = self.target.clone() {
                    self.screen = Screen::Inspect;
                    self.inspection = Inspection::Running;
                    return Action::Inspect {
                        host,
                        spec: preset_spec(self.preset),
                    };
                }
                self.screen = Screen::Discover;
            }
            _ => {}
        }
        Action::None
    }

    fn on_inspect_key(&mut self, code: KeyCode) {
        if matches!(code, KeyCode::Esc | KeyCode::Backspace) {
            self.screen = Screen::Discover;
        }
    }

    /// The host currently highlighted in the discovered list, if any.
    fn selected_host(&self) -> Option<Host> {
        let Scan::Done(hosts) = &self.discover else {
            return None;
        };
        self.host_list.selected().and_then(|i| hosts.get(i)).cloned()
    }

    /// Number of selectable rows in the discovered list.
    fn row_count(&self) -> usize {
        match &self.discover {
            Scan::Done(hosts) => hosts.len(),
            _ => 0,
        }
    }

    fn select_next(&mut self) {
        let count = self.row_count();
        if count == 0 {
            return;
        }
        let next = self.host_list.selected().map_or(0, |i| (i + 1).min(count - 1));
        self.host_list.select(Some(next));
    }

    fn select_previous(&mut self) {
        if self.row_count() == 0 {
            return;
        }
        let previous = self.host_list.selected().map_or(0, |i| i.saturating_sub(1));
        self.host_list.select(Some(previous));
    }
}

/// Spawn a thread that blocks on crossterm input and forwards events over a channel.
fn spawn_input_reader() -> mpsc::Receiver<Event> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::spawn(move || {
        while let Ok(event) = event::read() {
            if tx.blocking_send(event).is_err() {
                break;
            }
        }
    });
    rx
}
