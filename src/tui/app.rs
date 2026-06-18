//! TUI application state and the async event loop driving the Discover → Scope → Inspect flow.

use std::error::Error;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;
use tokio::sync::mpsc;
use tokio::time::{self, Duration};

use super::ui;
use crate::core::{self, Host, HostReport, PortSpec};

/// How often the loop wakes to advance the spinner (and otherwise idle-redraw).
const SPINNER_TICK: Duration = Duration::from_millis(100);

/// Port presets offered on the Scope screen, in display order. The last entry is
/// the free-text [`CUSTOM_PRESET`], which opens an input field instead of a fixed spec.
pub const PRESET_LABELS: [&str; 4] = ["Web", "Common", "All", "Custom"];

/// Index of the free-text "Custom" entry in [`PRESET_LABELS`].
pub const CUSTOM_PRESET: usize = 3;

/// The [`PortSpec`] for a fixed preset index. Not valid for [`CUSTOM_PRESET`],
/// whose spec is parsed from user input instead.
fn preset_spec(index: usize) -> PortSpec {
    match index {
        0 => PortSpec::Web,
        1 => PortSpec::Common,
        _ => PortSpec::All,
    }
}

/// Human-readable summary of the ports a preset covers, for the Scope footnote.
/// The fixed presets derive from [`PortSpec::resolve`] so they can't drift from
/// the core port lists; Custom shows an input example.
pub fn preset_hint(index: usize) -> String {
    match index {
        CUSTOM_PRESET => "e.g. 1-100 or 22,80,443".to_string(),
        _ => match preset_spec(index) {
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
        },
    }
}

/// Which screen of the flow is currently shown.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Discover,
    Scope,
    Inspect,
}

/// State of the background discover scan. `Running` carries the hosts found so
/// far, so the list renders and grows live as results stream in.
pub enum Scan {
    Running(Vec<Host>),
    Done(Vec<Host>),
    Failed(String),
}

/// State of the inspect run for the selected host. Both `Running` and `Done`
/// carry the latest report snapshot (`None` until the first one arrives; a `Done`
/// with `None` means the host had no open ports).
pub enum Inspection {
    Running(Option<HostReport>),
    Done(Option<HostReport>),
    Failed(String),
}

/// Side effect the event loop must perform after handling an event.
enum Action {
    None,
    Inspect { host: Host, spec: PortSpec },
    CancelInspect,
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
    /// Whether the Custom preset's free-text input is currently capturing keys.
    pub editing: bool,
    /// Buffer backing the Custom port input.
    pub port_input: String,
    pub inspection: Inspection,
    pub spinner_frame: usize,
    should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Discover,
            discover: Scan::Running(Vec::new()),
            host_list: TableState::default(),
            target: None,
            preset: 0,
            editing: false,
            port_input: String::new(),
            inspection: Inspection::Running(None),
            spinner_frame: 0,
            should_quit: false,
        }
    }

    /// Run the event loop until the user quits, redrawing on every wake-up.
    pub async fn run(mut self, terminal: &mut DefaultTerminal) -> Result<(), Box<dyn Error>> {
        // Start discover; core spawns the sweep and streams live hosts back. Setup
        // errors surface synchronously, so a failure shows immediately.
        let mut discover_rx = match core::discover() {
            Ok(rx) => Some(rx),
            Err(err) => {
                self.discover = Scan::Failed(err.to_string());
                None
            }
        };

        // Inspect runs on demand once the user picks a host + preset; core streams
        // report snapshots back over this receiver while it's set.
        let mut inspect_rx: Option<mpsc::Receiver<HostReport>> = None;

        // crossterm reads are blocking, so pull input on a dedicated thread and
        // forward each event over a channel the loop can select on.
        let mut input = spawn_input_reader();
        let mut ticker = time::interval(SPINNER_TICK);

        while !self.should_quit {
            terminal.draw(|frame| ui::draw(frame, &mut self))?;

            tokio::select! {
                Some(event) = input.recv() => {
                    match self.on_event(&event) {
                        // Replacing/clearing the receiver drops the old one, which
                        // signals core's coordinator to stop (its sends start failing).
                        Action::Inspect { host, spec } => {
                            inspect_rx = self.spawn_inspect(host, spec);
                        }
                        Action::CancelInspect => inspect_rx = None,
                        Action::None => {}
                    }
                }
                _ = ticker.tick() => self.spinner_frame = self.spinner_frame.wrapping_add(1),
                host = async { discover_rx.as_mut().unwrap().recv().await }, if discover_rx.is_some() => {
                    match host {
                        Some(host) => self.push_discovered(host),
                        // Channel closed: the sweep finished.
                        None => {
                            discover_rx = None;
                            if let Scan::Running(hosts) = &mut self.discover {
                                self.discover = Scan::Done(std::mem::take(hosts));
                            }
                        }
                    }
                }
                report = async { inspect_rx.as_mut().unwrap().recv().await }, if inspect_rx.is_some() => {
                    // Ignore late results once the user has left the Inspect screen.
                    match report {
                        Some(report) if self.screen == Screen::Inspect => {
                            self.inspection = Inspection::Running(Some(report));
                        }
                        Some(_) => {}
                        // Channel closed: the scan finished. Settle Running → Done.
                        None => {
                            inspect_rx = None;
                            if let Inspection::Running(report) = &mut self.inspection {
                                self.inspection = Inspection::Done(report.take());
                            }
                        }
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

        // Ctrl-C quits from anywhere; bare `q` quits too, except while typing a
        // custom port spec (where it's just a character).
        let ctrl_c =
            key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl_c || (key.code == KeyCode::Char('q') && !self.editing) {
            self.should_quit = true;
            return Action::None;
        }

        match self.screen {
            Screen::Discover => self.on_discover_key(key.code),
            Screen::Scope => return self.on_scope_key(key.code),
            Screen::Inspect => return self.on_inspect_key(key.code),
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
                    self.editing = false;
                    self.screen = Screen::Scope;
                }
            }
            _ => {}
        }
    }

    fn on_scope_key(&mut self, code: KeyCode) -> Action {
        if self.editing {
            return self.on_custom_key(code);
        }
        match code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::Left => {
                self.preset = self.preset.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Right => {
                self.preset = (self.preset + 1).min(PRESET_LABELS.len() - 1);
            }
            KeyCode::Esc => self.screen = Screen::Discover,
            KeyCode::Enter => return self.confirm_scope(),
            _ => {}
        }
        Action::None
    }

    /// Enter pressed on the preset menu: open the input for Custom, otherwise
    /// inspect the target with the chosen preset.
    fn confirm_scope(&mut self) -> Action {
        if self.preset == CUSTOM_PRESET {
            self.editing = true;
            return Action::None;
        }
        self.start_inspect(preset_spec(self.preset))
    }

    /// Handle a key while the Custom port input is capturing. Enter inspects when
    /// the buffer parses; a parse error keeps the user in the input (the preview
    /// shows why). Esc returns to the preset menu.
    fn on_custom_key(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Char(c) => self.port_input.push(c),
            KeyCode::Backspace => {
                self.port_input.pop();
            }
            KeyCode::Esc => self.editing = false,
            KeyCode::Enter => {
                if let Ok(spec) = self.port_input.parse::<PortSpec>() {
                    self.editing = false;
                    return self.start_inspect(spec);
                }
            }
            _ => {}
        }
        Action::None
    }

    /// Move to the Inspect screen and ask the loop to run the scan, or fall back
    /// to Discover if the target was somehow lost.
    fn start_inspect(&mut self, spec: PortSpec) -> Action {
        if let Some(host) = self.target.clone() {
            self.screen = Screen::Inspect;
            self.inspection = Inspection::Running(None);
            return Action::Inspect { host, spec };
        }
        self.screen = Screen::Discover;
        Action::None
    }

    /// Start a streamed inspect for one host, returning the report receiver, or
    /// recording a setup failure and returning `None`.
    fn spawn_inspect(&mut self, host: Host, spec: PortSpec) -> Option<mpsc::Receiver<HostReport>> {
        match core::scope(vec![host.ip], spec).and_then(core::inspect) {
            Ok(rx) => Some(rx),
            Err(err) => {
                self.inspection = Inspection::Failed(err.to_string());
                None
            }
        }
    }

    fn on_inspect_key(&mut self, code: KeyCode) -> Action {
        if matches!(code, KeyCode::Esc | KeyCode::Backspace) {
            self.screen = Screen::Discover;
            return Action::CancelInspect;
        }
        Action::None
    }

    /// Record a host streamed in from the discover sweep, selecting the first
    /// row as soon as one arrives.
    fn push_discovered(&mut self, host: Host) {
        if let Scan::Running(hosts) = &mut self.discover {
            if hosts.is_empty() {
                self.host_list.select(Some(0));
            }
            hosts.push(host);
        }
    }

    /// The discovered hosts found so far, whether the sweep is still running or done.
    fn discovered_hosts(&self) -> &[Host] {
        match &self.discover {
            Scan::Running(hosts) | Scan::Done(hosts) => hosts,
            Scan::Failed(_) => &[],
        }
    }

    /// The host currently highlighted in the discovered list, if any.
    fn selected_host(&self) -> Option<Host> {
        let hosts = self.discovered_hosts();
        self.host_list.selected().and_then(|i| hosts.get(i)).cloned()
    }

    /// Number of selectable rows in the discovered list.
    fn row_count(&self) -> usize {
        self.discovered_hosts().len()
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
