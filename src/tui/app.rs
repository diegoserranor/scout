//! TUI application state and the async event loop driving the Discover stage.

use std::error::Error;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;
use tokio::sync::mpsc;
use tokio::time::{self, Duration};

use super::ui;
use crate::core::{self, Host};

/// How often the loop wakes to advance the spinner (and otherwise idle-redraw).
const SPINNER_TICK: Duration = Duration::from_millis(100);

/// State of the background discover scan.
pub enum Scan {
    Running,
    Done(Vec<Host>),
    Failed(String),
}

/// The TUI's mutable state, owned by the event loop.
pub struct App {
    pub scan: Scan,
    pub table_state: TableState,
    pub spinner_frame: usize,
    should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            scan: Scan::Running,
            table_state: TableState::default(),
            spinner_frame: 0,
            should_quit: false,
        }
    }

    /// Run the event loop until the user quits, redrawing on every wake-up.
    pub async fn run(mut self, terminal: &mut DefaultTerminal) -> Result<(), Box<dyn Error>> {
        // Kick off discover as a task. Map its error to a String so the task's
        // output is `Send` (the core error is a bare `Box<dyn Error>`).
        let mut scan = tokio::spawn(async move { core::discover().await.map_err(|e| e.to_string()) });
        let mut scan_done = false;

        // crossterm reads are blocking, so pull input on a dedicated thread and
        // forward each event over a channel the loop can select on.
        let mut input = spawn_input_reader();
        let mut ticker = time::interval(SPINNER_TICK);

        while !self.should_quit {
            terminal.draw(|frame| ui::draw(frame, &mut self))?;

            tokio::select! {
                Some(event) = input.recv() => self.on_event(&event),
                _ = ticker.tick() => self.spinner_frame = self.spinner_frame.wrapping_add(1),
                result = &mut scan, if !scan_done => {
                    scan_done = true;
                    self.scan = match result {
                        Ok(Ok(hosts)) => {
                            if !hosts.is_empty() {
                                self.table_state.select(Some(0));
                            }
                            Scan::Done(hosts)
                        }
                        Ok(Err(err)) => Scan::Failed(err),
                        Err(err) => Scan::Failed(format!("scan task failed: {err}")),
                    };
                }
            }
        }

        Ok(())
    }

    /// Handle a single input event.
    fn on_event(&mut self, event: &Event) {
        let Event::Key(key) = event else { return };
        if key.kind != KeyEventKind::Press {
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true
            }
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_previous(),
            _ => {}
        }
    }

    /// Number of selectable rows in the current state.
    fn row_count(&self) -> usize {
        match &self.scan {
            Scan::Done(hosts) => hosts.len(),
            _ => 0,
        }
    }

    fn select_next(&mut self) {
        let count = self.row_count();
        if count == 0 {
            return;
        }
        let next = self.table_state.selected().map_or(0, |i| (i + 1).min(count - 1));
        self.table_state.select(Some(next));
    }

    fn select_previous(&mut self) {
        if self.row_count() == 0 {
            return;
        }
        let previous = self.table_state.selected().map_or(0, |i| i.saturating_sub(1));
        self.table_state.select(Some(previous));
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
