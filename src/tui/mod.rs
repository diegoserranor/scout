//! TUI front-end: the no-arg `scout` experience. First cut covers the Discover stage.

mod app;
mod ui;

use std::error::Error;

use app::App;

/// Launch the TUI: set up the terminal, run the app, and always restore on exit.
pub async fn run() -> Result<(), Box<dyn Error>> {
    let mut terminal = ratatui::init();
    let result = App::new().run(&mut terminal).await;
    ratatui::restore();
    result
}
