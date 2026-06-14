//! Rendering for the TUI: a pure function from [`App`] state to widgets.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::widgets::{Block, Paragraph, Row, Table};

use super::app::{App, Scan};

/// Braille spinner frames cycled while a scan is running.
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Draw the whole screen: a title line, the body (spinner / table / message),
/// and a footer with the active key hints.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(Paragraph::new(" scout — discover").bold(), header);
    draw_body(frame, app, body);
    frame.render_widget(Paragraph::new(footer_hints(&app.scan)).dim(), footer);
}

/// Render the body area based on the current scan state.
fn draw_body(frame: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    match &app.scan {
        Scan::Running => {
            let spinner = SPINNER[app.spinner_frame % SPINNER.len()];
            let widget = Paragraph::new(format!("{spinner} Discovering live hosts…"))
                .block(Block::bordered().title("Discover"));
            frame.render_widget(widget, area);
        }
        Scan::Done(hosts) if hosts.is_empty() => {
            let widget = Paragraph::new("No live hosts found on local networks.")
                .block(Block::bordered().title("Discover"));
            frame.render_widget(widget, area);
        }
        Scan::Done(hosts) => {
            let rows = hosts
                .iter()
                .map(|host| Row::new(vec![host.ip.to_string(), host.subnet.to_string()]));
            let table = Table::new(rows, [Constraint::Length(18), Constraint::Min(10)])
                .header(Row::new(vec!["Host", "Subnet"]).bold())
                .block(Block::bordered().title(format!("Discover — {} live", hosts.len())))
                .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
                .highlight_symbol("› ");
            frame.render_stateful_widget(table, area, &mut app.table_state);
        }
        Scan::Failed(err) => {
            let widget = Paragraph::new(format!("Discover failed: {err}"))
                .block(Block::bordered().title("Discover"))
                .red();
            frame.render_widget(widget, area);
        }
    }
}

/// The footer key hints for the current state.
fn footer_hints(scan: &Scan) -> &'static str {
    match scan {
        Scan::Done(hosts) if !hosts.is_empty() => "↑/↓ or j/k: navigate    q: quit",
        _ => "q: quit",
    }
}
