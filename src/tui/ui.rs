//! Rendering for the TUI: a pure function from [`App`] state to widgets.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Row, Table};

use super::app::{App, Inspection, PRESET_LABELS, Scan, Screen};
use crate::core::HostReport;

/// Braille spinner frames cycled while a scan is running.
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Draw the whole screen: a title line, the body (per current screen), and a
/// footer with the active key hints.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(Paragraph::new(title(app)).bold(), header);
    match app.screen {
        Screen::Discover => draw_discover(frame, app, body),
        Screen::Scope => draw_scope(frame, app, body),
        Screen::Inspect => draw_inspect(frame, app, body),
    }
    frame.render_widget(Paragraph::new(footer_hints(app)).dim(), footer);
}

/// The header title line for the current screen.
fn title(app: &App) -> String {
    let target = app
        .target
        .as_ref()
        .map(|host| host.ip.to_string())
        .unwrap_or_default();
    match app.screen {
        Screen::Discover => " scout — discover".to_string(),
        Screen::Scope => format!(" scout — scope {target}"),
        Screen::Inspect => format!(" scout — inspect {target}"),
    }
}

/// Discover screen: spinner while scanning, then the live-host table.
fn draw_discover(frame: &mut Frame, app: &mut App, area: Rect) {
    match &app.discover {
        Scan::Running => {
            let widget = Paragraph::new(format!("{} Discovering live hosts…", spinner(app)))
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
            frame.render_stateful_widget(table, area, &mut app.host_list);
        }
        Scan::Failed(err) => {
            let widget = Paragraph::new(format!("Discover failed: {err}"))
                .block(Block::bordered().title("Discover"))
                .red();
            frame.render_widget(widget, area);
        }
    }
}

/// Scope screen: pick a port preset for the selected host.
fn draw_scope(frame: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line> = PRESET_LABELS
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let line = Line::from(format!(" {label}"));
            if i == app.preset {
                line.bold().reversed()
            } else {
                line
            }
        })
        .collect();
    let widget = Paragraph::new(lines).block(Block::bordered().title("Scope — choose ports"));
    frame.render_widget(widget, area);
}

/// Inspect screen: spinner while probing, then the host report.
fn draw_inspect(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::bordered().title("Inspect");
    match &app.inspection {
        Inspection::Running => {
            frame.render_widget(
                Paragraph::new(format!("{} Inspecting…", spinner(app))).block(block),
                area,
            );
        }
        Inspection::Done(None) => {
            frame.render_widget(Paragraph::new("No open ports found.").block(block), area);
        }
        Inspection::Done(Some(report)) => {
            frame.render_widget(Paragraph::new(report_lines(report)).block(block), area);
        }
        Inspection::Failed(err) => {
            frame.render_widget(
                Paragraph::new(format!("Inspect failed: {err}")).block(block).red(),
                area,
            );
        }
    }
}

/// Render a host report as labelled lines.
fn report_lines(report: &HostReport) -> Vec<Line<'static>> {
    let ttl = report
        .ttl
        .map(|ttl| ttl.to_string())
        .unwrap_or_else(|| "-".to_string());
    let ports = report
        .open_ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mut lines = vec![
        Line::from(format!("TTL:        {ttl}")),
        Line::from(format!("Open ports: {ports}")),
        Line::from("Services:"),
    ];
    if report.services.is_empty() {
        lines.push(Line::from("  -"));
    } else {
        for service in &report.services {
            lines.push(Line::from(format!("  {}: {}", service.port, service.banner)));
        }
    }
    lines
}

/// The current spinner frame.
fn spinner(app: &App) -> &'static str {
    SPINNER[app.spinner_frame % SPINNER.len()]
}

/// The footer key hints for the current screen.
fn footer_hints(app: &App) -> &'static str {
    match app.screen {
        Screen::Discover => match &app.discover {
            Scan::Done(hosts) if !hosts.is_empty() => {
                "↑/↓ navigate    enter: scope    q: quit"
            }
            _ => "q: quit",
        },
        Screen::Scope => "↑/↓ choose    enter: inspect    esc: back    q: quit",
        Screen::Inspect => "esc: back    q: quit",
    }
}
