//! Rendering for the TUI: a pure function from [`App`] state to widgets.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Row, Table};

use super::app::{App, CUSTOM_PRESET, Inspection, PRESET_LABELS, Scan, Screen, preset_hint};
use crate::core::{Confidence, HostReport, PortSpec, Service};

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

/// Discover screen: the live-host table, growing as results stream in (with a
/// spinner in the title while the sweep runs).
fn draw_discover(frame: &mut Frame, app: &mut App, area: Rect) {
    let (hosts, scanning) = match &app.discover {
        Scan::Running(hosts) => (hosts, true),
        Scan::Done(hosts) => (hosts, false),
        Scan::Failed(err) => {
            let widget = Paragraph::new(format!("Discover failed: {err}"))
                .block(Block::bordered().title("Discover"))
                .red();
            frame.render_widget(widget, area);
            return;
        }
    };

    if hosts.is_empty() {
        let body = if scanning {
            format!("{} Discovering live hosts…", spinner(app))
        } else {
            "No live hosts found on local networks.".to_string()
        };
        let widget = Paragraph::new(body).block(Block::bordered().title("Discover"));
        frame.render_widget(widget, area);
        return;
    }

    let title = if scanning {
        format!("{} Discover — {} live", spinner(app), hosts.len())
    } else {
        format!("Discover — {} live", hosts.len())
    };
    let rows = hosts
        .iter()
        .map(|host| Row::new(vec![host.ip.to_string(), host.subnet.to_string()]));
    let table = Table::new(rows, [Constraint::Length(18), Constraint::Min(10)])
        .header(Row::new(vec!["Host", "Subnet"]).bold())
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("› ");
    frame.render_stateful_widget(table, area, &mut app.host_list);
}

/// Scope screen: pick a port preset for the selected host.
fn draw_scope(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::with_capacity(PRESET_LABELS.len() * 2);
    for (i, label) in PRESET_LABELS.iter().enumerate() {
        let label_line = Line::from(format!(" {label}"));
        lines.push(if i == app.preset {
            label_line.bold().reversed()
        } else {
            label_line
        });
        if i == CUSTOM_PRESET && app.editing {
            // The Custom row swaps its footnote for the live input and a parse preview.
            lines.push(Line::from(format!("   > {}_", app.port_input)));
            lines.push(scope_preview(&app.port_input));
        } else {
            lines.push(Line::from(format!("   {}", preset_hint(i))).dim());
        }
    }
    let widget = Paragraph::new(lines).block(Block::bordered().title("Scope — choose ports"));
    frame.render_widget(widget, area);
}

/// A preview line for the Custom input: the resolved port count, or the parse error.
fn scope_preview(input: &str) -> Line<'static> {
    if input.trim().is_empty() {
        return Line::from("   type ports, then enter").dim();
    }
    match input.parse::<PortSpec>().and_then(|spec| spec.resolve()) {
        Ok(ports) => Line::from(format!("   → {} port(s)", ports.len())).dim(),
        Err(err) => Line::from(format!("   ✗ {err}")).red(),
    }
}

/// Inspect screen: the host report, filling in live (spinner in the title while
/// the scan runs).
fn draw_inspect(frame: &mut Frame, app: &App, area: Rect) {
    let (report, scanning) = match &app.inspection {
        Inspection::Running(report) => (report.as_ref(), true),
        Inspection::Done(report) => (report.as_ref(), false),
        Inspection::Failed(err) => {
            let widget = Paragraph::new(format!("Inspect failed: {err}"))
                .block(Block::bordered().title("Inspect"))
                .red();
            frame.render_widget(widget, area);
            return;
        }
    };

    let title = if scanning {
        format!("{} Inspect", spinner(app))
    } else {
        "Inspect".to_string()
    };
    let block = Block::bordered().title(title);
    let widget = match report {
        Some(report) => Paragraph::new(report_lines(report)).block(block),
        None if scanning => Paragraph::new(format!("{} Inspecting…", spinner(app))).block(block),
        None => Paragraph::new("No open ports found.").block(block),
    };
    frame.render_widget(widget, area);
}

/// Render a host report as labelled lines.
fn report_lines(report: &HostReport) -> Vec<Line<'static>> {
    let ttl = report
        .ttl
        .map(|ttl| ttl.to_string())
        .unwrap_or_else(|| "-".to_string());
    let os = report
        .os
        .as_ref()
        .map(|os| format!("{} ({})", os.family.label(), os.confidence.label()))
        .unwrap_or_else(|| "-".to_string());
    let ports = report
        .open_ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mut lines = vec![
        Line::from(format!("TTL:        {ttl}")),
        Line::from(format!("OS:         {os}")),
        Line::from(format!("Open ports: {ports}")),
        Line::from("Services:"),
    ];
    if report.services.is_empty() {
        lines.push(Line::from("  -"));
    } else {
        for service in &report.services {
            lines.push(Line::from(format!("  {}", service_line(service))));
        }
    }
    lines
}

/// One service line: the parsed `name product/version` when identified,
/// otherwise the raw banner.
fn service_line(service: &Service) -> String {
    match service_identity(service) {
        Some(identity) => format!("{}: {}", service.port, identity),
        None => format!("{}: {}", service.port, service.banner),
    }
}

/// Assemble `name product/version` from a service, or `None` when no product
/// was recovered from the banner.
fn service_identity(service: &Service) -> Option<String> {
    let product = service.product.as_ref()?;
    let mut identity = String::new();
    if let Some(name) = &service.name {
        identity.push_str(name);
        identity.push(' ');
    }
    identity.push_str(product);
    if let Some(version) = &service.version {
        identity.push('/');
        identity.push_str(version);
    }
    // Flag identifications we are less sure of (e.g. product but no version).
    if service.confidence != Confidence::High {
        identity.push_str(&format!(" ({})", service.confidence.label()));
    }
    Some(identity)
}

/// The current spinner frame.
fn spinner(app: &App) -> &'static str {
    SPINNER[app.spinner_frame % SPINNER.len()]
}

/// The footer key hints for the current screen.
fn footer_hints(app: &App) -> &'static str {
    match app.screen {
        Screen::Discover => match &app.discover {
            Scan::Running(hosts) | Scan::Done(hosts) if !hosts.is_empty() => {
                "↑/↓ navigate    enter: scope    q: quit"
            }
            _ => "q: quit",
        },
        Screen::Scope if app.editing => "type ports    enter: inspect    esc: cancel",
        Screen::Scope => "↑/↓ choose    enter: select    esc: back    q: quit",
        Screen::Inspect => "esc: back    q: quit",
    }
}
