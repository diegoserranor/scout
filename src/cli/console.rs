use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

pub const OUTPUT_WIDTH: u16 = 100;

/// Build an indeterminate spinner with a steady tick for long-running stages.
/// Per-target progress bars are deferred until core exposes a streaming API.
pub fn spinner(message: &str) -> ProgressBar {
    let bar = ProgressBar::new_spinner();
    let style = ProgressStyle::with_template("{spinner:.cyan} {msg}").unwrap();
    bar.set_style(style);
    bar.set_message(message.to_string());
    bar.enable_steady_tick(Duration::from_millis(100));
    bar
}
