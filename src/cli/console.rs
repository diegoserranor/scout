use indicatif::{ProgressBar, ProgressStyle};

pub struct Console {
    bar: ProgressBar,
}

pub const OUTPUT_WIDTH: u16 = 100;
const PROGRESS_LABEL_WIDTH: usize = 21;

pub fn console_with_label(total: u64, label: &str, suffix: &str) -> Console {
    let bar = ProgressBar::new(total);
    let template = format!("{{prefix}} [{{bar:40.cyan/blue}}] {{pos}}/{{len}} {suffix}");
    let style = ProgressStyle::with_template(&template)
        .unwrap()
        .progress_chars("##-");
    bar.set_style(style);

    // Pad the prefix so different labels keep the bar aligned.
    let padded_label = format!("{label:<PROGRESS_LABEL_WIDTH$}");
    bar.set_prefix(padded_label);

    Console { bar }
}

pub fn progress(console: &Console) {
    console.bar.inc(1);
}

pub fn finish(console: &Console) {
    console.bar.finish();
}
