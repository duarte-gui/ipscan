//! Severity colours. Honours NO_COLOR by turning colour off.
use crate::correlate::Severity;
use ratatui::style::{Color, Modifier, Style};

pub fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some()
}

/// Foreground colour per severity: red for critical, yellow for high, grey otherwise.
pub fn severity_style(sev: Severity) -> Style {
    if no_color() {
        return Style::default();
    }
    match sev {
        Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(Color::Yellow),
        Severity::Info => Style::default().fg(Color::DarkGray),
    }
}

/// A narrow, predictable marker glyph per severity.
pub fn severity_glyph(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "●",
        Severity::High => "▲",
        Severity::Info => "·",
    }
}

pub fn accent() -> Style {
    if no_color() {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    }
}

pub fn dim() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}

pub fn selected() -> Style {
    if no_color() {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default().bg(Color::Rgb(40, 40, 55)).add_modifier(Modifier::BOLD)
    }
}
