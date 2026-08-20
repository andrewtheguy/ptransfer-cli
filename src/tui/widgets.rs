//! Small shared render helpers for the wizard screens.

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

/// The outer frame every screen draws inside; returns the inner area.
pub fn screen_frame(f: &mut Frame, title: &str) -> Rect {
    let area = f.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" pTransfer — {title} "));
    let inner = block.inner(area);
    f.render_widget(block, area);
    inner
}

/// A centered sub-area of fixed size, clamped to the available space.
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [area] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    area
}

/// A simple vertical menu with a highlighted row.
pub fn menu(f: &mut Frame, area: Rect, items: &[&str], selected: usize) {
    let items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let prefix = if i == selected { "▶ " } else { "  " };
            let item = ListItem::new(format!("{prefix}{label}"));
            if i == selected {
                item.style(Style::default().add_modifier(Modifier::BOLD))
            } else {
                item
            }
        })
        .collect();
    f.render_widget(List::new(items), area);
}

/// A single-line text input with a visible cursor at byte index `cursor`
/// (clamped to the end; the value must be single-width characters).
pub fn input_line(f: &mut Frame, area: Rect, label: &str, value: &str, cursor: usize) {
    let cursor = cursor.min(value.len());
    let (before, rest) = value.split_at(cursor);
    let mut spans = vec![label.to_string().into(), before.to_string().into()];
    match rest.chars().next() {
        Some(c) => {
            spans.push(c.to_string().reversed());
            spans.push(rest[c.len_utf8()..].to_string().into());
        }
        None => spans.push("█".dim()),
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The key-hint footer on the bottom row of `area`.
pub fn key_hints(f: &mut Frame, area: Rect, hints: &str) {
    let row = Rect {
        y: area.y + area.height.saturating_sub(1),
        height: 1,
        ..area
    };
    f.render_widget(Paragraph::new(hints).dim(), row);
}

/// An error line rendered in red.
pub fn error_line(f: &mut Frame, area: Rect, message: &str) {
    f.render_widget(Paragraph::new(message).red(), area);
}
