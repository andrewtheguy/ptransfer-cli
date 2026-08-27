//! Small shared render helpers for the wizard screens.

use crossterm::event::{KeyCode, KeyEvent};
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

/// Apply one line-editing key to `value`, returning whether the text changed.
///
/// `cursor` is a byte index that always lands on a character boundary: moves
/// and edits step whole characters, never bytes. That is not a nicety —
/// `String::insert`, `String::remove` and the slicing in [`input_line`] all
/// panic on an index inside a multi-byte character, so a single non-ASCII
/// character typed or pasted into a field would otherwise take the whole TUI
/// down on the next redraw.
///
/// Control characters are ignored, so a chord like Ctrl-A does not type its
/// letter. Callers that accept only a restricted alphabet (the PIN and the Tor
/// password) handle [`KeyCode::Char`] themselves before delegating here.
pub fn edit_line(value: &mut String, cursor: &mut usize, key: &KeyEvent) -> bool {
    match key.code {
        KeyCode::Left => {
            if let Some(c) = value[..*cursor].chars().next_back() {
                *cursor -= c.len_utf8();
            }
        }
        KeyCode::Right => {
            if let Some(c) = value[*cursor..].chars().next() {
                *cursor += c.len_utf8();
            }
        }
        KeyCode::Home => *cursor = 0,
        KeyCode::End => *cursor = value.len(),
        KeyCode::Backspace => {
            if let Some(c) = value[..*cursor].chars().next_back() {
                *cursor -= c.len_utf8();
                value.remove(*cursor);
                return true;
            }
        }
        KeyCode::Delete => {
            if value[*cursor..].chars().next().is_some() {
                value.remove(*cursor);
                return true;
            }
        }
        KeyCode::Char(c) if !c.is_control() => {
            value.insert(*cursor, c);
            *cursor += c.len_utf8();
            return true;
        }
        _ => {}
    }
    false
}

/// A single-line text input with a visible cursor at byte index `cursor`.
///
/// The cursor is clamped to the end and rounded down to a character boundary.
/// Every caller keeps it on one already ([`edit_line`]); this is the backstop
/// that keeps a redraw from panicking if one ever does not, because a panic
/// here would take the whole wizard down.
pub fn input_line(f: &mut Frame, area: Rect, label: &str, value: &str, cursor: usize) {
    let mut cursor = cursor.min(value.len());
    while !value.is_char_boundary(cursor) {
        cursor -= 1;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    /// Type `text` into an empty field, returning the value and the cursor.
    fn typed(text: &str) -> (String, usize) {
        let mut value = String::new();
        let mut cursor = 0;
        for c in text.chars() {
            edit_line(&mut value, &mut cursor, &press(KeyCode::Char(c)));
        }
        (value, cursor)
    }

    #[test]
    fn the_cursor_steps_whole_characters() {
        // A multi-byte character must advance the cursor past all of its
        // bytes; landing inside one panics the next edit or redraw.
        let (value, cursor) = typed("a│b");
        assert_eq!(value, "a│b");
        assert_eq!(cursor, value.len());
        assert!(value.is_char_boundary(cursor));

        let mut value = value;
        let mut cursor = cursor;
        // A move reports no change: only edits clear a field's error line.
        assert!(!edit_line(&mut value, &mut cursor, &press(KeyCode::Left)));
        assert_eq!((value.as_str(), cursor), ("a│b", 4));

        // Backspace removes the whole character, not one of its bytes.
        assert!(edit_line(&mut value, &mut cursor, &press(KeyCode::Backspace)));
        assert_eq!((value.as_str(), cursor), ("ab", 1));
    }

    #[test]
    fn moving_and_deleting_stay_inside_the_value() {
        let mut value = "x".to_string();
        let mut cursor = 0;
        // Nothing to the left, and nothing to delete past the end.
        assert!(!edit_line(&mut value, &mut cursor, &press(KeyCode::Left)));
        assert!(!edit_line(&mut value, &mut cursor, &press(KeyCode::Backspace)));
        assert_eq!(cursor, 0);

        edit_line(&mut value, &mut cursor, &press(KeyCode::End));
        assert_eq!(cursor, 1);
        assert!(!edit_line(&mut value, &mut cursor, &press(KeyCode::Right)));
        assert!(!edit_line(&mut value, &mut cursor, &press(KeyCode::Delete)));
        assert_eq!((value.as_str(), cursor), ("x", 1));
    }

    #[test]
    fn a_control_chord_does_not_type_its_letter() {
        let mut value = String::new();
        let mut cursor = 0;
        assert!(!edit_line(&mut value, &mut cursor, &press(KeyCode::Char('\u{1}'))));
        assert!(value.is_empty());
    }

    #[test]
    fn a_cursor_off_a_character_boundary_renders_instead_of_panicking() {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(20, 1)).unwrap();
        // Byte 2 is inside the leading three-byte character.
        terminal
            .draw(|f| input_line(f, f.area(), "> ", "│x", 2))
            .unwrap();
    }
}
