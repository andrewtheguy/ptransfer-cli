//! Wizard state machine: collects everything a transfer needs (direction,
//! selection, signaling mode, output directory, PIN) before any network work.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind};
use futures_util::StreamExt;
use ratatui::DefaultTerminal;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Stylize;
use ratatui::widgets::Paragraph;

use crate::crypto::pin::{PIN_LENGTH, is_valid_pin, pin_char};
use crate::ui::Direction;

use super::dir_picker::{DirPicker, DirPickerStep};
use super::file_browser::{Browser, BrowserStep};
use super::is_ctrl_c;
use super::widgets;

/// The resolved outcome of the wizard: what to transfer and how.
pub enum WizardPlan {
    SendPin(Vec<PathBuf>),
    ReceivePin { pin: String, output: PathBuf },
}

/// The transfer modes, in the pTransfer web app's order, so an option's
/// number means the same thing in both interfaces.
const MODES: [&str; 2] = ["PIN Exchange", "Code Exchange"];

/// One line of explanation per entry in [`MODES`].
const MODE_HINTS: [&str; 2] = [
    "A short PIN over relays, then a direct WebRTC transfer.",
    "Hand-carried connection codes. Not implemented in the CLI yet.",
];

const CODE_EXCHANGE_UNAVAILABLE: &str =
    "Code Exchange is not implemented in the CLI yet — use PIN Exchange.";

enum Screen {
    MainMenu {
        selected: usize,
    },
    ModeMenu {
        direction: Direction,
        selected: usize,
        /// Set when the highlighted mode cannot be started, cleared on move.
        notice: Option<String>,
    },
    FileBrowser(Browser),
    OutputDir {
        picker: DirPicker,
    },
    PinEntry {
        output: PathBuf,
        input: String,
        /// Insertion point in `input` (0..=len): standard line editing.
        cursor: usize,
        error: Option<String>,
    },
}

enum Step {
    Continue(Screen),
    Finish(WizardPlan),
    Quit,
}

/// Run the wizard. `Ok(None)` means the user quit cleanly.
pub async fn run_wizard(terminal: &mut DefaultTerminal) -> Result<Option<WizardPlan>> {
    let mut screen = Screen::MainMenu { selected: 0 };
    let mut events = EventStream::new();

    loop {
        terminal.draw(|f| draw(f, &mut screen))?;

        let event = events
            .next()
            .await
            .ok_or_else(|| anyhow!("input stream closed"))??;
        let step = match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if is_ctrl_c(&key) {
                    return Err(anyhow!("Interrupted"));
                }
                handle_key(screen, key)
            }
            Event::Paste(text) => handle_paste(screen, &text),
            _ => continue,
        };

        match step {
            Step::Continue(next) => screen = next,
            Step::Finish(plan) => return Ok(Some(plan)),
            Step::Quit => return Ok(None),
        }
    }
}

fn handle_key(screen: Screen, key: KeyEvent) -> Step {
    match screen {
        Screen::MainMenu { selected } => main_menu_key(selected, key),
        Screen::ModeMenu {
            direction,
            selected,
            ..
        } => mode_menu_key(direction, selected, key),
        Screen::FileBrowser(mut browser) => match browser.handle_key(key) {
            BrowserStep::Stay => Step::Continue(Screen::FileBrowser(browser)),
            BrowserStep::Back => Step::Continue(mode_menu(Direction::Send)),
            BrowserStep::Confirm => Step::Finish(WizardPlan::SendPin(browser.selection())),
        },
        Screen::OutputDir { mut picker } => match picker.handle_key(key) {
            DirPickerStep::Stay => Step::Continue(Screen::OutputDir { picker }),
            DirPickerStep::Back => Step::Continue(mode_menu(Direction::Receive)),
            DirPickerStep::Choose(output) => Step::Continue(Screen::PinEntry {
                output,
                input: String::new(),
                cursor: 0,
                error: None,
            }),
        },
        Screen::PinEntry {
            output,
            input,
            cursor,
            error,
        } => pin_entry_key(output, input, cursor, error, key),
    }
}

fn menu_move(selected: usize, len: usize, key: &KeyEvent) -> usize {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => selected.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => (selected + 1).min(len - 1),
        _ => selected,
    }
}

fn main_menu_key(selected: usize, key: KeyEvent) -> Step {
    match key.code {
        KeyCode::Enter => match selected {
            0 => Step::Continue(mode_menu(Direction::Send)),
            1 => Step::Continue(mode_menu(Direction::Receive)),
            _ => Step::Quit,
        },
        KeyCode::Esc | KeyCode::Char('q') => Step::Quit,
        _ => Step::Continue(Screen::MainMenu {
            selected: menu_move(selected, 3, &key),
        }),
    }
}

/// The mode menu for `direction`, with the first mode highlighted.
fn mode_menu(direction: Direction) -> Screen {
    Screen::ModeMenu {
        direction,
        selected: 0,
        notice: None,
    }
}

fn mode_menu_key(direction: Direction, selected: usize, key: KeyEvent) -> Step {
    let stay = |notice: Option<String>| {
        Step::Continue(Screen::ModeMenu {
            direction,
            selected,
            notice,
        })
    };

    match key.code {
        // Only PIN Exchange starts a transfer; the rest is a placeholder that
        // keeps the CLI's mode numbering aligned with the web app's.
        KeyCode::Enter => match (selected, direction) {
            (0, Direction::Send) => match Browser::new() {
                Ok(browser) => Step::Continue(Screen::FileBrowser(browser)),
                Err(_) => stay(None),
            },
            (0, Direction::Receive) => match DirPicker::new() {
                Ok(picker) => Step::Continue(Screen::OutputDir { picker }),
                Err(_) => stay(None),
            },
            _ => stay(Some(CODE_EXCHANGE_UNAVAILABLE.to_string())),
        },
        KeyCode::Esc => Step::Continue(Screen::MainMenu {
            selected: match direction {
                Direction::Send => 0,
                Direction::Receive => 1,
            },
        }),
        _ => Step::Continue(Screen::ModeMenu {
            direction,
            selected: menu_move(selected, MODES.len(), &key),
            notice: None,
        }),
    }
}

fn pin_entry_key(
    output: PathBuf,
    mut input: String,
    mut cursor: usize,
    mut error: Option<String>,
    key: KeyEvent,
) -> Step {
    let mut edited = false;
    match key.code {
        KeyCode::Enter => {
            if is_valid_pin(&input) {
                return Step::Finish(WizardPlan::ReceivePin { pin: input, output });
            }
            error = Some("Invalid PIN: check for typos and try again".to_string());
        }
        KeyCode::Esc => {
            return Step::Continue(Screen::OutputDir {
                picker: DirPicker::at(output),
            });
        }
        KeyCode::Left => cursor = cursor.saturating_sub(1),
        KeyCode::Right => cursor = (cursor + 1).min(input.len()),
        KeyCode::Home => cursor = 0,
        KeyCode::End => cursor = input.len(),
        KeyCode::Backspace => {
            if cursor > 0 {
                cursor -= 1;
                input.remove(cursor);
                edited = true;
            }
        }
        KeyCode::Delete => {
            if cursor < input.len() {
                input.remove(cursor);
                edited = true;
            }
        }
        // PIN entry is case-sensitive. Unsupported characters are filtered
        // without changing the supported characters around them.
        KeyCode::Char(c) if input.len() < PIN_LENGTH => {
            if let Some(c) = pin_char(c) {
                input.insert(cursor, c);
                cursor += 1;
                edited = true;
            } else {
                error = Some("That character is not supported in a PIN".to_string());
            }
        }
        _ => {}
    }

    if edited {
        error = None;
    }

    Step::Continue(Screen::PinEntry {
        output,
        input,
        cursor,
        error,
    })
}

fn handle_paste(screen: Screen, pasted: &str) -> Step {
    let Screen::PinEntry { output, .. } = screen else {
        return Step::Continue(screen);
    };

    let mut input = String::with_capacity(PIN_LENGTH);
    let mut invalid = false;
    for c in pasted.chars() {
        if let Some(c) = pin_char(c) {
            if input.len() < PIN_LENGTH {
                input.push(c);
            }
        } else {
            invalid = true;
        }
    }
    Step::Continue(Screen::PinEntry {
        output,
        cursor: input.len(),
        input,
        error: invalid.then(|| "Unsupported characters were removed".to_string()),
    })
}

fn direction_title(direction: Direction) -> &'static str {
    match direction {
        Direction::Send => "send",
        Direction::Receive => "receive",
    }
}

fn draw(f: &mut Frame, screen: &mut Screen) {
    match screen {
        Screen::MainMenu { selected } => {
            let inner = widgets::screen_frame(f, "wizard");
            let area = widgets::centered(inner, 40, 6);
            let [title, _, list] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            f.render_widget(Paragraph::new("What do you want to do?"), title);
            widgets::menu(
                f,
                list,
                &["Send files or a folder", "Receive", "Quit"],
                *selected,
            );
            widgets::key_hints(f, inner, "↑/↓ move · Enter select · q quit");
        }

        Screen::ModeMenu {
            direction,
            selected,
            notice,
        } => {
            let inner = widgets::screen_frame(f, direction_title(*direction));
            let area = widgets::centered(inner, 60, 7);
            let [title, _, list, extra] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(MODES.len() as u16),
                Constraint::Fill(1),
            ])
            .areas(area);
            f.render_widget(Paragraph::new("How do you want to connect?"), title);
            widgets::menu(f, list, &MODES, *selected);
            match notice {
                Some(notice) => widgets::error_line(f, extra, notice),
                None => f.render_widget(Paragraph::new(MODE_HINTS[*selected]).dim(), extra),
            }
            widgets::key_hints(f, inner, "↑/↓ move · Enter select · Esc back");
        }

        Screen::FileBrowser(browser) => {
            let inner = widgets::screen_frame(f, "send");
            browser.render(f, inner);
        }

        Screen::OutputDir { picker } => {
            let inner = widgets::screen_frame(f, "receive");
            picker.render(f, inner);
        }

        Screen::PinEntry {
            input,
            cursor,
            error,
            ..
        } => {
            let inner = widgets::screen_frame(f, "receive");
            let area = widgets::centered(inner, 60, 5);
            let [title, line, extra] = Layout::vertical([
                Constraint::Length(2),
                Constraint::Length(1),
                Constraint::Length(2),
            ])
            .areas(area);
            f.render_widget(
                Paragraph::new("Enter the sender's 12-character PIN (case-sensitive):"),
                title,
            );
            widgets::input_line(f, line, "PIN: ", input, *cursor);
            if let Some(error) = error {
                widgets::error_line(f, extra, error);
            } else if input.len() == PIN_LENGTH && is_valid_pin(input) {
                f.render_widget(
                    Paragraph::new("After you start, read the confirmation code to the sender.")
                        .dim(),
                    extra,
                );
            }
            widgets::key_hints(f, inner, "Enter confirm · ←/→ move · Esc back");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    #[test]
    fn code_exchange_reports_that_it_is_not_implemented() {
        let step = mode_menu_key(Direction::Send, 1, press(KeyCode::Enter));

        let Step::Continue(Screen::ModeMenu {
            selected, notice, ..
        }) = step
        else {
            panic!("Code Exchange should stay on the mode menu");
        };
        assert_eq!(selected, 1);
        assert_eq!(notice.as_deref(), Some(CODE_EXCHANGE_UNAVAILABLE));
    }

    #[test]
    fn moving_off_a_notice_clears_it() {
        let step = mode_menu_key(Direction::Send, 1, press(KeyCode::Up));

        let Step::Continue(Screen::ModeMenu {
            selected, notice, ..
        }) = step
        else {
            panic!("expected the mode menu");
        };
        assert_eq!(selected, 0);
        assert!(notice.is_none());
    }

    #[test]
    fn escaping_the_mode_menu_reselects_its_direction() {
        let Step::Continue(Screen::MainMenu { selected }) =
            mode_menu_key(Direction::Receive, 0, press(KeyCode::Esc))
        else {
            panic!("Esc should return to the main menu");
        };
        assert_eq!(selected, 1);
    }

    #[test]
    fn pasted_pin_replaces_input_and_filters_unsupported_characters() {
        let screen = Screen::PinEntry {
            output: PathBuf::from("."),
            input: "old".to_string(),
            cursor: 3,
            error: None,
        };

        let Step::Continue(Screen::PinEntry {
            input,
            cursor,
            error,
            ..
        }) = handle_paste(screen, "AB*CD EFGHJKLc")
        else {
            panic!("paste should remain on the PIN entry screen");
        };

        assert_eq!(input, "ABCDEFGHJKLc");
        assert_eq!(cursor, PIN_LENGTH);
        assert_eq!(
            error.as_deref(),
            Some("Unsupported characters were removed")
        );
    }
}
