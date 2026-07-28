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

use crate::crypto::pin::{PIN_LENGTH, is_valid_pin, pin_char, pin_fingerprint};

use super::dir_picker::{DirPicker, DirPickerStep};
use super::file_browser::{Browser, BrowserStep};
use super::is_ctrl_c;
use super::widgets;

/// The resolved outcome of the wizard: what to transfer and how.
pub enum WizardPlan {
    /// Stays in the TUI.
    SendNostr(Vec<PathBuf>),
    /// Leaves the TUI so the SS03 blobs can be copy/pasted.
    SendManual(Vec<PathBuf>),
    /// Stays in the TUI.
    ReceiveNostr {
        pin: String,
        /// Fingerprint of `pin`, computed during entry and kept on screen for
        /// the visual check against the sender's.
        fingerprint: String,
        output: PathBuf,
    },
    /// Leaves the TUI so the SS03 blobs can be copy/pasted.
    ReceiveManual { output: PathBuf },
}

const MODE_ITEMS: &[&str] = &[
    "PIN code via Nostr relays (works with secure-send-web Auto Exchange)",
    "Manual copy/paste exchange (leaves this screen for the code swap)",
];

enum Screen {
    MainMenu {
        selected: usize,
    },
    FileBrowser(Browser),
    SendMode {
        browser: Browser,
        selected: usize,
    },
    ReceiveMode {
        selected: usize,
    },
    OutputDir {
        manual: bool,
        picker: DirPicker,
    },
    PinEntry {
        output: PathBuf,
        input: String,
        /// Insertion point in `input` (0..=len): standard line editing.
        cursor: usize,
        /// Fingerprint of a complete, valid `input`, shown for comparison
        /// with the sender's before the user confirms with Enter.
        fingerprint: Option<String>,
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
        Screen::FileBrowser(mut browser) => match browser.handle_key(key) {
            BrowserStep::Stay => Step::Continue(Screen::FileBrowser(browser)),
            BrowserStep::Back => Step::Continue(Screen::MainMenu { selected: 0 }),
            BrowserStep::Confirm => Step::Continue(Screen::SendMode {
                browser,
                selected: 0,
            }),
        },
        Screen::SendMode { browser, selected } => send_mode_key(browser, selected, key),
        Screen::ReceiveMode { selected } => receive_mode_key(selected, key),
        Screen::OutputDir { manual, mut picker } => match picker.handle_key(key) {
            DirPickerStep::Stay => Step::Continue(Screen::OutputDir { manual, picker }),
            DirPickerStep::Back => Step::Continue(Screen::ReceiveMode {
                selected: usize::from(manual),
            }),
            DirPickerStep::Choose(output) => {
                if manual {
                    Step::Finish(WizardPlan::ReceiveManual { output })
                } else {
                    Step::Continue(Screen::PinEntry {
                        output,
                        input: String::new(),
                        cursor: 0,
                        fingerprint: None,
                        error: None,
                    })
                }
            }
        },
        Screen::PinEntry {
            output,
            input,
            cursor,
            fingerprint,
            error,
        } => pin_entry_key(output, input, cursor, fingerprint, error, key),
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
            0 => match Browser::new() {
                Ok(browser) => Step::Continue(Screen::FileBrowser(browser)),
                Err(_) => Step::Continue(Screen::MainMenu { selected }),
            },
            1 => Step::Continue(Screen::ReceiveMode { selected: 0 }),
            _ => Step::Quit,
        },
        KeyCode::Esc | KeyCode::Char('q') => Step::Quit,
        _ => Step::Continue(Screen::MainMenu {
            selected: menu_move(selected, 3, &key),
        }),
    }
}

fn send_mode_key(browser: Browser, selected: usize, key: KeyEvent) -> Step {
    match key.code {
        KeyCode::Enter => {
            let paths = browser.selection();
            if selected == 0 {
                Step::Finish(WizardPlan::SendNostr(paths))
            } else {
                Step::Finish(WizardPlan::SendManual(paths))
            }
        }
        KeyCode::Esc => Step::Continue(Screen::FileBrowser(browser)),
        _ => Step::Continue(Screen::SendMode {
            browser,
            selected: menu_move(selected, MODE_ITEMS.len(), &key),
        }),
    }
}

fn receive_mode_key(selected: usize, key: KeyEvent) -> Step {
    match key.code {
        KeyCode::Enter => match DirPicker::new() {
            Ok(picker) => Step::Continue(Screen::OutputDir {
                manual: selected == 1,
                picker,
            }),
            Err(_) => Step::Continue(Screen::ReceiveMode { selected }),
        },
        KeyCode::Esc => Step::Continue(Screen::MainMenu { selected: 1 }),
        _ => Step::Continue(Screen::ReceiveMode {
            selected: menu_move(selected, MODE_ITEMS.len(), &key),
        }),
    }
}

fn pin_entry_key(
    output: PathBuf,
    mut input: String,
    mut cursor: usize,
    mut fingerprint: Option<String>,
    mut error: Option<String>,
    key: KeyEvent,
) -> Step {
    let mut edited = false;
    match key.code {
        KeyCode::Enter => {
            if is_valid_pin(&input) {
                let fingerprint = fingerprint.unwrap_or_else(|| pin_fingerprint(&input));
                return Step::Finish(WizardPlan::ReceiveNostr {
                    pin: input,
                    fingerprint,
                    output,
                });
            }
            error = Some("Invalid PIN: check for typos and try again".to_string());
        }
        KeyCode::Esc => {
            return Step::Continue(Screen::OutputDir {
                manual: false,
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
        // Shown for the visual check against the sender's fingerprint before
        // Enter confirms.
        fingerprint =
            (input.len() == PIN_LENGTH && is_valid_pin(&input)).then(|| pin_fingerprint(&input));
    }

    Step::Continue(Screen::PinEntry {
        output,
        input,
        cursor,
        fingerprint,
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
    let fingerprint =
        (input.len() == PIN_LENGTH && is_valid_pin(&input)).then(|| pin_fingerprint(&input));

    Step::Continue(Screen::PinEntry {
        output,
        cursor: input.len(),
        input,
        fingerprint,
        error: invalid.then(|| "Unsupported characters were removed".to_string()),
    })
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

        Screen::FileBrowser(browser) => {
            let inner = widgets::screen_frame(f, "send");
            browser.render(f, inner);
        }

        Screen::SendMode { browser, selected } => {
            let inner = widgets::screen_frame(f, "send");
            let area = widgets::centered(inner, 74, 7);
            let [title, _, list] = Layout::vertical([
                Constraint::Length(2),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            let paths = browser.selection();
            f.render_widget(
                Paragraph::new(format!(
                    "Sending \"{}\" — how should the two sides connect?",
                    crate::archive::send_display_name(&paths)
                )),
                title,
            );
            widgets::menu(f, list, MODE_ITEMS, *selected);
            widgets::key_hints(f, inner, "↑/↓ move · Enter select · Esc back");
        }

        Screen::ReceiveMode { selected } => {
            let inner = widgets::screen_frame(f, "receive");
            let area = widgets::centered(inner, 74, 6);
            let [title, _, list] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            f.render_widget(
                Paragraph::new("How is the sender sharing the transfer?"),
                title,
            );
            widgets::menu(f, list, MODE_ITEMS, *selected);
            widgets::key_hints(f, inner, "↑/↓ move · Enter select · Esc back");
        }

        Screen::OutputDir { picker, .. } => {
            let inner = widgets::screen_frame(f, "receive");
            picker.render(f, inner);
        }

        Screen::PinEntry {
            input,
            cursor,
            fingerprint,
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
            } else if let Some(fp) = fingerprint {
                // Dimmed so the hex fingerprint is never mistaken for the PIN.
                f.render_widget(
                    Paragraph::new(format!("PIN fingerprint: {fp} (should match the sender's)"))
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

    #[test]
    fn pasted_pin_replaces_input_and_filters_unsupported_characters() {
        let screen = Screen::PinEntry {
            output: PathBuf::from("."),
            input: "old".to_string(),
            cursor: 3,
            fingerprint: None,
            error: None,
        };

        let Step::Continue(Screen::PinEntry {
            input,
            cursor,
            fingerprint,
            error,
            ..
        }) = handle_paste(screen, "AB*CD EFGHJKLc")
        else {
            panic!("paste should remain on the PIN entry screen");
        };

        assert_eq!(input, "ABCDEFGHJKLc");
        assert_eq!(cursor, PIN_LENGTH);
        assert!(fingerprint.is_some());
        assert_eq!(
            error.as_deref(),
            Some("Unsupported characters were removed")
        );
    }
}
