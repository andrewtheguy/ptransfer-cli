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
    ReceivePin {
        pin: String,
        output: PathBuf,
    },
    #[cfg(feature = "tor")]
    SendTor(Vec<PathBuf>),
    #[cfg(feature = "tor")]
    ReceiveTor {
        address: String,
        password: String,
        output: PathBuf,
    },
}

/// The transfer modes, in the pTransfer web app's order, so an option's
/// number means the same thing in both interfaces. The Tor transport is the
/// CLI's own third mode, and only exists in a build with the `tor` feature.
#[cfg(not(feature = "tor"))]
const MODES: [&str; 2] = ["PIN Exchange", "Code Exchange"];
#[cfg(feature = "tor")]
const MODES: [&str; 3] = ["PIN Exchange", "Code Exchange", "Tor Onion Service"];

/// One line of explanation per entry in [`MODES`].
#[cfg(not(feature = "tor"))]
const MODE_HINTS: [&str; 2] = [
    "A short PIN over relays, then a direct WebRTC transfer.",
    "Hand-carried connection codes. Not implemented in the CLI yet.",
];
#[cfg(feature = "tor")]
const MODE_HINTS: [&str; 3] = [
    "A short PIN over relays, then a direct WebRTC transfer.",
    "Hand-carried connection codes. Not implemented in the CLI yet.",
    "An onion address and a password. CLI to CLI, up to 1 MiB.",
];

const MODE_PIN: usize = 0;
#[cfg(feature = "tor")]
const MODE_TOR: usize = 2;

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
    /// The selection screens are shared by every mode, so each carries the
    /// mode it was entered from: it decides which plan the wizard finishes
    /// with, and which menu Esc goes back to.
    FileBrowser {
        mode: usize,
        browser: Browser,
    },
    OutputDir {
        mode: usize,
        picker: DirPicker,
    },
    PinEntry {
        output: PathBuf,
        input: String,
        /// Insertion point in `input` (0..=len): standard line editing.
        cursor: usize,
        error: Option<String>,
    },
    /// Tor receive: the onion address and the password, both needed.
    #[cfg(feature = "tor")]
    TorEntry {
        output: PathBuf,
        address: String,
        password: String,
        field: TorField,
        /// Insertion point in the focused field.
        cursor: usize,
        error: Option<String>,
    },
}

/// Which line of the Tor entry screen is being edited.
#[cfg(feature = "tor")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorField {
    Address,
    Password,
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
        Screen::FileBrowser { mode, mut browser } => match browser.handle_key(key) {
            BrowserStep::Stay => Step::Continue(Screen::FileBrowser { mode, browser }),
            BrowserStep::Back => Step::Continue(mode_menu_at(Direction::Send, mode)),
            BrowserStep::Confirm => Step::Finish(send_plan(mode, browser.selection())),
        },
        Screen::OutputDir { mode, mut picker } => match picker.handle_key(key) {
            DirPickerStep::Stay => Step::Continue(Screen::OutputDir { mode, picker }),
            DirPickerStep::Back => Step::Continue(mode_menu_at(Direction::Receive, mode)),
            DirPickerStep::Choose(output) => Step::Continue(receive_entry(mode, output)),
        },
        Screen::PinEntry {
            output,
            input,
            cursor,
            error,
        } => pin_entry_key(output, input, cursor, error, key),
        #[cfg(feature = "tor")]
        Screen::TorEntry {
            output,
            address,
            password,
            field,
            cursor,
            error,
        } => tor_entry_key(output, address, password, field, cursor, error, key),
    }
}

/// The plan a confirmed send selection produces in `mode`.
fn send_plan(mode: usize, paths: Vec<PathBuf>) -> WizardPlan {
    match mode {
        #[cfg(feature = "tor")]
        MODE_TOR => WizardPlan::SendTor(paths),
        _ => WizardPlan::SendPin(paths),
    }
}

/// The screen that collects what `mode` needs from the receiving side, once an
/// output directory is chosen.
fn receive_entry(mode: usize, output: PathBuf) -> Screen {
    match mode {
        #[cfg(feature = "tor")]
        MODE_TOR => Screen::TorEntry {
            output,
            address: String::new(),
            password: String::new(),
            field: TorField::Address,
            cursor: 0,
            error: None,
        },
        _ => Screen::PinEntry {
            output,
            input: String::new(),
            cursor: 0,
            error: None,
        },
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
    mode_menu_at(direction, MODE_PIN)
}

/// The mode menu for `direction`, with `selected` highlighted — what going back
/// from a selection screen returns to.
fn mode_menu_at(direction: Direction, selected: usize) -> Screen {
    Screen::ModeMenu {
        direction,
        selected,
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

    // Code Exchange is a placeholder that keeps the CLI's mode numbering
    // aligned with the web app's; every other mode runs a transfer.
    #[cfg(not(feature = "tor"))]
    let implemented = selected == MODE_PIN;
    #[cfg(feature = "tor")]
    let implemented = selected == MODE_PIN || selected == MODE_TOR;

    match key.code {
        KeyCode::Enter if !implemented => stay(Some(CODE_EXCHANGE_UNAVAILABLE.to_string())),
        KeyCode::Enter => match direction {
            Direction::Send => match Browser::new() {
                Ok(browser) => Step::Continue(Screen::FileBrowser {
                    mode: selected,
                    browser,
                }),
                Err(_) => stay(None),
            },
            Direction::Receive => match DirPicker::new() {
                Ok(picker) => Step::Continue(Screen::OutputDir {
                    mode: selected,
                    picker,
                }),
                Err(_) => stay(None),
            },
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
                mode: MODE_PIN,
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

/// The Tor receive screen: an onion address and a password, both required.
#[cfg(feature = "tor")]
#[allow(clippy::too_many_arguments)]
fn tor_entry_key(
    output: PathBuf,
    mut address: String,
    mut password: String,
    mut field: TorField,
    mut cursor: usize,
    mut error: Option<String>,
    key: KeyEvent,
) -> Step {
    use crate::crypto::pin::is_valid_pin;

    let mut edited = false;
    match key.code {
        // Enter walks to the next field, and submits from the last one, so the
        // whole screen can be filled without ever reaching for Tab.
        KeyCode::Enter if field == TorField::Address => {
            field = TorField::Password;
            cursor = password.len();
        }
        KeyCode::Enter => match validate_tor_entry(&address, &password) {
            Ok(address) => {
                return Step::Finish(WizardPlan::ReceiveTor {
                    address,
                    password,
                    output,
                });
            }
            Err(message) => error = Some(message),
        },
        KeyCode::Esc => {
            return Step::Continue(Screen::OutputDir {
                mode: MODE_TOR,
                picker: DirPicker::at(output),
            });
        }
        KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
            field = match field {
                TorField::Address => TorField::Password,
                TorField::Password => TorField::Address,
            };
            cursor = match field {
                TorField::Address => address.len(),
                TorField::Password => password.len(),
            };
        }
        // The password is a PIN, so it filters exactly like one, and a full one
        // swallows further characters instead of growing. Every `Char` on this
        // field is handled here: falling through to the shared editor would
        // insert whatever the filter just rejected. The address takes any
        // printable character and is validated as a whole on submit: a rejected
        // keystroke with no explanation is worse than a rejected address with
        // one.
        KeyCode::Char(c) if field == TorField::Password => {
            if password.len() < PIN_LENGTH {
                match pin_char(c) {
                    Some(c) => {
                        password.insert(cursor, c);
                        cursor += 1;
                        edited = true;
                    }
                    None => {
                        error = Some("That character is not supported in a password".to_string())
                    }
                }
            }
        }
        _ => {
            let value = match field {
                TorField::Address => &mut address,
                TorField::Password => &mut password,
            };
            edited = widgets::edit_line(value, &mut cursor, &key);
        }
    }

    if edited {
        error = None;
    }
    // Nudge toward the missing half rather than waiting for a submit to fail.
    if error.is_none()
        && field == TorField::Password
        && password.len() == PIN_LENGTH
        && !is_valid_pin(&password)
    {
        error = Some("Invalid password: check for typos".to_string());
    }

    Step::Continue(Screen::TorEntry {
        output,
        address,
        password,
        field,
        cursor,
        error,
    })
}

/// Check both Tor fields, returning the address in the form the transfer will
/// bind its handshake to.
#[cfg(feature = "tor")]
fn validate_tor_entry(address: &str, password: &str) -> Result<String, String> {
    use crate::crypto::pin::is_valid_pin;

    let address = address.trim();
    if address.is_empty() {
        return Err("Enter the onion address the sender printed".to_string());
    }
    // Rejects anything that is not a real v3 onion address, which Arti would
    // otherwise resolve through an exit node and off the onion network.
    crate::tor::split_address(address, crate::tor::DEFAULT_PORT)
        .map_err(|_| format!("Not a valid onion address: {address}"))?;

    if !is_valid_pin(password) {
        return Err("Invalid password: check for typos and try again".to_string());
    }
    Ok(address.to_string())
}

fn handle_paste(screen: Screen, pasted: &str) -> Step {
    #[cfg(feature = "tor")]
    if let Screen::TorEntry {
        output,
        mut address,
        mut password,
        field,
        ..
    } = screen
    {
        // Whole-field replacement, matching the PIN screen: a paste is a fresh
        // value, not an insertion.
        let (cursor, error) = match field {
            TorField::Address => {
                address = pasted.trim().to_string();
                (address.len(), None)
            }
            TorField::Password => {
                let (filtered, dropped) = filter_pin_paste(pasted);
                password = filtered;
                (
                    password.len(),
                    dropped.then(|| "Unsupported characters were removed".to_string()),
                )
            }
        };
        return Step::Continue(Screen::TorEntry {
            output,
            address,
            password,
            field,
            cursor,
            error,
        });
    }

    let Screen::PinEntry { output, .. } = screen else {
        return Step::Continue(screen);
    };

    let (input, invalid) = filter_pin_paste(pasted);
    Step::Continue(Screen::PinEntry {
        output,
        cursor: input.len(),
        input,
        error: invalid.then(|| "Unsupported characters were removed".to_string()),
    })
}

/// Reduce pasted text to a PIN, reporting whether anything was dropped.
fn filter_pin_paste(pasted: &str) -> (String, bool) {
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
    (input, invalid)
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

        Screen::FileBrowser { browser, .. } => {
            let inner = widgets::screen_frame(f, "send");
            browser.render(f, inner);
        }

        Screen::OutputDir { picker, .. } => {
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

        #[cfg(feature = "tor")]
        Screen::TorEntry {
            address,
            password,
            field,
            cursor,
            error,
            ..
        } => {
            let inner = widgets::screen_frame(f, "receive");
            let area = widgets::centered(inner, 76, 7);
            let [title, address_row, password_row, extra] = Layout::vertical([
                Constraint::Length(2),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            f.render_widget(
                Paragraph::new("Enter the onion address and password the sender printed:"),
                title,
            );
            tor_field_row(
                f,
                address_row,
                "Address:  ",
                address,
                *cursor,
                *field == TorField::Address,
            );
            tor_field_row(
                f,
                password_row,
                "Password: ",
                password,
                *cursor,
                *field == TorField::Password,
            );
            match error {
                Some(error) => widgets::error_line(f, extra, error),
                None => f.render_widget(
                    Paragraph::new("Both come from the sender's screen; the password is a PIN.")
                        .dim(),
                    extra,
                ),
            }
            widgets::key_hints(
                f,
                inner,
                "Enter next/confirm · Tab switch · ←/→ move · Esc back",
            );
        }
    }
}

/// One line of the Tor entry screen. Only the focused field draws a cursor, so
/// there is never a question about where typing lands.
#[cfg(feature = "tor")]
fn tor_field_row(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    label: &str,
    value: &str,
    cursor: usize,
    focused: bool,
) {
    if focused {
        widgets::input_line(f, area, label, value, cursor);
    } else {
        f.render_widget(Paragraph::new(format!("{label}{value}")).dim(), area);
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

    #[cfg(feature = "tor")]
    #[test]
    fn the_tor_mode_starts_a_transfer_rather_than_a_notice() {
        let Step::Continue(Screen::OutputDir { mode, .. }) =
            mode_menu_key(Direction::Receive, MODE_TOR, press(KeyCode::Enter))
        else {
            panic!("Tor should open the output directory picker");
        };
        // The mode has to survive the shared picker to pick the right plan.
        assert_eq!(mode, MODE_TOR);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn the_selected_mode_decides_the_send_plan() {
        assert!(matches!(
            send_plan(MODE_TOR, vec![PathBuf::from("a")]),
            WizardPlan::SendTor(_)
        ));
        assert!(matches!(
            send_plan(MODE_PIN, vec![PathBuf::from("a")]),
            WizardPlan::SendPin(_)
        ));
    }

    #[cfg(feature = "tor")]
    #[test]
    fn a_tor_entry_needs_a_real_onion_address_and_a_valid_password() {
        let onion = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";
        let password = crate::crypto::pin::generate_pin().unwrap();

        assert_eq!(validate_tor_entry(onion, &password).unwrap(), onion);
        // A port in the address is the sender's own output, so it stays.
        let with_port = format!("{onion}:9735");
        assert_eq!(validate_tor_entry(&with_port, &password).unwrap(), with_port);

        assert!(validate_tor_entry("", &password).is_err());
        // Anything that is not a v3 onion address would leave the onion
        // network through an exit node.
        assert!(validate_tor_entry("example.com", &password).is_err());
        assert!(validate_tor_entry(onion, "not-a-password").is_err());
    }

    #[cfg(feature = "tor")]
    #[test]
    fn tor_entry_walks_the_fields_then_finishes() {
        let onion = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";
        let password = crate::crypto::pin::generate_pin().unwrap();

        // Enter on the address moves to the password rather than submitting a
        // half-filled screen.
        let Step::Continue(Screen::TorEntry { field, cursor, .. }) = tor_entry_key(
            PathBuf::from("."),
            onion.to_string(),
            String::new(),
            TorField::Address,
            onion.len(),
            None,
            press(KeyCode::Enter),
        ) else {
            panic!("expected the Tor entry screen");
        };
        assert_eq!(field, TorField::Password);
        assert_eq!(cursor, 0);

        let Step::Finish(WizardPlan::ReceiveTor {
            address,
            password: entered,
            ..
        }) = tor_entry_key(
            PathBuf::from("."),
            format!("  {onion}  "),
            password.clone(),
            TorField::Password,
            password.len(),
            None,
            press(KeyCode::Enter),
        ) else {
            panic!("a complete screen should finish the wizard");
        };
        assert_eq!(address, onion, "the address is trimmed before use");
        assert_eq!(entered, password);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn a_multi_byte_character_in_the_address_leaves_the_cursor_usable() {
        // Regression: the cursor used to advance one byte per character, so a
        // single non-ASCII character left it inside that character and the
        // next redraw panicked.
        let mut screen = Screen::TorEntry {
            output: PathBuf::from("."),
            address: String::new(),
            password: String::new(),
            field: TorField::Address,
            cursor: 0,
            error: None,
        };

        for c in "a│b".chars() {
            let Step::Continue(next) = handle_key(screen, press(KeyCode::Char(c))) else {
                panic!("expected the Tor entry screen");
            };
            screen = next;
        }

        let Screen::TorEntry {
            address, cursor, ..
        } = &screen
        else {
            panic!("expected the Tor entry screen");
        };
        assert_eq!(address, "a│b");
        assert!(
            address.is_char_boundary(*cursor),
            "cursor {cursor} splits {address:?}"
        );

        // And such an address is refused with a message rather than accepted.
        let password = crate::crypto::pin::generate_pin().unwrap();
        assert!(validate_tor_entry(address, &password).is_err());
    }

    #[cfg(feature = "tor")]
    #[test]
    fn typing_lands_in_the_focused_tor_field_only() {
        // A character the password would reject must not leak into it from the
        // address line, where every printable character is allowed.
        let Step::Continue(Screen::TorEntry {
            address, password, ..
        }) = tor_entry_key(
            PathBuf::from("."),
            "abc".to_string(),
            String::new(),
            TorField::Address,
            3,
            None,
            press(KeyCode::Char('-')),
        ) else {
            panic!("expected the Tor entry screen");
        };
        assert_eq!(address, "abc-");
        assert!(password.is_empty());
    }

    #[cfg(feature = "tor")]
    #[test]
    fn a_full_tor_password_stops_accepting_characters() {
        // Regression: past PIN_LENGTH the typing guard failed and the keystroke
        // fell through to the shared line editor, which inserted it into the
        // focused field anyway — past the length cap and past the PIN filter.
        let full = crate::crypto::pin::generate_pin().unwrap();
        assert_eq!(full.len(), PIN_LENGTH);

        for typed in ['x', '*'] {
            let Step::Continue(Screen::TorEntry { password, .. }) = tor_entry_key(
                PathBuf::from("."),
                "kept.onion".to_string(),
                full.clone(),
                TorField::Password,
                full.len(),
                None,
                press(KeyCode::Char(typed)),
            ) else {
                panic!("expected the Tor entry screen");
            };
            assert_eq!(password, full, "{typed:?} should have been ignored");
        }
    }

    #[cfg(feature = "tor")]
    #[test]
    fn a_pasted_tor_password_is_filtered_like_a_pin() {
        let screen = Screen::TorEntry {
            output: PathBuf::from("."),
            address: "kept.onion".to_string(),
            password: "old".to_string(),
            field: TorField::Password,
            cursor: 3,
            error: None,
        };

        let Step::Continue(Screen::TorEntry {
            address,
            password,
            error,
            ..
        }) = handle_paste(screen, "AB*CD EFGHJKLc")
        else {
            panic!("paste should stay on the Tor entry screen");
        };
        assert_eq!(password, "ABCDEFGHJKLc");
        assert_eq!(address, "kept.onion", "the other field is untouched");
        assert_eq!(error.as_deref(), Some("Unsupported characters were removed"));
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
