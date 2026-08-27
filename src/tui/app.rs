//! Wizard state machine: collects everything a transfer needs before any
//! network work.
//!
//! The two directions ask for different things. Sending picks a mode and then a
//! selection; receiving picks an output directory and then pastes whatever the
//! sender handed over, and [`classify`] reads the mode off that rather than
//! asking for it a second time in a form the sender already answered.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind};
use futures_util::StreamExt;
use ratatui::DefaultTerminal;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Stylize;
use ratatui::widgets::Paragraph;

use crate::crypto::pin::{PinKind, classify_pin, pin_char};
// Only the Tor transport's password field is fixed to one length; a PIN
// Exchange PIN has two, and `PinKind` is what names them.
#[cfg(feature = "tor")]
use crate::crypto::pin::PIN_LENGTH;

use super::dir_picker::{DirPicker, DirPickerStep};
use super::file_browser::{Browser, BrowserStep};
use super::is_ctrl_c;
use super::widgets;

/// The resolved outcome of the wizard: what to transfer and how.
pub enum WizardPlan {
    SendPin {
        paths: Vec<PathBuf>,
        /// Which length the PINs this transfer mints are drawn at, and so
        /// which relay pool they are published on.
        pin_kind: PinKind,
    },
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

/// The transfer modes the sending side chooses between, in the pTransfer web
/// app's order, so an option's number means the same thing in both interfaces.
/// The Tor transport is the CLI's own third mode, and only exists in a build
/// with the `tor` feature.
///
/// Anonymous signaling is deliberately not a fourth entry. It is not a mode:
/// it changes which relays PIN Exchange signals over and nothing else, and the
/// web app has it as an advanced option of the PIN Exchange choice rather than
/// beside it. It is the same here — a toggle on the [`MODE_PIN`] row, off
/// until asked for.
///
/// There is no matching menu on the receiving side: what the sender hands over
/// says which mode it is, so [`classify`] reads the mode off it.
#[cfg(not(feature = "tor"))]
const MODES: [&str; 2] = ["PIN Exchange", "Code Exchange"];
#[cfg(feature = "tor")]
const MODES: [&str; 3] = [
    "PIN Exchange",
    "Code Exchange",
    "Tor Onion Service (experimental)",
];

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
    "An onion address and a password. Slow; up to 100 MiB.",
];

const MODE_PIN: usize = 0;
#[cfg(feature = "tor")]
const MODE_TOR: usize = 2;

/// The key that turns anonymous signaling on and off on the [`MODE_PIN`] row.
#[cfg(feature = "tor")]
const ANONYMOUS_KEY: char = 'a';

/// What the toggle under the menu says, given its state.
#[cfg(feature = "tor")]
fn anonymous_toggle_line(on: bool) -> &'static str {
    if on {
        "[x] Anonymous signaling (experimental)   a to turn off"
    } else {
        "[ ] Anonymous signaling (experimental)   a to turn on"
    }
}

/// What the toggle does, said the same way whichever state it is in: this is
/// the line someone reads to decide, so it cannot only appear once they have.
#[cfg(feature = "tor")]
const ANONYMOUS_TOGGLE_HINT: &str =
    "Signaling over Tor, so relays never see an IP. Slow to start; longer PIN.";

const CODE_EXCHANGE_UNAVAILABLE: &str =
    "Code Exchange is not implemented in the CLI yet — use PIN Exchange.";

/// What the receive box accepts, in the wording every message naming it uses.
/// Feature-gated so a build without Tor never offers something it cannot do.
#[cfg(feature = "tor")]
const ACCEPTED: &str = "a PIN or an onion address";
#[cfg(not(feature = "tor"))]
const ACCEPTED: &str = "a PIN";

/// What to say about text shaped like an onion address that is not one.
#[cfg(feature = "tor")]
const ONION_REJECTED: &str = "Not a valid onion address — check for typos";
#[cfg(not(feature = "tor"))]
const ONION_REJECTED: &str = "This build has no Tor support — rebuild it with --features tor";

/// What to say about a perfectly good anonymous-signaling PIN this build has
/// no Tor client to act on. It is not a typo, so it must not be reported as
/// one.
#[cfg(not(feature = "tor"))]
const ANONYMOUS_PIN_REJECTED: &str =
    "That PIN needs anonymous signaling — rebuild this with --features tor";

enum Screen {
    MainMenu {
        selected: usize,
    },
    /// Sending only. The receiving side has no such menu: it learns the mode
    /// from what it was handed.
    ModeMenu {
        selected: usize,
        /// Set when the highlighted mode cannot be started, cleared on move.
        notice: Option<String>,
        /// Whether PIN Exchange will signal over the onion relay pool. Only a
        /// `tor` build can turn it on — there is no client to reach that pool
        /// with otherwise — so it is false throughout a build without one.
        anonymous: bool,
    },
    /// The browser is shared by every send mode, so it carries the mode it was
    /// entered from: that decides which plan the wizard finishes with, and
    /// which row Esc returns to on the mode menu.
    FileBrowser {
        mode: usize,
        /// Carried for the same reason as `mode`: it is part of the answer the
        /// mode menu gave, and Esc has to return to the menu still holding it.
        anonymous: bool,
        browser: Browser,
    },
    /// Receiving picks a directory first, because the mode is not known until
    /// the sender's PIN or address lands in the box on the next screen.
    OutputDir {
        picker: DirPicker,
    },
    /// The one box the receiving side pastes into.
    ReceiveEntry {
        output: PathBuf,
        input: String,
        /// Insertion point in `input` (0..=len): standard line editing.
        cursor: usize,
        /// Set by a submit with nothing to act on; cleared by the next edit.
        error: Option<String>,
    },
    /// The second half of a Tor receive. The password is asked for only once
    /// the address is recognized, because it is a separate secret and the
    /// address alone already says which mode this is.
    #[cfg(feature = "tor")]
    TorPassword {
        output: PathBuf,
        /// The address that led here, kept so Esc goes back to it intact.
        address: String,
        password: String,
        cursor: usize,
        error: Option<String>,
    },
}

/// What the receiving side was handed, once recognized.
///
/// The receiver holds exactly one thing, and which one is decidable from the
/// text, so the wizard detects the mode instead of asking for it — the same
/// rule the web app's receive screen follows. Only Tor needs a second input
/// afterwards, because its password is a separate secret.
#[derive(Debug, PartialEq, Eq)]
enum Pasted {
    /// A PIN, with the mode its length announced: an anonymous one is
    /// published on a relay pool of onion services, and the receiver is told
    /// which by the PIN rather than asked.
    Pin { pin: String, kind: PinKind },
    /// A valid v3 onion address, in whichever of its two spellings was pasted;
    /// the transfer re-splits it into the `<host>:<port>` its handshake binds.
    #[cfg(feature = "tor")]
    Onion(String),
}

/// Why the receive box holds nothing to act on yet.
#[derive(Debug, PartialEq, Eq)]
enum Rejection {
    /// Nothing pasted or typed.
    Empty,
    /// The right shape, the wrong value.
    Malformed(&'static str),
    /// Neither shape.
    Unrecognized,
}

impl Rejection {
    /// The line to show for this rejection.
    fn message(&self) -> String {
        match self {
            Rejection::Empty => format!("Paste {ACCEPTED} from the sender"),
            Rejection::Malformed(message) => (*message).to_string(),
            Rejection::Unrecognized => {
                format!("That is not {ACCEPTED} — check that you copied the whole thing")
            }
        }
    }

    /// Whether it is worth saying before the box is submitted.
    ///
    /// A full-length value of the right shape can only be a typo, so saying so
    /// helps the moment it is true. The other two are true of every prefix of a
    /// valid value, and would blink at every keystroke.
    fn while_typing(&self) -> bool {
        matches!(self, Rejection::Malformed(_))
    }
}

/// Whether the text has a PIN's shape, checksum aside.
///
/// Tells "you mistyped a PIN" apart from "this is not a PIN at all", which
/// [`classify`] alone cannot express. The alphabet is ASCII, so a byte length
/// is a character count here.
fn looks_like_pin(text: &str) -> bool {
    PinKind::ALL.iter().any(|kind| kind.length() == text.len())
        && text.chars().all(|c| pin_char(c).is_some())
}

/// Whether the text has an onion address's shape, checksum aside.
fn looks_like_onion(text: &str) -> bool {
    let host = match text.rsplit_once(':') {
        Some((host, port)) => {
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            host
        }
        None => text,
    };
    host.to_ascii_lowercase().ends_with(".onion")
}

/// Identify what the receiving side pasted, or say why it is not usable.
fn classify(text: &str) -> Result<Pasted, Rejection> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Rejection::Empty);
    }

    if let Some(kind) = classify_pin(text) {
        // An anonymous PIN reaches a pool of onion services and nothing else,
        // so a build without the Tor client cannot act on one however valid it
        // is.
        #[cfg(not(feature = "tor"))]
        if kind == PinKind::Anonymous {
            return Err(Rejection::Malformed(ANONYMOUS_PIN_REJECTED));
        }
        return Ok(Pasted::Pin {
            pin: text.to_string(),
            kind,
        });
    }

    // Checked in full, checksum included: Arti resolves anything that is not a
    // v3 onion address through an exit node and off the onion network, so a
    // typo that survived to here would reach the plain internet.
    #[cfg(feature = "tor")]
    if crate::tor::split_address(text, crate::tor::DEFAULT_PORT).is_ok() {
        return Ok(Pasted::Onion(text.to_string()));
    }

    if looks_like_pin(text) {
        return Err(Rejection::Malformed("Invalid PIN — check for typos"));
    }
    if looks_like_onion(text) {
        return Err(Rejection::Malformed(ONION_REJECTED));
    }
    Err(Rejection::Unrecognized)
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
            selected, anonymous, ..
        } => mode_menu_key(selected, anonymous, key),
        Screen::FileBrowser {
            mode,
            anonymous,
            mut browser,
        } => match browser.handle_key(key) {
            BrowserStep::Stay => Step::Continue(Screen::FileBrowser {
                mode,
                anonymous,
                browser,
            }),
            BrowserStep::Back => Step::Continue(mode_menu_at(mode, anonymous)),
            BrowserStep::Confirm => Step::Finish(send_plan(mode, anonymous, browser.selection())),
        },
        Screen::OutputDir { mut picker } => match picker.handle_key(key) {
            DirPickerStep::Stay => Step::Continue(Screen::OutputDir { picker }),
            DirPickerStep::Back => Step::Continue(Screen::MainMenu { selected: 1 }),
            DirPickerStep::Choose(output) => Step::Continue(Screen::ReceiveEntry {
                output,
                input: String::new(),
                cursor: 0,
                error: None,
            }),
        },
        Screen::ReceiveEntry {
            output,
            input,
            cursor,
            error,
        } => receive_entry_key(output, input, cursor, error, key),
        #[cfg(feature = "tor")]
        Screen::TorPassword {
            output,
            address,
            password,
            cursor,
            error,
        } => tor_password_key(output, address, password, cursor, error, key),
    }
}

/// The plan a confirmed send selection produces in `mode`.
///
/// `anonymous` only ever reaches PIN Exchange: it is the length its PINs are
/// minted at, which is the whole of what the option changes.
fn send_plan(mode: usize, anonymous: bool, paths: Vec<PathBuf>) -> WizardPlan {
    match mode {
        #[cfg(feature = "tor")]
        MODE_TOR => WizardPlan::SendTor(paths),
        _ => WizardPlan::SendPin {
            paths,
            pin_kind: if anonymous {
                PinKind::Anonymous
            } else {
                PinKind::Standard
            },
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
            0 => Step::Continue(mode_menu()),
            // Straight to the output directory: the receiving side is not asked
            // how to connect, it is told by what it pastes afterwards.
            1 => match DirPicker::new() {
                Ok(picker) => Step::Continue(Screen::OutputDir { picker }),
                Err(_) => Step::Continue(Screen::MainMenu { selected }),
            },
            _ => Step::Quit,
        },
        KeyCode::Esc | KeyCode::Char('q') => Step::Quit,
        _ => Step::Continue(Screen::MainMenu {
            selected: menu_move(selected, 3, &key),
        }),
    }
}

/// The send mode menu, with the first mode highlighted and the option off.
fn mode_menu() -> Screen {
    mode_menu_at(MODE_PIN, false)
}

/// The send mode menu as it was left — what going back from the file browser
/// returns to.
fn mode_menu_at(selected: usize, anonymous: bool) -> Screen {
    Screen::ModeMenu {
        selected,
        notice: None,
        anonymous,
    }
}

fn mode_menu_key(selected: usize, anonymous: bool, key: KeyEvent) -> Step {
    let stay = |notice: Option<String>| {
        Step::Continue(Screen::ModeMenu {
            selected,
            notice,
            anonymous,
        })
    };

    // Code Exchange is a placeholder that keeps the CLI's mode numbering
    // aligned with the web app's; every other mode runs a transfer.
    #[cfg(not(feature = "tor"))]
    let implemented = selected == MODE_PIN;
    #[cfg(feature = "tor")]
    let implemented = selected == MODE_PIN || selected == MODE_TOR;

    // The option belongs to PIN Exchange, so the key does nothing on any other
    // row rather than setting something that row would ignore.
    #[cfg(feature = "tor")]
    if key.code == KeyCode::Char(ANONYMOUS_KEY) && selected == MODE_PIN {
        return Step::Continue(mode_menu_at(selected, !anonymous));
    }

    match key.code {
        KeyCode::Enter if !implemented => stay(Some(CODE_EXCHANGE_UNAVAILABLE.to_string())),
        KeyCode::Enter => match Browser::new() {
            Ok(browser) => Step::Continue(Screen::FileBrowser {
                mode: selected,
                anonymous,
                browser,
            }),
            Err(_) => stay(None),
        },
        KeyCode::Esc => Step::Continue(Screen::MainMenu { selected: 0 }),
        _ => Step::Continue(Screen::ModeMenu {
            selected: menu_move(selected, MODES.len(), &key),
            notice: None,
            anonymous,
        }),
    }
}

/// The receive box: one field that decides the mode by what lands in it.
///
/// Every printable character is accepted and the value is judged as a whole,
/// because the field has to hold both a PIN and an onion address — filtering
/// per keystroke would have to reject one to allow the other.
fn receive_entry_key(
    output: PathBuf,
    mut input: String,
    mut cursor: usize,
    mut error: Option<String>,
    key: KeyEvent,
) -> Step {
    let mut edited = false;
    match key.code {
        KeyCode::Enter => match classify(&input) {
            Ok(Pasted::Pin { pin, .. }) => {
                return Step::Finish(WizardPlan::ReceivePin { pin, output });
            }
            #[cfg(feature = "tor")]
            Ok(Pasted::Onion(address)) => {
                return Step::Continue(Screen::TorPassword {
                    output,
                    address,
                    password: String::new(),
                    cursor: 0,
                    error: None,
                });
            }
            Err(rejection) => error = Some(rejection.message()),
        },
        KeyCode::Esc => {
            return Step::Continue(Screen::OutputDir {
                picker: DirPicker::at(output),
            });
        }
        _ => edited = widgets::edit_line(&mut input, &mut cursor, &key),
    }

    if edited {
        error = None;
    }

    Step::Continue(Screen::ReceiveEntry {
        output,
        input,
        cursor,
        error,
    })
}

/// The password half of a Tor receive.
#[cfg(feature = "tor")]
fn tor_password_key(
    output: PathBuf,
    address: String,
    mut password: String,
    mut cursor: usize,
    mut error: Option<String>,
    key: KeyEvent,
) -> Step {
    let mut edited = false;
    match key.code {
        KeyCode::Enter => {
            // The transport's password is not a PIN Exchange PIN and selects
            // no relay pool, so only the ordinary length is a password here.
            if classify_pin(&password) == Some(PinKind::Standard) {
                return Step::Finish(WizardPlan::ReceiveTor {
                    address,
                    password,
                    output,
                });
            }
            error = Some("Invalid password: check for typos and try again".to_string());
        }
        // Back to the address as it was typed, not to an empty box.
        KeyCode::Esc => {
            return Step::Continue(Screen::ReceiveEntry {
                output,
                cursor: address.len(),
                input: address,
                error: None,
            });
        }
        // The password is a PIN, so it filters exactly like one, and a full one
        // swallows further characters instead of growing. Every `Char` is
        // handled here: falling through to the shared line editor would insert
        // whatever the filter just rejected.
        KeyCode::Char(c) => {
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
        _ => edited = widgets::edit_line(&mut password, &mut cursor, &key),
    }

    if edited {
        error = None;
    }
    // Say so on the last keystroke rather than waiting for a submit to fail.
    if error.is_none()
        && password.len() == PIN_LENGTH
        && classify_pin(&password) != Some(PinKind::Standard)
    {
        error = Some("Invalid password: check for typos".to_string());
    }

    Step::Continue(Screen::TorPassword {
        output,
        address,
        password,
        cursor,
        error,
    })
}

fn handle_paste(screen: Screen, pasted: &str) -> Step {
    match screen {
        // Whole-field replacement: a paste is a fresh value, not an insertion.
        // Trimmed, because a copied PIN or address routinely arrives with a
        // trailing newline, and nothing else is filtered — the field has to
        // hold either kind and [`classify`] judges the result.
        Screen::ReceiveEntry { output, .. } => {
            let input = pasted.trim().to_string();
            Step::Continue(Screen::ReceiveEntry {
                output,
                cursor: input.len(),
                input,
                error: None,
            })
        }
        #[cfg(feature = "tor")]
        Screen::TorPassword {
            output, address, ..
        } => {
            let (password, dropped) = filter_pin_paste(pasted);
            Step::Continue(Screen::TorPassword {
                output,
                address,
                cursor: password.len(),
                password,
                error: dropped.then(|| "Unsupported characters were removed".to_string()),
            })
        }
        _ => Step::Continue(screen),
    }
}

/// Reduce pasted text to a PIN, reporting whether anything was dropped.
#[cfg(feature = "tor")]
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
            selected,
            notice,
            anonymous,
        } => {
            let inner = widgets::screen_frame(f, "send");
            // Three rows under the menu: the highlighted mode's hint, then the
            // option that belongs to PIN Exchange and what it does.
            let area = widgets::centered(inner, 76, MODES.len() as u16 + 5);
            let [title, _, list, extra] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(MODES.len() as u16),
                Constraint::Fill(1),
            ])
            .areas(area);
            f.render_widget(Paragraph::new("How do you want to connect?"), title);
            widgets::menu(f, list, &MODES, *selected);
            let [hint, option, option_hint] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .areas(extra);
            match notice {
                Some(notice) => widgets::error_line(f, hint, notice),
                None => f.render_widget(Paragraph::new(MODE_HINTS[*selected]).dim(), hint),
            }
            #[cfg(feature = "tor")]
            if *selected == MODE_PIN {
                f.render_widget(Paragraph::new(anonymous_toggle_line(*anonymous)), option);
                f.render_widget(Paragraph::new(ANONYMOUS_TOGGLE_HINT).dim(), option_hint);
            }
            #[cfg(not(feature = "tor"))]
            let _ = (anonymous, option, option_hint);
            widgets::key_hints(f, inner, "↑/↓ move · Enter select · Esc back");
        }

        Screen::FileBrowser { browser, .. } => {
            let inner = widgets::screen_frame(f, "send");
            browser.render(f, inner);
        }

        Screen::OutputDir { picker } => {
            let inner = widgets::screen_frame(f, "receive");
            picker.render(f, inner);
        }

        Screen::ReceiveEntry {
            input,
            cursor,
            error,
            ..
        } => {
            let inner = widgets::screen_frame(f, "receive");
            let area = widgets::centered(inner, 76, 6);
            let [title, line, extra] = Layout::vertical([
                Constraint::Length(2),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            f.render_widget(
                Paragraph::new(format!("Paste {ACCEPTED} from the sender:")),
                title,
            );
            widgets::input_line(f, line, "> ", input, *cursor);
            match (error.as_deref(), classify(input)) {
                (Some(error), _) => widgets::error_line(f, extra, error),
                // Naming what was recognized is the whole point of the screen:
                // it is how the receiver sees which mode they are about to run
                // without ever having been asked.
                (None, Ok(Pasted::Pin { kind, .. })) => f.render_widget(
                    Paragraph::new(match kind {
                        PinKind::Standard => {
                            "PIN detected. After you start, read the confirmation code to the sender."
                        }
                        PinKind::Anonymous => {
                            "Anonymous-signaling PIN detected — starting Tor first takes a few minutes."
                        }
                    })
                    .dim(),
                    extra,
                ),
                #[cfg(feature = "tor")]
                (None, Ok(Pasted::Onion(_))) => f.render_widget(
                    Paragraph::new("Onion address detected — the password comes next.").dim(),
                    extra,
                ),
                (None, Err(rejection)) if rejection.while_typing() => {
                    widgets::error_line(f, extra, &rejection.message());
                }
                (None, Err(_)) => {}
            }
            widgets::key_hints(f, inner, "Enter confirm · ←/→ move · Esc back");
        }

        #[cfg(feature = "tor")]
        Screen::TorPassword {
            address,
            password,
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
                Paragraph::new("Enter the one-time password the sender printed:"),
                title,
            );
            // Shown, not editable: Esc goes back to the box it came from.
            f.render_widget(
                Paragraph::new(format!("Address:  {address}")).dim(),
                address_row,
            );
            widgets::input_line(f, password_row, "Password: ", password, *cursor);
            match error {
                Some(error) => widgets::error_line(f, extra, error),
                None => f.render_widget(
                    Paragraph::new("The password is a PIN, from the sender's screen.").dim(),
                    extra,
                ),
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

    #[cfg(feature = "tor")]
    const ONION: &str = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";

    #[test]
    fn code_exchange_reports_that_it_is_not_implemented() {
        let step = mode_menu_key(1, false, press(KeyCode::Enter));

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
        let step = mode_menu_key(1, false, press(KeyCode::Up));

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
    fn escaping_the_mode_menu_reselects_send() {
        // The mode menu is the sending side's alone, so Esc lands back on Send.
        let Step::Continue(Screen::MainMenu { selected }) =
            mode_menu_key(0, false, press(KeyCode::Esc))
        else {
            panic!("Esc should return to the main menu");
        };
        assert_eq!(selected, 0);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn the_tor_mode_starts_a_selection_rather_than_a_notice() {
        let step = mode_menu_key(MODE_TOR, false, press(KeyCode::Enter));
        let Step::Continue(Screen::FileBrowser { mode, .. }) = step else {
            panic!("Tor should open the file browser");
        };
        // The mode has to survive the shared browser to pick the right plan.
        assert_eq!(mode, MODE_TOR);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn the_selected_mode_decides_the_send_plan() {
        assert!(matches!(
            send_plan(MODE_TOR, false, vec![PathBuf::from("a")]),
            WizardPlan::SendTor(_)
        ));
        assert!(matches!(
            send_plan(MODE_PIN, false, vec![PathBuf::from("a")]),
            WizardPlan::SendPin {
                pin_kind: PinKind::Standard,
                ..
            }
        ));
        // The only thing the option changes is the length of the PINs this
        // transfer mints, which is what carries the mode to the receiver.
        assert!(matches!(
            send_plan(MODE_PIN, true, vec![PathBuf::from("a")]),
            WizardPlan::SendPin {
                pin_kind: PinKind::Anonymous,
                ..
            }
        ));
    }

    /// The option is PIN Exchange's, the way the web app has it under that
    /// mode's advanced options rather than as a mode of its own.
    #[cfg(feature = "tor")]
    #[test]
    fn the_anonymous_toggle_belongs_to_pin_exchange_alone() {
        let toggle = press(KeyCode::Char(ANONYMOUS_KEY));

        let Step::Continue(Screen::ModeMenu {
            selected, anonymous, ..
        }) = mode_menu_key(MODE_PIN, false, toggle)
        else {
            panic!("the toggle should stay on the mode menu");
        };
        assert_eq!(selected, MODE_PIN);
        assert!(anonymous, "a should turn the option on");

        // And back off again: it is a toggle, not a one-way switch.
        let Step::Continue(Screen::ModeMenu { anonymous, .. }) =
            mode_menu_key(MODE_PIN, true, toggle)
        else {
            panic!("the toggle should stay on the mode menu");
        };
        assert!(!anonymous);

        // On the Tor row the key is not a toggle, so it falls through to the
        // menu's ordinary handling and changes nothing.
        let Step::Continue(Screen::ModeMenu {
            selected, anonymous, ..
        }) = mode_menu_key(MODE_TOR, false, toggle)
        else {
            panic!("expected the mode menu");
        };
        assert_eq!(selected, MODE_TOR);
        assert!(!anonymous);
    }

    /// Turning it on and then picking files has to reach the plan: the browser
    /// sits between the two and carries the answer across.
    #[cfg(feature = "tor")]
    #[test]
    fn the_toggle_survives_the_file_browser() {
        let Step::Continue(Screen::FileBrowser { mode, anonymous, .. }) =
            mode_menu_key(MODE_PIN, true, press(KeyCode::Enter))
        else {
            panic!("PIN Exchange should open the file browser");
        };
        assert_eq!(mode, MODE_PIN);
        assert!(anonymous);
        assert!(matches!(
            send_plan(mode, anonymous, vec![PathBuf::from("a")]),
            WizardPlan::SendPin {
                pin_kind: PinKind::Anonymous,
                ..
            }
        ));
    }

    #[test]
    fn receiving_goes_straight_to_the_output_directory() {
        // No mode menu on the way in: the mode comes from what gets pasted.
        let Step::Continue(Screen::OutputDir { .. }) = main_menu_key(1, press(KeyCode::Enter))
        else {
            panic!("Receive should open the output directory picker");
        };
    }

    #[test]
    fn a_pasted_pin_is_recognized_without_being_asked_which_mode_it_is() {
        let pin = crate::crypto::pin::generate_pin(PinKind::Standard).unwrap();
        assert_eq!(
            classify(&pin),
            Ok(Pasted::Pin {
                pin: pin.clone(),
                kind: PinKind::Standard
            })
        );
        // Surrounding whitespace comes along with almost every copy.
        assert_eq!(
            classify(&format!("  {pin}\n")),
            Ok(Pasted::Pin {
                pin,
                kind: PinKind::Standard
            })
        );
    }

    /// The receiver is never asked whether the sender turned on anonymous
    /// signaling: the PIN it was handed is longer, and that is the whole
    /// announcement.
    #[cfg(feature = "tor")]
    #[test]
    fn a_pasted_anonymous_pin_is_recognized_as_one() {
        let pin = crate::crypto::pin::generate_pin(PinKind::Anonymous).unwrap();
        assert_eq!(
            classify(&pin),
            Ok(Pasted::Pin {
                pin: pin.clone(),
                kind: PinKind::Anonymous
            })
        );
    }

    /// Without the Tor client there is no onion relay pool to look on, so a
    /// perfectly valid anonymous PIN has to be refused — and not as a typo,
    /// which it is not.
    #[cfg(not(feature = "tor"))]
    #[test]
    fn an_anonymous_pin_is_refused_by_a_build_without_tor() {
        let pin = crate::crypto::pin::generate_pin(PinKind::Anonymous).unwrap();
        assert_eq!(
            classify(&pin),
            Err(Rejection::Malformed(ANONYMOUS_PIN_REJECTED))
        );
    }

    #[cfg(feature = "tor")]
    #[test]
    fn a_pasted_onion_address_is_recognized_in_either_spelling() {
        assert_eq!(classify(ONION), Ok(Pasted::Onion(ONION.to_string())));
        // A port in the address is the sender's own output, so it stays: the
        // transfer re-splits it into the string the handshake binds.
        let with_port = format!("{ONION}:9736");
        assert_eq!(
            classify(&format!(" {with_port} ")),
            Ok(Pasted::Onion(with_port))
        );
    }

    #[test]
    fn a_typo_is_named_while_typing_and_anything_else_only_on_submit() {
        assert_eq!(classify(""), Err(Rejection::Empty));

        // Full length and the right alphabet: only a typo can explain it, so it
        // is worth saying before Enter.
        let typo = classify("ABCDEFGHJKLM").unwrap_err();
        assert!(typo.while_typing(), "a bad checksum should be called out");

        // A prefix of a valid value looks like this, so it waits for a submit.
        let partial = classify("ABCDE").unwrap_err();
        assert_eq!(partial, Rejection::Unrecognized);
        assert!(!partial.while_typing());
        assert!(partial.message().contains("copied the whole thing"));
    }

    #[test]
    fn something_shaped_like_an_onion_address_gets_its_own_complaint() {
        // Whether or not this build can use one, "that address is wrong" beats
        // "that is not a PIN".
        let rejection = classify("nothexactly.onion").unwrap_err();
        assert_eq!(rejection, Rejection::Malformed(ONION_REJECTED));
        assert!(rejection.while_typing());

        // A trailing port is part of the shape; a trailing anything else is not.
        assert!(looks_like_onion("abc.onion:9735"));
        assert!(!looks_like_onion("abc.onion:x"));
        assert!(!looks_like_onion("example.com"));
    }

    #[test]
    fn a_recognized_pin_finishes_the_wizard() {
        let pin = crate::crypto::pin::generate_pin(PinKind::Standard).unwrap();
        let Step::Finish(WizardPlan::ReceivePin { pin: entered, .. }) = receive_entry_key(
            PathBuf::from("."),
            format!(" {pin} "),
            pin.len(),
            None,
            press(KeyCode::Enter),
        ) else {
            panic!("a valid PIN should finish the wizard");
        };
        assert_eq!(entered, pin);
    }

    #[test]
    fn an_unusable_entry_reports_why_instead_of_starting() {
        let Step::Continue(Screen::ReceiveEntry { error, .. }) = receive_entry_key(
            PathBuf::from("."),
            "not-anything".to_string(),
            12,
            None,
            press(KeyCode::Enter),
        ) else {
            panic!("expected the receive entry screen");
        };
        assert_eq!(error, Some(Rejection::Unrecognized.message()));
    }

    #[cfg(feature = "tor")]
    #[test]
    fn an_onion_address_asks_for_the_password_and_then_finishes() {
        // Enter on a recognized address opens the password screen rather than
        // submitting: the address alone already fixed the mode.
        let Step::Continue(Screen::TorPassword {
            address,
            password,
            cursor,
            ..
        }) = receive_entry_key(
            PathBuf::from("."),
            format!("  {ONION}  "),
            ONION.len(),
            None,
            press(KeyCode::Enter),
        )
        else {
            panic!("an onion address should lead to the password screen");
        };
        assert_eq!(address, ONION, "the address is trimmed before use");
        assert!(password.is_empty());
        assert_eq!(cursor, 0);

        let entered = crate::crypto::pin::generate_pin(PinKind::Standard).unwrap();
        let Step::Finish(WizardPlan::ReceiveTor {
            address, password, ..
        }) = tor_password_key(
            PathBuf::from("."),
            address,
            entered.clone(),
            entered.len(),
            None,
            press(KeyCode::Enter),
        )
        else {
            panic!("a valid password should finish the wizard");
        };
        assert_eq!(address, ONION);
        assert_eq!(password, entered);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn escaping_the_password_returns_the_address_to_the_box() {
        let Step::Continue(Screen::ReceiveEntry { input, cursor, .. }) = tor_password_key(
            PathBuf::from("."),
            ONION.to_string(),
            "ABC".to_string(),
            3,
            None,
            press(KeyCode::Esc),
        ) else {
            panic!("Esc should go back to the receive box");
        };
        assert_eq!(input, ONION, "the address should not have to be retyped");
        assert_eq!(cursor, ONION.len());
    }

    #[test]
    fn a_multi_byte_character_in_the_box_leaves_the_cursor_usable() {
        // Regression: the cursor used to advance one byte per character, so a
        // single non-ASCII character left it inside that character and the
        // next redraw panicked.
        let mut screen = Screen::ReceiveEntry {
            output: PathBuf::from("."),
            input: String::new(),
            cursor: 0,
            error: None,
        };

        for c in "a│b".chars() {
            let Step::Continue(next) = handle_key(screen, press(KeyCode::Char(c))) else {
                panic!("expected the receive entry screen");
            };
            screen = next;
        }

        let Screen::ReceiveEntry { input, cursor, .. } = &screen else {
            panic!("expected the receive entry screen");
        };
        assert_eq!(input, "a│b");
        assert!(
            input.is_char_boundary(*cursor),
            "cursor {cursor} splits {input:?}"
        );
        // And such an entry is refused with a message rather than accepted.
        assert!(classify(input).is_err());
    }

    #[test]
    fn a_pasted_pin_lands_in_the_box_untouched() {
        // The box has to hold an onion address too, so unlike the old PIN-only
        // screen it filters nothing: only the surrounding whitespace goes.
        let screen = Screen::ReceiveEntry {
            output: PathBuf::from("."),
            input: "old".to_string(),
            cursor: 3,
            error: Some("stale".to_string()),
        };
        let pin = crate::crypto::pin::generate_pin(PinKind::Standard).unwrap();

        let Step::Continue(Screen::ReceiveEntry {
            input,
            cursor,
            error,
            ..
        }) = handle_paste(screen, &format!("{pin}\n"))
        else {
            panic!("paste should remain on the receive entry screen");
        };
        assert_eq!(input, pin);
        assert_eq!(cursor, pin.len());
        assert!(error.is_none());
    }

    #[cfg(feature = "tor")]
    #[test]
    fn a_full_tor_password_stops_accepting_characters() {
        // Regression: past PIN_LENGTH the typing guard failed and the keystroke
        // fell through to the shared line editor, which inserted it into the
        // field anyway — past the length cap and past the PIN filter.
        let full = crate::crypto::pin::generate_pin(PinKind::Standard).unwrap();
        assert_eq!(full.len(), PIN_LENGTH);

        for typed in ['x', '*'] {
            let Step::Continue(Screen::TorPassword { password, .. }) = tor_password_key(
                PathBuf::from("."),
                ONION.to_string(),
                full.clone(),
                full.len(),
                None,
                press(KeyCode::Char(typed)),
            ) else {
                panic!("expected the Tor password screen");
            };
            assert_eq!(password, full, "{typed:?} should have been ignored");
        }
    }

    #[cfg(feature = "tor")]
    #[test]
    fn a_pasted_tor_password_is_filtered_like_a_pin() {
        let screen = Screen::TorPassword {
            output: PathBuf::from("."),
            address: ONION.to_string(),
            password: "old".to_string(),
            cursor: 3,
            error: None,
        };

        let Step::Continue(Screen::TorPassword {
            address,
            password,
            error,
            ..
        }) = handle_paste(screen, "AB*CD EFGHJKLc")
        else {
            panic!("paste should stay on the Tor password screen");
        };
        assert_eq!(password, "ABCDEFGHJKLc");
        assert_eq!(address, ONION, "the address is not touched by the paste");
        assert_eq!(error.as_deref(), Some("Unsupported characters were removed"));
    }
}
