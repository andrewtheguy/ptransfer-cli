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
    SendCode {
        paths: Vec<PathBuf>,
        /// Whether the offer asks for the Tor fallback when no direct route
        /// exists. The sender's switch, carried in the code itself.
        anonymous: bool,
    },
    ReceiveCode {
        /// The sender's offer code, exactly as it was pasted.
        offer: String,
        output: PathBuf,
        /// Whether to answer with none of this device's network routes in the
        /// response, so the sender's direct attempt has nothing to connect to
        /// and the offer's anonymous fallback runs instead. Only ever set for
        /// an offer that has one.
        simulate_no_direct: bool,
    },
    SendTor(Vec<PathBuf>),
    ReceiveTor {
        address: String,
        password: String,
        output: PathBuf,
    },
}

/// The transfer modes the sending side chooses between, in the pTransfer web
/// app's order, so an option's number means the same thing in both interfaces.
/// The Tor transport is the CLI's own third mode.
///
/// The anonymous option is deliberately not a fourth entry. It is not a mode:
/// on PIN Exchange it changes which relays signaling goes over, and on Code
/// Exchange it changes where a failed direct connection falls back to. The web
/// app has it as an advanced option of each of those choices rather than
/// beside them, and it is the same here — a toggle on the row it belongs to,
/// off until asked for.
///
/// There is no matching menu on the receiving side: what the sender hands over
/// says which mode it is, so [`classify`] reads the mode off it.
const MODES: [&str; 3] = [
    "PIN Exchange",
    "Code Exchange",
    "Tor Onion Service (experimental)",
];

/// One line of explanation per entry in [`MODES`].
const MODE_HINTS: [&str; 3] = [
    "A short PIN over relays, then a direct WebRTC transfer.",
    "Codes you carry by hand. No relay sees the exchange.",
    "An onion address and a password. Slow; up to 100 MiB.",
];

const MODE_PIN: usize = 0;
const MODE_CODE: usize = 1;
const MODE_TOR: usize = 2;

/// The key that turns the anonymous option on and off, on the two rows that
/// have one.
const ANONYMOUS_KEY: char = 'a';

/// Whether the highlighted mode has an anonymous option at all.
fn has_anonymous_option(mode: usize) -> bool {
    mode == MODE_PIN || mode == MODE_CODE
}

/// What the toggle under the menu says, given the row it is on and its state.
fn anonymous_toggle_line(mode: usize, on: bool) -> &'static str {
    match (mode, on) {
        (MODE_CODE, true) => "[x] Anonymous signaling and relay (experimental)   a to turn off",
        (MODE_CODE, false) => "[ ] Anonymous signaling and relay (experimental)   a to turn on",
        (_, true) => "[x] Anonymous signaling (experimental)   a to turn off",
        (_, false) => "[ ] Anonymous signaling (experimental)   a to turn on",
    }
}

/// What the toggle does, said the same way whichever state it is in: this is
/// the line someone reads to decide, so it cannot only appear once they have.
fn anonymous_toggle_hint(mode: usize) -> &'static str {
    if mode == MODE_CODE {
        "No direct route? Relay the file over Tor instead. Slow; up to 100 MiB."
    } else {
        "Signaling over Tor, so relays never see an IP. Slow to start; longer PIN."
    }
}

/// The key that turns the receiving side's simulated dead route on and off.
///
/// Not a letter, unlike the sending side's: the row it sits under is a text
/// field, where every printable character is part of the value being typed.
const SIMULATE_KEY: KeyCode = KeyCode::Tab;

/// What the simulated-dead-route toggle says, in the state it is in.
fn simulate_toggle_line(on: bool) -> &'static str {
    if on {
        "[x] Simulate no direct connection   Tab to turn off"
    } else {
        "[ ] Simulate no direct connection   Tab to turn on"
    }
}

/// What the toggle does, said in both states for the same reason the sending
/// side's hint is: this is the line someone reads to decide.
fn simulate_toggle_hint(on: bool) -> &'static str {
    if on {
        "The response leaves out this device's routes, so the file comes over Tor."
    } else {
        "Drops the direct route on purpose, to exercise the sender's Tor fallback."
    }
}

/// What the receive box accepts, in the wording every message naming it uses.
const ACCEPTED: &str = "a PIN, an onion address, or a sender code";

/// What to say about text shaped like an onion address that is not one.
const ONION_REJECTED: &str = "Not a valid onion address — check for typos";

enum Screen {
    MainMenu {
        selected: usize,
    },
    /// Sending only. The receiving side has no such menu: it learns the mode
    /// from what it was handed.
    ModeMenu {
        selected: usize,
        /// Whether the highlighted mode's anonymous option is on. Every mode
        /// that has one starts with it off.
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
        /// Whether the simulated dead route is armed. Kept across edits, and
        /// read only while what is in the box is an offer with a fallback, so
        /// it can never reach a transfer that has nothing to fall back onto.
        simulate: bool,
    },
    /// The second half of a Tor receive. The password is asked for only once
    /// the address is recognized, because it is a separate secret and the
    /// address alone already says which mode this is.
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
    Onion(String),
    /// A Code Exchange sender code: the whole offer, carried by hand.
    Code {
        /// Kept exactly as pasted, because the confirmation tag the response
        /// carries is bound to a digest of exactly these bytes.
        offer: String,
        /// Whether the offer asks for the anonymous fallback. That is the only
        /// thing a dead direct route can fall back onto, so it is also what
        /// decides whether the simulated one is offered at all.
        fallback: bool,
    },
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

/// Whether a receive-box value is too long to render as an editable line.
///
/// Only a Code Exchange offer ever is: a PIN is 12 or 16 characters and an
/// onion address 62. The threshold sits above both with room to spare, so a
/// half-typed value of either kind still edits normally.
fn is_long_paste(text: &str) -> bool {
    text.len() > 80
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
        return Ok(Pasted::Pin {
            pin: text.to_string(),
            kind,
        });
    }

    // Checked in full, checksum included: Arti resolves anything that is not a
    // v3 onion address through an exit node and off the onion network, so a
    // typo that survived to here would reach the plain internet.
    if crate::tor::split_address(text, crate::tor::DEFAULT_PORT).is_ok() {
        return Ok(Pasted::Onion(text.to_string()));
    }

    // A sender code is the one entry here with no shape of its own to guess
    // at, so it is recognized by decoding: base64 that unwraps to a PT01
    // container is one, and nothing else is.
    if let Ok(binary) = crate::code::payload::from_clipboard(text)
        && crate::code::payload::is_code_payload(&binary)
    {
        // A container that will not decode is still a sender code, and saying
        // why — expired, or minted in some other hour — is the receive path's
        // job, which reports the reason. All that is read out of it here is
        // whether there is a fallback for the simulation to run into.
        let fallback =
            crate::code::payload::decode(&binary).is_ok_and(|offer| offer.is_anonymous());
        return Ok(Pasted::Code {
            offer: text.to_string(),
            fallback,
        });
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
                simulate: false,
            }),
        },
        Screen::ReceiveEntry {
            output,
            input,
            cursor,
            error,
            simulate,
        } => receive_entry_key(output, input, cursor, error, simulate, key),
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
        MODE_TOR => WizardPlan::SendTor(paths),
        MODE_CODE => WizardPlan::SendCode { paths, anonymous },
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
        anonymous,
    }
}

fn mode_menu_key(selected: usize, anonymous: bool, key: KeyEvent) -> Step {

    // The option belongs to two of the three rows, so the key does nothing on
    // the third rather than setting something that row would ignore.
    if key.code == KeyCode::Char(ANONYMOUS_KEY) && has_anonymous_option(selected) {
        return Step::Continue(mode_menu_at(selected, !anonymous));
    }

    match key.code {
        KeyCode::Enter => match Browser::new() {
            Ok(browser) => Step::Continue(Screen::FileBrowser {
                mode: selected,
                anonymous,
                browser,
            }),
            // A browser that cannot open its starting directory leaves the
            // menu where it is rather than moving on to nothing.
            Err(_) => Step::Continue(mode_menu_at(selected, anonymous)),
        },
        KeyCode::Esc => Step::Continue(Screen::MainMenu { selected: 0 }),
        _ => Step::Continue(mode_menu_at(
            menu_move(selected, MODES.len(), &key),
            anonymous,
        )),
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
    simulate: bool,
    key: KeyEvent,
) -> Step {
    // The toggle belongs to the one thing in the box that has something to
    // fall back onto, so on anything else the key does nothing rather than
    // arming a simulation the transfer would refuse to run.
    if key.code == SIMULATE_KEY && simulate_offered(&input) {
        return Step::Continue(Screen::ReceiveEntry {
            output,
            input,
            cursor,
            error,
            simulate: !simulate,
        });
    }

    let mut edited = false;
    match key.code {
        KeyCode::Enter => match classify(&input) {
            Ok(Pasted::Pin { pin, .. }) => {
                return Step::Finish(WizardPlan::ReceivePin { pin, output });
            }
            Ok(Pasted::Code { offer, fallback }) => {
                return Step::Finish(WizardPlan::ReceiveCode {
                    offer,
                    output,
                    simulate_no_direct: simulate && fallback,
                });
            }
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
        simulate,
    })
}

/// Whether what is in the receive box has a fallback to simulate a dead route
/// into: a sender code, from a sender that turned the anonymous option on.
fn simulate_offered(input: &str) -> bool {
    matches!(classify(input), Ok(Pasted::Code { fallback: true, .. }))
}

/// The password half of a Tor receive.
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
                // An onion address is what led here, and it has no fallback to
                // simulate one into.
                simulate: false,
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
        Screen::ReceiveEntry {
            output, simulate, ..
        } => {
            let input = pasted.trim().to_string();
            Step::Continue(Screen::ReceiveEntry {
                output,
                cursor: input.len(),
                input,
                error: None,
                // Kept across the paste: pasting a second code is how a
                // refused or stale offer is retried, and the choice made about
                // the first one still stands.
                simulate,
            })
        }
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
            anonymous,
        } => {
            let inner = widgets::screen_frame(f, "send");
            // Three rows under the menu: the highlighted mode's hint, then the
            // anonymous option of the mode that has one, and what it does.
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
            f.render_widget(Paragraph::new(MODE_HINTS[*selected]).dim(), hint);
            if has_anonymous_option(*selected) {
                f.render_widget(
                    Paragraph::new(anonymous_toggle_line(*selected, *anonymous)),
                    option,
                );
                f.render_widget(
                    Paragraph::new(anonymous_toggle_hint(*selected)).dim(),
                    option_hint,
                );
            }
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
            simulate,
            ..
        } => {
            let inner = widgets::screen_frame(f, "receive");
            // Two rows taller once the box holds an offer with a fallback: the
            // simulated dead route, and what turning it on does.
            let offered = simulate_offered(input);
            let area = widgets::centered(inner, 76, if offered { 8 } else { 6 });
            let [title, line, extra, option, option_hint] = Layout::vertical([
                Constraint::Length(2),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(area);
            f.render_widget(
                Paragraph::new(format!("Paste {ACCEPTED} from the sender:")),
                title,
            );
            // A sender code is kilobytes of base64: rendering it into a
            // one-line field would show a meaningless slice of it and put the
            // cursor somewhere off screen, so it is summarized instead.
            if is_long_paste(input) {
                f.render_widget(
                    Paragraph::new(format!("> [sender code, {} characters]", input.len())),
                    line,
                );
            } else {
                widgets::input_line(f, line, "> ", input, *cursor);
            }
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
                (None, Ok(Pasted::Onion(_))) => f.render_widget(
                    Paragraph::new("Onion address detected — the password comes next.").dim(),
                    extra,
                ),
                (None, Ok(Pasted::Code { .. })) => f.render_widget(
                    Paragraph::new(
                        "Sender code detected — you will get a response code to give back.",
                    )
                    .dim(),
                    extra,
                ),
                (None, Err(rejection)) if rejection.while_typing() => {
                    widgets::error_line(f, extra, &rejection.message());
                }
                (None, Err(_)) => {}
            }
            // The web app keeps this under the response's advanced options,
            // where it rebuilds a connection that is already running. Here it
            // is asked before the transfer starts, which is the same choice a
            // keystroke earlier.
            if offered {
                f.render_widget(Paragraph::new(simulate_toggle_line(*simulate)), option);
                f.render_widget(
                    Paragraph::new(simulate_toggle_hint(*simulate)).dim(),
                    option_hint,
                );
            }
            widgets::key_hints(
                f,
                inner,
                if offered {
                    "Enter confirm · Tab simulate no direct · Esc back"
                } else {
                    "Enter confirm · ←/→ move · Esc back"
                },
            );
        }

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

    const ONION: &str = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";

    /// Every mode on the menu starts a transfer; none is a placeholder kept
    /// only to align the numbering with the web app's any more.
    #[test]
    fn every_mode_starts_a_selection() {
        for mode in 0..MODES.len() {
            let step = mode_menu_key(mode, false, press(KeyCode::Enter));
            let Step::Continue(Screen::FileBrowser { mode: chosen, .. }) = step else {
                panic!("mode {mode} should open the file browser");
            };
            // The mode has to survive the shared browser to pick the right plan.
            assert_eq!(chosen, mode);
        }
    }

    #[test]
    fn moving_the_selection_keeps_the_option() {
        let Step::Continue(Screen::ModeMenu {
            selected,
            anonymous,
        }) = mode_menu_key(1, true, press(KeyCode::Up))
        else {
            panic!("expected the mode menu");
        };
        assert_eq!(selected, 0);
        assert!(anonymous);
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

    /// A sender code as the sending side would hand it over, with the
    /// anonymous option `anonymous` says.
    fn sender_code(anonymous: bool) -> String {
        use crate::code::payload::{
            CODE_SALT_LEN, PUBLIC_KEY_LEN, PayloadKind, SignalingPayload, encode, now_ms,
            to_clipboard,
        };
        let offer = SignalingPayload {
            kind: PayloadKind::Offer,
            sdp: "v=0\r\n".to_string(),
            candidates: vec![],
            created_at: now_ms(),
            public_key: vec![4u8; PUBLIC_KEY_LEN],
            confirm: None,
            file_name: Some("report.pdf".to_string()),
            file_size: Some(1024),
            content_encoding: Some(crate::wire::WireEncoding::DeflateRaw),
            mime_type: Some("application/pdf".to_string()),
            salt: Some(vec![7u8; CODE_SALT_LEN]),
            relays: None,
            anon: anonymous.then_some(true),
        };
        to_clipboard(&encode(&offer).unwrap())
    }

    /// The receiving side is not asked which mode a code is either, and the
    /// one thing read out of it before the transfer starts is whether the
    /// sender left it a fallback.
    #[test]
    fn a_pasted_sender_code_is_recognized_with_its_fallback() {
        let anonymous = sender_code(true);
        assert_eq!(
            classify(&anonymous),
            Ok(Pasted::Code {
                offer: anonymous,
                fallback: true,
            })
        );

        let plain = sender_code(false);
        let Ok(Pasted::Code { offer, fallback }) = classify(&format!("  {plain}\n")) else {
            panic!("a sender code should be recognized");
        };
        assert_eq!(offer, plain, "the code is kept exactly as it was pasted");
        assert!(!fallback, "this sender turned the anonymous option off");
    }

    /// The receiver's half of the simulated dead route, which the web app has
    /// under the response's advanced options: it exists to exercise the
    /// sender's fallback from a network where a direct route would work.
    #[test]
    fn the_simulated_dead_route_is_offered_only_where_there_is_a_fallback() {
        let code = sender_code(true);
        let toggle = press(SIMULATE_KEY);

        let Step::Continue(Screen::ReceiveEntry { simulate, .. }) = receive_entry_key(
            PathBuf::from("."),
            code.clone(),
            code.len(),
            None,
            false,
            toggle,
        ) else {
            panic!("the toggle should stay on the receive screen");
        };
        assert!(simulate, "Tab should arm the simulation");

        let Step::Finish(WizardPlan::ReceiveCode {
            simulate_no_direct, ..
        }) = receive_entry_key(
            PathBuf::from("."),
            code.clone(),
            code.len(),
            None,
            true,
            press(KeyCode::Enter),
        )
        else {
            panic!("a sender code should finish the wizard");
        };
        assert!(simulate_no_direct, "the choice has to reach the transfer");

        // And back off again.
        let Step::Continue(Screen::ReceiveEntry { simulate, .. }) =
            receive_entry_key(PathBuf::from("."), code.clone(), code.len(), None, true, toggle)
        else {
            panic!("the toggle should stay on the receive screen");
        };
        assert!(!simulate);
    }

    /// Armed on one code and then handed another that has nothing to fall back
    /// onto, the flag cannot reach the transfer: it would only be refused
    /// there, and this screen is where the difference is visible.
    #[test]
    fn a_code_without_a_fallback_never_carries_the_simulation() {
        let plain = sender_code(false);

        // The key is not a toggle here, so it changes nothing.
        let Step::Continue(Screen::ReceiveEntry { simulate, .. }) = receive_entry_key(
            PathBuf::from("."),
            plain.clone(),
            plain.len(),
            None,
            false,
            press(SIMULATE_KEY),
        ) else {
            panic!("expected the receive entry screen");
        };
        assert!(!simulate);

        let Step::Finish(WizardPlan::ReceiveCode {
            simulate_no_direct, ..
        }) = receive_entry_key(
            PathBuf::from("."),
            plain.clone(),
            plain.len(),
            None,
            true,
            press(KeyCode::Enter),
        )
        else {
            panic!("a sender code should finish the wizard");
        };
        assert!(!simulate_no_direct);
    }

    /// An option nobody can see is not one, and this is the only thing on the
    /// receiving side that is not settled by what was pasted.
    #[test]
    fn the_receive_box_shows_the_toggle_only_where_it_applies() {
        for (code, shown) in [(sender_code(true), true), (sender_code(false), false)] {
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(90, 20)).unwrap();
            let mut screen = Screen::ReceiveEntry {
                output: PathBuf::from("."),
                cursor: code.len(),
                input: code,
                error: None,
                simulate: false,
            };
            terminal.draw(|f| draw(f, &mut screen)).unwrap();
            let rendered: String = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert_eq!(
                rendered.contains("Simulate no direct connection"),
                shown,
                "the toggle should{} be on screen",
                if shown { "" } else { " not" }
            );
        }
    }

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
            false,
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
            false,
            press(KeyCode::Enter),
        ) else {
            panic!("expected the receive entry screen");
        };
        assert_eq!(error, Some(Rejection::Unrecognized.message()));
    }

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
            false,
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
            simulate: false,
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
            simulate: false,
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
