//! Live TUI view for Nostr-mode transfers: renders the status log, PIN panel,
//! progress gauge, and the file-exists modal while the transfer task runs.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use futures_util::StreamExt;
use ratatui::DefaultTerminal;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Gauge, Paragraph, Wrap};
use tokio::sync::{mpsc, oneshot};

use crate::crypto::base32::{CONFIRMATION_CODE_LENGTH, normalize_crockford_base32};
use crate::crypto::pin::{PIN_ROTATION_MS, PIN_WAIT_TIMEOUT_MS};
use crate::ui::{Direction, FileExistsChoice, UiEvent};
use crate::util::{OnConflict, calc_percent, format_bytes};
use crate::tor;
use crate::{archive, code, ui, webrtc};

use super::app::WizardPlan;
use super::is_ctrl_c;
use super::widgets;

const STATUS_LOG_CAPACITY: usize = 200;

/// How many status lines the code overlay shows beneath the code. Enough for a
/// step and the two before it, which is what the fallback's wait looks like.
const STATUS_BESIDE_CODE: usize = 3;

/// Drive a Nostr-mode plan to completion inside the TUI. Returns the
/// transfer's result once the user has acknowledged the final screen.
pub async fn run(terminal: &mut DefaultTerminal, plan: WizardPlan) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    ui::install_tui_sink(tx);

    let mut state = State::new(&plan);
    let mut task = tokio::spawn(run_plan(plan));
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    loop {
        terminal.draw(|f| state.render(f))?;
        tokio::select! {
            Some(event) = rx.recv() => state.apply(event),

            maybe_event = events.next() => {
                let event = maybe_event.ok_or_else(|| anyhow!("input stream closed"))??;
                if let Event::Paste(text) = event {
                    // Two prompts take a paste, and only one is ever open.
                    state.paste_response_code(&text);
                    state.paste_confirmation_code(&text);
                    continue;
                }
                let Event::Key(key) = event else { continue };
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if is_ctrl_c(&key) {
                    task.abort();
                    return Err(anyhow!("Interrupted"));
                }
                if state.modal.is_some() {
                    let choice = match key.code {
                        KeyCode::Char('o') => Some(FileExistsChoice::Overwrite),
                        KeyCode::Char('r') => Some(FileExistsChoice::Rename),
                        KeyCode::Char('c') | KeyCode::Esc => Some(FileExistsChoice::Cancel),
                        _ => None,
                    };
                    if let Some(choice) = choice
                        && let Some((_, reply)) = state.modal.take()
                    {
                        let _ = reply.send(choice);
                    }
                } else if state.confirmation_prompt.is_some() {
                    state.confirmation_code_key(key.code);
                } else if state.code.is_some() {
                    state.code_key(key.code);
                } else if state.outcome.is_some() {
                    // Any key on the final screen exits with the transfer's result.
                    return state.outcome.take().expect("checked above");
                } else if key.code == KeyCode::Char('r') && state.pin.is_some() {
                    // Mint and publish a fresh PIN, invalidating every
                    // previously shown one (e.g. it was exposed to a bystander).
                    ui::request_pin_refresh();
                }
            }

            join = &mut task, if state.outcome.is_none() => {
                // Apply any status updates the task queued before finishing so
                // the final log reflects them before "press any key to exit".
                while let Ok(event) = rx.try_recv() {
                    state.apply(event);
                }
                let outcome = match join {
                    Ok(result) => result,
                    Err(e) if e.is_cancelled() => Err(anyhow!("Interrupted")),
                    Err(e) => Err(anyhow!("Transfer task failed: {e}")),
                };
                state.finish(outcome);
            }

            _ = tick.tick() => {}
        }
    }
}

async fn run_plan(plan: WizardPlan) -> Result<()> {
    match plan {
        WizardPlan::SendPin { paths, pin_kind } => {
            let source =
                tokio::task::spawn_blocking(move || archive::prepare_send_source(&paths)).await??;
            webrtc::send_file_nostr(&source, pin_kind).await
        }
        WizardPlan::ReceivePin { pin, output } => {
            webrtc::receive_file_nostr(&pin, Some(output), OnConflict::Prompt).await
        }
        WizardPlan::SendCode { paths, anonymous } => {
            let source =
                tokio::task::spawn_blocking(move || archive::prepare_send_source(&paths)).await??;
            code::send_file_code(&source, anonymous).await
        }
        WizardPlan::ReceiveCode {
            offer,
            output,
            simulate_no_direct,
        } => {
            code::receive_file_code(&offer, Some(output), OnConflict::Prompt, simulate_no_direct)
                .await
        }
        WizardPlan::SendTor(paths) => tor::transfer::send(paths, tor::DEFAULT_PORT).await,
        WizardPlan::ReceiveTor {
            address,
            password,
            output,
        } => {
            tor::transfer::receive(
                &address,
                tor::DEFAULT_PORT,
                &password,
                Some(output),
                OnConflict::Prompt,
            )
            .await
        }
    }
}

struct State {
    title: &'static str,
    outgoing: Option<String>,
    pin: Option<String>,
    /// When the displayed PIN was minted; restarts the rotation countdown on
    /// every [`UiEvent::ShowPin`].
    pin_shown_at: Option<Instant>,
    /// When the first PIN appeared: start of the overall wait window, stable
    /// across rotations.
    wait_started_at: Option<Instant>,
    incoming: Option<String>,
    /// Sender-side onion address and password, while the Tor transport waits.
    tor: Option<TorRendezvous>,
    /// Receiver-side code to read to the sender.
    confirmation_code: Option<String>,
    /// Sender-side text entry while the transfer task waits for an attempt.
    confirmation_prompt: Option<ConfirmationPrompt>,
    /// A Code Exchange code this side is showing for the operator to carry.
    code: Option<ShownCode>,
    /// Sender-side wait for the response code the receiver is showing.
    response_prompt: Option<ResponsePrompt>,
    /// The status lines, each with the id of the step that wrote it — a
    /// step revises its own row, whoever else has written since.
    status_log: Vec<StatusRow>,
    progress: Option<(Direction, u64, u64)>,
    modal: Option<(PathBuf, oneshot::Sender<FileExistsChoice>)>,
    outcome: Option<Result<()>>,
}

/// One line of the status log. `id` is the step that wrote it, when a step
/// did; lines the screen writes for itself have none and are never rewritten.
struct StatusRow {
    id: Option<u64>,
    line: String,
}

struct ConfirmationPrompt {
    input: String,
    reply: oneshot::Sender<String>,
}

/// The code on screen, with the line that says what to do with it.
struct ShownCode {
    label: String,
    code: String,
    /// Whether the terminal accepted an OSC 52 clipboard write. It says the
    /// sequence was sent, not that the terminal acted on it — which is why the
    /// code stays on screen either way.
    copied: bool,
    /// First visible row of the wrapped code.
    scroll: usize,
    /// Rows the last frame could show and how many there were, so paging can
    /// stop at the end instead of scrolling into blank space.
    page: usize,
    rows: usize,
    /// Where the code was written for an operator who can use neither the
    /// clipboard nor a mouse selection, and `None` until they ask for it.
    saved: Option<PathBuf>,
    /// Set when that write failed, so the offer to make it is withdrawn
    /// instead of silently doing nothing.
    save_failed: bool,
}

/// The saved copy is the code, and the code is this transfer's whole secret,
/// so it lives exactly as long as the code is on screen. A killed process can
/// still leave one behind, the same way an interrupted receiver leaves a
/// `.part` file behind.
impl Drop for ShownCode {
    fn drop(&mut self) {
        if let Some(path) = &self.saved {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl ShownCode {
    /// The code split into rows of `width`, which is the drawing area's own
    /// width. Base64 is ASCII, so a byte chunk is a character chunk.
    fn rows(&self, width: usize) -> Vec<String> {
        self.code
            .as_bytes()
            .chunks(width.max(1))
            .map(|row| String::from_utf8_lossy(row).into_owned())
            .collect()
    }

    fn max_scroll(&self) -> usize {
        self.rows.saturating_sub(self.page)
    }
}

/// The response the sender is waiting for. Kilobytes of base64, so it is
/// pasted rather than typed and the field shows a character count instead of
/// the value.
struct ResponsePrompt {
    input: String,
    reply: oneshot::Sender<String>,
}

/// Ask the terminal to put `text` on the system clipboard (OSC 52).
///
/// A Code Exchange code is a kilobyte of base64 that has to reach the other
/// device, and a TUI cannot reach the clipboard any other way. Terminals that
/// do not implement OSC 52 — or have it turned off, as tmux does by default —
/// ignore the sequence silently, which is why the code is also drawn on screen
/// for selecting by hand.
fn copy_to_clipboard(text: &str) -> bool {
    use base64::Engine as _;
    use std::io::Write as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let mut stdout = std::io::stdout();
    write!(stdout, "\x1b]52;c;{encoded}\x07")
        .and_then(|()| stdout.flush())
        .is_ok()
}

/// Write `text` where the operator can read it with another tool, and say
/// where that is.
///
/// A terminal selection is the fallback for a terminal that ignores OSC 52,
/// and it only reaches what is on screen: a code is a couple of kilobytes, so
/// on an ordinary terminal it is several screens tall and no single selection
/// can take all of it. A file is the only carrier left. It is created private
/// to this user and removed when the code leaves the screen, because it holds
/// the same secret the code does.
fn save_code(text: &str) -> Result<PathBuf> {
    use std::io::Write as _;

    let path = std::env::temp_dir().join(format!("ptransfer-code-{}.txt", std::process::id()));
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    // A trailing newline, because everything that will read this file back —
    // `cat`, an editor, a mail client — expects one.
    writeln!(file, "{text}")?;
    file.flush()?;
    Ok(path)
}

/// What the Tor sender is showing its operator to hand over.
struct TorRendezvous {
    address: String,
    password: String,
    /// Until the descriptor is up, the address is not reachable yet.
    published: bool,
}

impl State {
    fn new(plan: &WizardPlan) -> Self {
        let title = match plan {
            WizardPlan::SendPin { .. } => "sending",
            WizardPlan::ReceivePin { .. } => "receiving",
            WizardPlan::SendCode { .. } => "sending",
            WizardPlan::ReceiveCode { .. } => "receiving",
            WizardPlan::SendTor(_) => "sending over Tor",
            WizardPlan::ReceiveTor { .. } => "receiving over Tor",
        };
        Self {
            title,
            outgoing: None,
            pin: None,
            pin_shown_at: None,
            wait_started_at: None,
            incoming: None,
            tor: None,
            confirmation_code: None,
            confirmation_prompt: None,
            code: None,
            response_prompt: None,
            status_log: Vec::new(),
            progress: None,
            modal: None,
            outcome: None,
        }
    }

    fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::Status { id, line } => self.push_status(Some(id), line),
            UiEvent::StatusReplace { id, line } => {
                // "Doing X..." became "Did X (elapsed)": rewrite that step's
                // own row. Steps overlap — the Tor bootstrap reports from
                // behind whatever the foreground is doing — so the row is
                // found by id and not by being the last one written.
                match self
                    .status_log
                    .iter_mut()
                    .find(|row| row.id == Some(id))
                {
                    Some(row) => row.line = line,
                    // Scrolled out of the log's capacity, which is the one way
                    // a step's row can be gone before it finishes.
                    None => self.push_status(Some(id), line),
                }
            }
            UiEvent::Progress { dir, bytes, total } => self.progress = Some((dir, bytes, total)),
            UiEvent::ProgressEnd => {}
            UiEvent::ShowPin {
                file_name,
                size,
                pin,
            } => {
                self.outgoing = Some(format!("{file_name} ({})", format_bytes(size)));
                self.pin = Some(pin);
                self.pin_shown_at = Some(Instant::now());
                self.wait_started_at.get_or_insert_with(Instant::now);
            }
            UiEvent::HidePin => {
                self.pin = None;
                self.pin_shown_at = None;
                self.wait_started_at = None;
            }
            UiEvent::ShowTorAddress {
                file_name,
                size,
                address,
                password,
            } => {
                self.outgoing = Some(format!("{file_name} ({})", format_bytes(size)));
                self.tor = Some(TorRendezvous {
                    address,
                    password,
                    published: false,
                });
            }
            UiEvent::TorPublished => {
                if let Some(tor) = &mut self.tor {
                    tor.published = true;
                }
            }
            UiEvent::ShowConfirmationCode(code) => self.confirmation_code = Some(code),
            UiEvent::HideConfirmationCode => self.confirmation_code = None,
            UiEvent::ConfirmationCodeInput { reply } => {
                self.confirmation_prompt = Some(ConfirmationPrompt {
                    input: String::new(),
                    reply,
                });
            }
            UiEvent::ShowCode { label, code } => {
                let copied = copy_to_clipboard(&code);
                self.code = Some(ShownCode {
                    label,
                    code,
                    copied,
                    scroll: 0,
                    page: 1,
                    rows: 1,
                    saved: None,
                    save_failed: false,
                });
            }
            UiEvent::HideCode => self.code = None,
            UiEvent::ResponseCodeInput { reply } => {
                self.response_prompt = Some(ResponsePrompt {
                    input: String::new(),
                    reply,
                });
            }
            UiEvent::Incoming { file_name, size } => {
                self.incoming = Some(format!("{file_name} ({})", format_bytes(size)));
            }
            UiEvent::FileExists { path, reply } => self.modal = Some((path, reply)),
        }
    }

    fn push_status(&mut self, id: Option<u64>, line: String) {
        if self.status_log.len() == STATUS_LOG_CAPACITY {
            self.status_log.remove(0);
        }
        self.status_log.push(StatusRow { id, line });
    }

    /// The last `count` status lines, oldest first — what the code overlay
    /// shows beside a code, since it covers the log while it is up.
    fn recent_status(&self, count: usize) -> impl Iterator<Item = &str> {
        self.status_log[self.status_log.len().saturating_sub(count)..]
            .iter()
            .map(|row| row.line.as_str())
    }

    fn confirmation_code_key(&mut self, key: KeyCode) {
        let Some(prompt) = self.confirmation_prompt.as_mut() else {
            return;
        };

        match key {
            KeyCode::Enter if prompt.input.len() == CONFIRMATION_CODE_LENGTH => {
                let prompt = self
                    .confirmation_prompt
                    .take()
                    .expect("confirmation prompt checked above");
                let _ = prompt.reply.send(prompt.input);
            }
            KeyCode::Backspace => {
                prompt.input.pop();
            }
            KeyCode::Char(character) if prompt.input.len() < CONFIRMATION_CODE_LENGTH => {
                let normalized = normalize_crockford_base32(&character.to_string());
                if let Some(character) = normalized.chars().next() {
                    prompt.input.push(character);
                }
            }
            _ => {}
        }
    }

    /// Keys while a code is on screen: page through it, copy it again, and —
    /// on the sending side — submit the response that was pasted over it.
    fn code_key(&mut self, key: KeyCode) {
        let Some(code) = self.code.as_mut() else {
            return;
        };
        match key {
            KeyCode::Up => code.scroll = code.scroll.saturating_sub(1),
            KeyCode::Down => code.scroll = (code.scroll + 1).min(code.max_scroll()),
            KeyCode::PageUp => code.scroll = code.scroll.saturating_sub(code.page),
            KeyCode::PageDown => {
                code.scroll = (code.scroll + code.page).min(code.max_scroll());
            }
            // Terminals that ignore OSC 52 the first time will ignore it
            // again, but a tmux or terminal setting changed in between is
            // exactly the case worth a second try.
            KeyCode::Char('c') => {
                let copied = copy_to_clipboard(&code.code);
                code.copied = copied;
            }
            // The way out of a terminal that has neither a working OSC 52 nor
            // a screen tall enough to select the whole code from.
            KeyCode::Char('s') => match save_code(&code.code) {
                Ok(path) => {
                    // The previous copy, if any, is this same path rewritten.
                    code.saved = Some(path);
                    code.save_failed = false;
                }
                Err(error) => {
                    log::warn!("the code could not be saved to a file: {error:#}");
                    code.save_failed = true;
                }
            },
            KeyCode::Enter | KeyCode::Backspace => self.response_code_key(key),
            _ => {}
        }
    }

    fn response_code_key(&mut self, key: KeyCode) {
        let Some(prompt) = self.response_prompt.as_mut() else {
            return;
        };
        match key {
            // A response is a couple of kilobytes of base64, so an empty field
            // means nothing was pasted yet rather than an empty answer.
            KeyCode::Enter if !prompt.input.is_empty() => {
                let prompt = self
                    .response_prompt
                    .take()
                    .expect("response prompt checked above");
                let _ = prompt.reply.send(prompt.input);
            }
            // One key clears a mis-paste; there is nothing here to edit
            // character by character.
            KeyCode::Backspace => prompt.input.clear(),
            _ => {}
        }
    }

    fn paste_response_code(&mut self, pasted: &str) {
        let Some(prompt) = self.response_prompt.as_mut() else {
            return;
        };
        // Whole-field replacement: a paste is a fresh value, not an insertion,
        // and the sender's own paste is what admits a receiver at all.
        prompt.input = pasted.trim().to_string();
    }

    fn paste_confirmation_code(&mut self, pasted: &str) {
        let Some(prompt) = self.confirmation_prompt.as_mut() else {
            return;
        };
        prompt.input = normalize_crockford_base32(pasted)
            .chars()
            .take(CONFIRMATION_CODE_LENGTH)
            .collect();
    }

    fn finish(&mut self, outcome: Result<()>) {
        self.confirmation_prompt = None;
        self.confirmation_code = None;
        self.response_prompt = None;
        self.code = None;
        let line = match &outcome {
            Ok(()) => "Done — press any key to exit".to_string(),
            Err(e) => format!("Failed: {e:#} — press any key to exit"),
        };
        self.push_status(None, line);
        self.outcome = Some(outcome);
    }

    fn render(&mut self, f: &mut Frame) {
        let inner = widgets::screen_frame(f, self.title);
        let [panel_area, log_area, gauge_area, hint_area] = Layout::vertical([
            Constraint::Length(self.panel_height()),
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(inner);

        self.render_panel(f, panel_area);
        self.render_log(f, log_area);
        self.render_gauge(f, gauge_area);

        let hint = if self.outcome.is_some() {
            "press any key to exit"
        } else if self.modal.is_some() {
            "o overwrite · r rename · c cancel"
        } else if self.confirmation_prompt.is_some() {
            "type the code · Enter submit · Ctrl-C abort"
        } else if self.code.is_some() {
            if self.response_prompt.is_some() {
                "paste the response · Enter send · c copy · s save · ↑/↓ scroll · Ctrl-C abort"
            } else {
                "c copy · s save · ↑/↓ scroll · Ctrl-C abort"
            }
        } else if self.pin.is_some() {
            "r new PIN · Ctrl-C abort"
        } else {
            "Ctrl-C abort"
        };
        f.render_widget(Paragraph::new(hint).dim(), hint_area);

        if let Some((path, _)) = &self.modal {
            let path = path.clone();
            self.render_modal(f, inner, &path);
        } else if let Some(prompt) = &self.confirmation_prompt {
            let input = prompt.input.clone();
            self.render_confirmation_prompt(f, inner, &input);
        } else if self.code.is_some() {
            self.render_code(f, inner);
        }
    }

    /// The code overlay: the whole screen, because a code that cannot be read
    /// off it in full is a transfer that cannot happen.
    ///
    /// It stays up for as long as the code is live — on the sending side that
    /// is while the response is being pasted over it, which is why the paste
    /// state is reported down here rather than in a second box.
    fn render_code(&mut self, f: &mut Frame, inner: Rect) {
        let pasted = self.response_prompt.as_ref().map(|prompt| prompt.input.len());
        // The overlay covers the log, and what is happening behind it is the
        // other half of what someone holding a code needs to know — a Tor
        // client still bootstrapping, a sender not there yet. The web app puts
        // the same lines beside the response for the same reason.
        let status: Vec<String> = self
            .recent_status(STATUS_BESIDE_CODE)
            .map(str::to_string)
            .collect();
        let Some(code) = self.code.as_mut() else {
            return;
        };
        f.render_widget(Clear, inner);
        // A title rule rather than a box, for the reason
        // [`widgets::screen_frame`] gives: terminal mouse selection is
        // column-based, so a left border would be dragged into every row of
        // the code — and the code is the one string on this screen that has to
        // survive a copy byte for byte. Nothing is drawn to either side of it.
        let block = Block::default().borders(Borders::TOP).title(" Code ");
        let body = block.inner(inner);
        f.render_widget(block, inner);

        let [label_area, code_area, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            // The status excerpt, then the copy line, the scroll line and the
            // paste prompt.
            Constraint::Length(STATUS_BESIDE_CODE as u16 + 3),
        ])
        .areas(body);

        let rows = code.rows(code_area.width as usize);
        // Recorded for the key handler, which has no view of the geometry.
        code.page = code_area.height.max(1) as usize;
        code.rows = rows.len();
        code.scroll = code.scroll.min(code.max_scroll());

        f.render_widget(Paragraph::new(code.label.clone()).bold(), label_area);
        let visible: Vec<Line> = rows
            .iter()
            .skip(code.scroll)
            .take(code.page)
            .map(|row| Line::from(row.as_str()).green())
            .collect();
        f.render_widget(Paragraph::new(visible), code_area);

        let mut lines: Vec<Line> = status
            .iter()
            .map(|line| Line::from(line.as_str()).dim())
            .collect();
        // A selection reaches only what is drawn, so once the code is taller
        // than the screen the hand-copy fallback is a file rather than the
        // mouse — and saying "select it above" there would be advice that
        // cannot work.
        let selectable = code.rows <= code.page;
        let carrier: Line = match (&code.saved, code.save_failed, code.copied) {
            (Some(path), _, _) => format!(
                "Saved to {} — copy it from there; c retries the clipboard.",
                path.display()
            )
            .dim()
            .into(),
            (None, true, _) => "The code could not be saved to a file; c retries the clipboard."
                .dim()
                .into(),
            (None, false, true) if selectable => {
                "Sent to your clipboard (c to copy again) — or select it above."
                    .dim()
                    .into()
            }
            (None, false, true) => "Sent to your clipboard (c to copy again) — or s to save it."
                .dim()
                .into(),
            (None, false, false) if selectable => {
                "Select it above to copy; your terminal refused the clipboard."
                    .dim()
                    .into()
            }
            (None, false, false) => {
                "Too long to select in one go — s saves it to a file, c retries the clipboard."
                    .dim()
                    .into()
            }
        };
        lines.push(carrier);
        if code.rows > code.page {
            lines.push(
                format!(
                    "Showing lines {}-{} of {} — ↑/↓ or PgUp/PgDn to scroll.",
                    code.scroll + 1,
                    (code.scroll + code.page).min(code.rows),
                    code.rows
                )
                .dim()
                .into(),
            );
        }
        if let Some(pasted) = pasted {
            lines.push(if pasted == 0 {
                "Paste the receiver's response here when you have it."
                    .yellow()
                    .into()
            } else {
                format!("{pasted} characters pasted — Enter to send, Backspace to clear")
                    .yellow()
                    .into()
            });
        }
        f.render_widget(Paragraph::new(lines), footer);
    }

    fn panel_height(&self) -> u16 {
        let mut height = 0;
        if self.outgoing.is_some() {
            height += 1;
        }
        if self.pin.is_some() {
            // Label, PIN, rotation countdown, wait backstop.
            height += 4;
        }
        if self.tor.is_some() {
            // Label, address, password, publish state.
            height += 4;
        }
        if self.incoming.is_some() {
            height += 1;
        }
        if self.confirmation_code.is_some() {
            height += 3;
        }
        if height > 0 { height + 1 } else { 0 }
    }

    fn render_panel(&self, f: &mut Frame, area: Rect) {
        let mut lines: Vec<Line> = Vec::new();
        if let Some(outgoing) = &self.outgoing {
            lines.push(format!("Sending: {outgoing}").bold().into());
        }
        if let Some(pin) = &self.pin {
            lines.push("Enter this PIN on the receiving side:".bold().into());
            // Prominent color: the PIN is the one thing to read off this
            // screen (the web PIN box is highlighted green too).
            lines.push(pin.clone().green().bold().into());
            lines.push(self.rotation_line());
            lines.push(self.wait_backstop_line());
        }
        if let Some(tor) = &self.tor {
            lines.push("Give the receiver this address and password:".bold().into());
            // The two things to read off this screen, in the same prominent
            // color the PIN gets.
            lines.push(tor.address.clone().green().bold().into());
            lines.push(tor.password.clone().green().bold().into());
            lines.push(if tor.published {
                "Published — the address is reachable now.".dim().into()
            } else {
                "Publishing the onion descriptor; this can take a minute..."
                    .dim()
                    .into()
            });
        }
        if let Some(incoming) = &self.incoming {
            lines.push(format!("Incoming file: {incoming}").bold().into());
        }
        if let Some(code) = &self.confirmation_code {
            lines.push("Read this confirmation code to the sender:".bold().into());
            lines.push(code.clone().green().bold().into());
            lines.push("The sender must enter it before anything is sent.".dim().into());
        }
        if !lines.is_empty() {
            f.render_widget(Paragraph::new(lines), area);
        }
    }

    /// Depleting bar plus `New PIN in m:ss`: time until rotation replaces the
    /// displayed PIN with a fresh one.
    fn rotation_line(&self) -> Line<'static> {
        const BAR_WIDTH: usize = 22;
        let rotation = Duration::from_millis(PIN_ROTATION_MS);
        let remaining = self
            .pin_shown_at
            .map(|shown| rotation.saturating_sub(shown.elapsed()))
            .unwrap_or(rotation);
        let filled = ((remaining.as_secs_f64() / rotation.as_secs_f64()) * BAR_WIDTH as f64).round()
            as usize;
        let secs = remaining.as_secs();
        Line::from(vec![
            "█".repeat(filled.min(BAR_WIDTH)).yellow(),
            "░".repeat(BAR_WIDTH.saturating_sub(filled)).dim(),
            format!("  New PIN in {}:{:02}", secs / 60, secs % 60).into(),
            " (r: new PIN now)".dim(),
        ])
    }

    /// Quiet resource backstop, not a security deadline: rotation already caps
    /// each PIN's life, so there is no urgency to surface here.
    fn wait_backstop_line(&self) -> Line<'static> {
        let timeout = Duration::from_millis(PIN_WAIT_TIMEOUT_MS);
        let remaining = self
            .wait_started_at
            .map(|start| timeout.saturating_sub(start.elapsed()))
            .unwrap_or(timeout);
        let when = if remaining.as_secs() >= 60 {
            format!("in about {} min", remaining.as_secs().div_ceil(60))
        } else {
            "in less than a minute".to_string()
        };
        format!("Waiting stops automatically {when} if no one connects.")
            .dim()
            .into()
    }

    /// History is dimmed; only the current (last) line renders at full
    /// intensity so the eye lands on what is happening now.
    fn render_log(&self, f: &mut Frame, area: Rect) {
        let visible = area.height as usize;
        let start = self.status_log.len().saturating_sub(visible);
        let tail = &self.status_log[start..];
        let lines: Vec<ratatui::text::Line> = tail
            .iter()
            .enumerate()
            .map(|(i, row)| {
                if i + 1 == tail.len() {
                    ratatui::text::Line::from(row.line.as_str())
                } else {
                    ratatui::text::Line::from(row.line.as_str()).dim()
                }
            })
            .collect();
        f.render_widget(Paragraph::new(lines), area);
    }

    fn render_gauge(&self, f: &mut Frame, area: Rect) {
        let Some((dir, bytes, total)) = self.progress else {
            return;
        };
        let verb = match dir {
            Direction::Send => "Sending",
            Direction::Receive => "Receiving",
        };
        let gauge = Gauge::default()
            .ratio(calc_percent(bytes, total) / 100.0)
            .label(format!(
                "{verb}: {}/{}",
                format_bytes(bytes),
                format_bytes(total)
            ));
        f.render_widget(gauge, area);
    }

    fn render_modal(&self, f: &mut Frame, inner: Rect, path: &std::path::Path) {
        let area = widgets::centered(inner, inner.width.saturating_sub(8).max(30), 5);
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" File exists ");
        let body = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new(format!(
                "{}\n\n(o)verwrite · (r)ename · (c)ancel",
                path.display()
            ))
            .wrap(Wrap { trim: false }),
            body,
        );
    }

    fn render_confirmation_prompt(&self, f: &mut Frame, inner: Rect, input: &str) {
        let area = widgets::centered(inner, 58, 7);
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Confirmation code ");
        let body = block.inner(area);
        f.render_widget(block, area);
        let padded = format!(
            "{}{}",
            input,
            "_".repeat(CONFIRMATION_CODE_LENGTH.saturating_sub(input.len()))
        );
        f.render_widget(
            Paragraph::new(format!(
                "Enter the code shown by the receiver:\n\n{padded}\n\nEnter submits when all 8 characters are present."
            )),
            body,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a step's completion used to rewrite whatever line happened
    /// to be last, so the Tor bootstrap finishing behind a Code Exchange
    /// receive erased the line saying what that receive was waiting for, and
    /// the log read as a sequence that never happened.
    #[tokio::test]
    async fn a_step_finishing_behind_another_rewrites_its_own_line() {
        let mut state = State::new(&WizardPlan::SendPin {
            paths: Vec::new(),
            pin_kind: crate::crypto::pin::PinKind::Standard,
        });
        state.apply(UiEvent::Status {
            id: 7,
            line: "Fetching the Tor directory...".to_string(),
        });
        state.apply(UiEvent::Status {
            id: 8,
            line: "Waiting for the sender to take the response in...".to_string(),
        });
        state.apply(UiEvent::StatusReplace {
            id: 7,
            line: "Fetched the Tor directory (36.5 s)".to_string(),
        });

        let lines: Vec<&str> = state.recent_status(10).collect();
        assert_eq!(
            lines,
            [
                "Fetched the Tor directory (36.5 s)",
                "Waiting for the sender to take the response in...",
            ]
        );

        // A step whose row has scrolled out of the log still reports; it has
        // nowhere to rewrite, so it says so on a line of its own.
        state.apply(UiEvent::StatusReplace {
            id: 99,
            line: "Published the onion descriptor (9.6 s)".to_string(),
        });
        assert_eq!(
            state.recent_status(1).next(),
            Some("Published the onion descriptor (9.6 s)")
        );
    }

    /// Regression: the code overlay used to be a full box, so dragging the
    /// mouse over the code — the fallback for terminals that ignore OSC 52 —
    /// copied a border glyph at the start and end of every line, and the
    /// pasted result was not a code at all.
    #[tokio::test]
    async fn nothing_is_drawn_beside_the_code_for_a_selection_to_pick_up() {
        let code = "A".repeat(600);
        let mut state = State::new(&WizardPlan::SendPin {
            paths: Vec::new(),
            pin_kind: crate::crypto::pin::PinKind::Standard,
        });
        // Set directly rather than through `ShowCode`, whose clipboard write
        // would put an OSC 52 sequence into the test run's own terminal.
        state.code = Some(ShownCode {
            label: "Give this code to the receiver:".to_string(),
            code: code.clone(),
            copied: false,
            scroll: 0,
            page: 1,
            rows: 1,
            saved: None,
            save_failed: false,
        });

        // What is happening behind the overlay belongs on it: the overlay
        // covers the log, and a code is held while a Tor client bootstraps.
        state.apply(UiEvent::Status {
            id: 1,
            line: "Waiting for the sender to publish its onion service...".to_string(),
        });

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| state.render(f)).unwrap();
        let buffer = terminal.backend().buffer().clone();

        let rows: Vec<String> = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();

        // Full-width rows of the code itself: they have to be the code and
        // nothing else, from the first column to the last.
        let full = "A".repeat(80);
        assert!(
            rows.iter().filter(|row| **row == full).count() >= 2,
            "the code should fill whole rows: {rows:#?}"
        );
        for row in &rows {
            assert!(
                !row.contains('\u{2502}'),
                "a vertical border would be dragged into a selection: {row:?}"
            );
        }
        assert!(
            rows.iter()
                .any(|row| row.contains("Waiting for the sender to publish")),
            "the overlay should carry what is happening behind it: {rows:#?}"
        );
    }

    /// A code taller than the screen cannot be taken in one mouse selection,
    /// which is the fallback for a terminal that ignores OSC 52. Telling the
    /// operator to select it would be advice that cannot work, so the overlay
    /// offers the file instead — and `s` writes exactly the code.
    #[tokio::test]
    async fn a_code_too_tall_to_select_is_offered_as_a_file() {
        let code = "A".repeat(2000);
        let mut state = State::new(&WizardPlan::SendPin {
            paths: Vec::new(),
            pin_kind: crate::crypto::pin::PinKind::Standard,
        });
        // Set directly for the same reason as above: no OSC 52 into the test
        // run's own terminal.
        state.code = Some(ShownCode {
            label: "Give this code to the receiver:".to_string(),
            code: code.clone(),
            copied: false,
            scroll: 0,
            page: 1,
            rows: 1,
            saved: None,
            save_failed: false,
        });

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        let rendered = |terminal: &mut ratatui::Terminal<ratatui::backend::TestBackend>,
                        state: &mut State| {
            terminal.draw(|f| state.render(f)).unwrap();
            let buffer = terminal.backend().buffer().clone();
            (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<String>>()
        };

        let rows = rendered(&mut terminal, &mut state);
        assert!(
            rows.iter().any(|row| row.contains("s saves it to a file")),
            "a code that does not fit should offer the file: {rows:#?}"
        );

        state.code_key(KeyCode::Char('s'));
        let path = state
            .code
            .as_ref()
            .and_then(|code| code.saved.clone())
            .expect("s should have saved the code");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            code,
            "the file has to hold the code byte for byte"
        );

        let rows = rendered(&mut terminal, &mut state);
        assert!(
            rows.iter()
                .any(|row| row.contains("Saved to") && row.contains("copy it from there")),
            "the overlay should say where the code went: {rows:#?}"
        );

        // The file holds the transfer's secret, so it goes when the code does.
        state.apply(UiEvent::HideCode);
        assert!(!path.exists(), "the saved code should not outlive the code");
    }

    #[tokio::test]
    async fn confirmation_prompt_normalizes_paste_before_submitting() {
        let mut state = State::new(&WizardPlan::SendPin {
            paths: Vec::new(),
            pin_kind: crate::crypto::pin::PinKind::Standard,
        });
        let (reply, received) = oneshot::channel();
        state.apply(UiEvent::ConfirmationCodeInput { reply });

        state.paste_confirmation_code("a4bc-d9zt");
        assert_eq!(
            state.confirmation_prompt.as_ref().unwrap().input,
            "A4BCD9ZT"
        );
        state.confirmation_code_key(KeyCode::Enter);

        assert_eq!(received.await.unwrap(), "A4BCD9ZT");
        assert!(state.confirmation_prompt.is_none());
    }
}
