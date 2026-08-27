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
#[cfg(feature = "tor")]
use crate::tor;
use crate::{archive, ui, webrtc};

use super::app::WizardPlan;
use super::is_ctrl_c;
use super::widgets;

const STATUS_LOG_CAPACITY: usize = 200;

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
        #[cfg(feature = "tor")]
        WizardPlan::SendTor(paths) => tor::transfer::send(paths, tor::DEFAULT_PORT).await,
        #[cfg(feature = "tor")]
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
    #[cfg(feature = "tor")]
    tor: Option<TorRendezvous>,
    /// Receiver-side code to read to the sender.
    confirmation_code: Option<String>,
    /// Sender-side text entry while the transfer task waits for an attempt.
    confirmation_prompt: Option<ConfirmationPrompt>,
    status_log: Vec<String>,
    progress: Option<(Direction, u64, u64)>,
    modal: Option<(PathBuf, oneshot::Sender<FileExistsChoice>)>,
    outcome: Option<Result<()>>,
}

struct ConfirmationPrompt {
    input: String,
    reply: oneshot::Sender<String>,
}

/// What the Tor sender is showing its operator to hand over.
#[cfg(feature = "tor")]
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
            #[cfg(feature = "tor")]
            WizardPlan::SendTor(_) => "sending over Tor",
            #[cfg(feature = "tor")]
            WizardPlan::ReceiveTor { .. } => "receiving over Tor",
        };
        Self {
            title,
            outgoing: None,
            pin: None,
            pin_shown_at: None,
            wait_started_at: None,
            incoming: None,
            #[cfg(feature = "tor")]
            tor: None,
            confirmation_code: None,
            confirmation_prompt: None,
            status_log: Vec::new(),
            progress: None,
            modal: None,
            outcome: None,
        }
    }

    fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::Status(line) => {
                if self.status_log.len() == STATUS_LOG_CAPACITY {
                    self.status_log.remove(0);
                }
                self.status_log.push(line);
            }
            UiEvent::StatusDone(line) => {
                // "Doing X..." became "Did X (elapsed)": replace, don't stack.
                match self.status_log.last_mut() {
                    Some(last) => *last = line,
                    None => self.status_log.push(line),
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
            #[cfg(feature = "tor")]
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
            #[cfg(feature = "tor")]
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
            UiEvent::Incoming { file_name, size } => {
                self.incoming = Some(format!("{file_name} ({})", format_bytes(size)));
            }
            UiEvent::FileExists { path, reply } => self.modal = Some((path, reply)),
        }
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
        let line = match &outcome {
            Ok(()) => "Done — press any key to exit".to_string(),
            Err(e) => format!("Failed: {e:#} — press any key to exit"),
        };
        self.status_log.push(line);
        self.outcome = Some(outcome);
    }

    fn render(&self, f: &mut Frame) {
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
        } else if self.pin.is_some() {
            "r new PIN · Ctrl-C abort"
        } else {
            "Ctrl-C abort"
        };
        f.render_widget(Paragraph::new(hint).dim(), hint_area);

        if let Some((path, _)) = &self.modal {
            self.render_modal(f, inner, path);
        } else if let Some(prompt) = &self.confirmation_prompt {
            self.render_confirmation_prompt(f, inner, &prompt.input);
        }
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
        #[cfg(feature = "tor")]
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
        #[cfg(feature = "tor")]
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
            .map(|(i, line)| {
                if i + 1 == tail.len() {
                    ratatui::text::Line::from(line.as_str())
                } else {
                    ratatui::text::Line::from(line.as_str()).dim()
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
