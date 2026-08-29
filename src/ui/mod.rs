//! Terminal output and interactive prompts for the CLI.
//!
//! Every transfer flow reports through the free functions here. By default
//! they print plain text: status/progress to stderr, and the base64 signaling
//! codes the user must copy to stdout so they can be piped or redirected
//! cleanly. When the TUI wizard runs a Nostr transfer it installs an event
//! sink first ([`install_tui_sink`]); the same functions then emit
//! [`UiEvent`]s for the TUI to render instead of printing. The sink is
//! installed at most once per process — the wizard performs a single transfer
//! and exits.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::util::{calc_percent, format_bytes};

/// Direction of a transfer, used to label progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Send,
    Receive,
}

/// User's choice when a destination file already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileExistsChoice {
    Overwrite,
    Rename,
    Cancel,
}

/// What a transfer flow reports while running, for the TUI to render.
#[derive(Debug)]
pub enum UiEvent {
    Status {
        /// Identifies the line, so a later revision can find it again.
        id: u64,
        line: String,
    },
    /// The finished form of the [`UiEvent::Status`] line with this `id`
    /// ("Doing X..." → "Did X (elapsed)"). The TUI rewrites that line instead
    /// of appending, so a step costs one row however long it took.
    ///
    /// Keyed by id rather than "the last line", because steps overlap: the Tor
    /// bootstrap reports from a background task while the foreground is
    /// reporting its own, and the two would otherwise overwrite each other's
    /// rows and leave a log nobody can read a sequence out of.
    StatusReplace {
        id: u64,
        line: String,
    },
    Progress {
        dir: Direction,
        bytes: u64,
        total: u64,
    },
    ProgressEnd,
    ShowPin {
        file_name: String,
        size: u64,
        pin: String,
    },
    /// The PIN is no longer valid (a receiver claimed the transfer); stop
    /// displaying it.
    HidePin,
    /// The Tor sender's onion address and password, which the receiver needs
    /// both of.
    ShowTorAddress {
        file_name: String,
        size: u64,
        address: String,
        password: String,
    },
    /// The onion descriptor is published, so the address is now reachable.
    TorPublished,
    /// A Code Exchange code the operator has to carry to the other device:
    /// the sender's offer, or the receiver's response.
    ShowCode {
        label: String,
        code: String,
    },
    /// The code has been acted on and is no longer worth showing.
    HideCode,
    /// Sender-side request for the response the receiver is showing.
    ResponseCodeInput {
        reply: oneshot::Sender<String>,
    },
    /// Receiver-side code the user must read to the sender.
    ShowConfirmationCode(String),
    HideConfirmationCode,
    /// Sender-side request for the code being shown by the receiver.
    ConfirmationCodeInput {
        reply: oneshot::Sender<String>,
    },
    Incoming {
        file_name: String,
        size: u64,
    },
    FileExists {
        path: PathBuf,
        reply: oneshot::Sender<FileExistsChoice>,
    },
}

static TUI_SINK: OnceLock<mpsc::UnboundedSender<UiEvent>> = OnceLock::new();

/// On-demand PIN refresh requests (TUI `r` key → Nostr sender). A
/// [`Notify`] with `notify_one` semantics: a request made moments before the
/// sender awaits is stored as a permit, not lost.
static PIN_REFRESH: OnceLock<Arc<Notify>> = OnceLock::new();

/// The shared PIN-refresh signal. The Nostr sender awaits it while waiting
/// for a receiver; [`request_pin_refresh`] fires it.
pub fn pin_refresh_signal() -> Arc<Notify> {
    PIN_REFRESH.get_or_init(|| Arc::new(Notify::new())).clone()
}

/// Ask the running Nostr sender to mint and publish a fresh PIN immediately,
/// invalidating every previously shown PIN. No-op unless a transfer is
/// waiting for a receiver.
pub fn request_pin_refresh() {
    pin_refresh_signal().notify_one();
}

/// Route all subsequent UI output to the TUI as [`UiEvent`]s. Call once,
/// before spawning the transfer task.
pub fn install_tui_sink(tx: mpsc::UnboundedSender<UiEvent>) {
    // The wizard installs the sink once per process. Guard against a repeat
    // call anyway: keep the first sender rather than crashing or replacing it.
    if TUI_SINK.set(tx).is_err() {
        debug_assert!(false, "TUI sink installed more than once");
    }
}

fn sink() -> Option<&'static mpsc::UnboundedSender<UiEvent>> {
    TUI_SINK.get()
}

/// Ids for status lines. A counter rather than a position, so a line can still
/// be found after other steps have reported over it.
static NEXT_STATUS_ID: AtomicU64 = AtomicU64::new(0);

fn next_status_id() -> u64 {
    NEXT_STATUS_ID.fetch_add(1, Ordering::Relaxed)
}

/// Informational status line (stderr).
pub fn status(line: &str) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::Status {
            id: next_status_id(),
            line: line.to_string(),
        });
    } else {
        eprintln!("{line}");
    }
}

/// A status line that will be rewritten in place when its step reports again.
///
/// Held by the step it announces, so "Fetching the Tor directory..." becomes
/// "Fetched the Tor directory (36.5 s)" on the row it was written to, however
/// many other steps reported in between. Without a sink there is no row to
/// rewrite and the completion is simply a second line on stderr.
#[must_use = "a step that is never completed leaves its line saying it is still running"]
pub struct StatusStep {
    id: u64,
    started: Instant,
}

/// Announce a step and keep hold of its line.
pub fn status_step(line: &str) -> StatusStep {
    let id = next_status_id();
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::Status {
            id,
            line: line.to_string(),
        });
    } else {
        eprintln!("{line}");
    }
    StatusStep {
        id,
        started: Instant::now(),
    }
}

impl StatusStep {
    /// Rewrite the step's line as finished, with how long it took.
    pub fn done(self, line: &str) {
        let line = format!("{line} ({})", format_elapsed(self.started.elapsed()));
        if let Some(tx) = sink() {
            let _ = tx.send(UiEvent::StatusReplace { id: self.id, line });
        } else {
            eprintln!("{line}");
        }
    }
}

fn format_elapsed(elapsed: Duration) -> String {
    let ms = elapsed.as_millis();
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.1} s", elapsed.as_secs_f64())
    }
}

/// Update the single-line live progress indicator (stderr).
pub fn progress(dir: Direction, bytes: u64, total: u64) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::Progress { dir, bytes, total });
        return;
    }
    let verb = match dir {
        Direction::Send => "Sending",
        Direction::Receive => "Receiving",
    };
    eprint!(
        "\r   {verb}: {}% ({}/{})",
        calc_percent(bytes, total) as u32,
        format_bytes(bytes),
        format_bytes(total),
    );
    let _ = std::io::stderr().flush();
}

/// Terminate the live progress line with a newline.
pub fn progress_end() {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::ProgressEnd);
    } else {
        eprintln!();
    }
}

/// Present the sender's PIN (stdout in plain mode, panel in the TUI).
pub fn show_pin(file_name: &str, file_size: u64, pin: &str) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::ShowPin {
            file_name: file_name.to_string(),
            size: file_size,
            pin: pin.to_string(),
        });
        return;
    }
    eprintln!(
        "Ready to send \"{file_name}\" ({}). Enter this PIN in pTransfer:",
        format_bytes(file_size)
    );
    println!("{pin}");
    eprintln!("After the receiver enters it, ask them for their confirmation code.");
    eprintln!(
        "(a fresh PIN is printed every {} min)",
        crate::crypto::pin::PIN_ROTATION_MS / 60_000
    );
}

/// Present the Tor sender's address and password. Both are needed to receive,
/// and neither is a secret the sender keeps — they are meant to be handed over
/// together.
pub fn show_tor_address(file_name: &str, file_size: u64, address: &str, password: &str) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::ShowTorAddress {
            file_name: file_name.to_string(),
            size: file_size,
            address: address.to_string(),
            password: password.to_string(),
        });
        return;
    }
    eprintln!(
        "Ready to send \"{file_name}\" ({}). The receiver needs both of these:",
        format_bytes(file_size)
    );
    println!("address:  {address}");
    println!("password: {password}");
    let _ = std::io::stdout().flush();
}

/// Report that the onion descriptor is published and the address is reachable.
pub fn tor_published() {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::TorPublished);
        return;
    }
    // The line callers script against: nothing can connect before it.
    println!("ready");
    let _ = std::io::stdout().flush();
}

/// Present a Code Exchange code for the operator to carry.
///
/// The code goes to stdout and everything else to stderr, so a piped run
/// captures the code alone — it is a couple of kilobytes of base64, which is
/// worth redirecting rather than reading.
pub fn show_code(label: &str, code: &str) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::ShowCode {
            label: label.to_string(),
            code: code.to_string(),
        });
        return;
    }
    eprintln!("{label}");
    println!("{code}");
    let _ = std::io::stdout().flush();
}

/// Stop showing a code that has been acted on. Plain mode prints nothing: the
/// code is already scrolled into the terminal's history, where it is harmless
/// once the session it belongs to has moved on.
pub fn hide_code() {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::HideCode);
    }
}

/// Assemble a hand-carried code from `reader`, however it was wrapped.
///
/// A code is a couple of kilobytes of base64, and everything that carries one
/// is free to break it across lines — a mail client, a chat window, a terminal
/// that soft-wrapped the paste it was given. The protocol says whitespace and
/// line wrapping around a code are ignored, so reading a single line would
/// refuse a code that arrived completely intact.
///
/// Lines are taken until they add up to a code that decodes, or until a blank
/// line or end of input says there are no more. The first rule is what makes a
/// one-line paste finish on its own Enter, the way it always did; the second
/// is how a code that will never decode — expired, or from another hour — ends
/// up reported as that rather than waiting forever for a line that would fix
/// it.
fn read_code(reader: &mut impl std::io::BufRead, noun: &str) -> Result<String> {
    let mut code = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            // Nothing yet is a blank line before the paste, not the end of it.
            if code.is_empty() {
                continue;
            }
            break;
        }
        code.push_str(trimmed);
        if is_complete_code(&code) {
            break;
        }
    }
    if code.is_empty() {
        return Err(anyhow!("no {noun} on stdin"));
    }
    Ok(code)
}

/// Whether what has been read so far is a whole code. Only a complete
/// container decodes, so this is what says another line is not needed.
fn is_complete_code(text: &str) -> bool {
    crate::code::payload::from_clipboard(text)
        .is_ok_and(|binary| crate::code::payload::decode(&binary).is_ok())
}

/// Read a hand-carried code from stdin, prompting with `label` at a terminal.
///
/// The prompt says a blank line ends the paste, because that is the way out
/// for a code this side cannot decode: an expired one, or one from a wrapped
/// paste that lost a line on the way.
pub async fn read_code_from_stdin(label: &'static str, noun: &'static str) -> Result<String> {
    use std::io::IsTerminal;

    tokio::task::spawn_blocking(move || {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            eprint!("{label} (paste it; a blank line ends it): ");
            std::io::stderr().flush()?;
        }
        read_code(&mut stdin.lock(), noun)
    })
    .await?
}

/// Read the receiver's response code, which is Code Exchange's confirmation
/// step: nothing enters this session unless the operator puts it there.
pub async fn prompt_response_code() -> Result<String> {
    if let Some(tx) = sink() {
        let (reply, rx) = oneshot::channel();
        tx.send(UiEvent::ResponseCodeInput { reply })
            .map_err(|_| anyhow!("TUI closed"))?;
        return rx.await.map_err(|_| anyhow!("TUI closed"));
    }

    eprint!("Paste the receiver's response code (a blank line ends it): ");
    std::io::stderr().flush()?;
    // A detached OS thread, for the same reason the confirmation prompt uses
    // one: Tokio's blocking pool waits for a stuck stdin read when the runtime
    // is dropped, and this read has no deadline over it.
    let (reply, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let result = read_code(&mut stdin.lock(), "response code");
        let _ = reply.send(result);
    });
    rx.await.map_err(|_| anyhow!("response code input closed"))?
}

/// Display the ECDH-derived code the receiver must read to the sender.
pub fn show_confirmation_code(code: &str) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::ShowConfirmationCode(code.to_string()));
        return;
    }
    eprintln!("Read this confirmation code to the sender:");
    println!("{code}");
    let _ = std::io::stdout().flush();
}

/// Stop displaying the receiver's confirmation code once confirm arrives.
pub fn hide_confirmation_code() {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::HideConfirmationCode);
    }
}

/// Read one sender-side confirmation-code attempt.
pub async fn prompt_confirmation_code() -> Result<String> {
    if let Some(tx) = sink() {
        let (reply, rx) = oneshot::channel();
        tx.send(UiEvent::ConfirmationCodeInput { reply })
            .map_err(|_| anyhow!("TUI closed"))?;
        return rx.await.map_err(|_| anyhow!("TUI closed"));
    }

    eprint!("Enter the receiver's 8-character confirmation code: ");
    std::io::stderr().flush()?;
    // A detached OS thread keeps the read from blocking Tokio runtime shutdown
    // if the surrounding 150-second confirmation deadline expires. Tokio's
    // blocking pool waits for stuck stdin reads when the runtime is dropped.
    let (reply, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let mut input = String::new();
        let result = std::io::stdin()
            .read_line(&mut input)
            .map_err(anyhow::Error::from)
            .and_then(|_| validate_confirmation_code_input(&input));
        let _ = reply.send(result);
    });
    rx.await.map_err(|_| anyhow!("confirmation input closed"))?
}

fn validate_confirmation_code_input(input: &str) -> Result<String> {
    let input = input.trim();
    if input.is_empty() {
        Err(anyhow!("no confirmation code entered"))
    } else {
        Ok(input.to_string())
    }
}

/// Stop displaying the PIN: a receiver claimed the transfer, so every shown
/// PIN is now invalid. Plain mode prints nothing — the sender's status line
/// already reports the claim.
pub fn hide_pin() {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::HidePin);
    }
}

/// Announce the incoming file a receiver is about to accept.
pub fn incoming(file_name: &str, size: u64, mime_type: Option<&str>) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::Incoming {
            file_name: file_name.to_string(),
            size,
        });
        return;
    }
    match mime_type {
        Some(mime) => eprintln!(
            "Incoming file: \"{file_name}\" ({}, {mime})",
            format_bytes(size)
        ),
        None => eprintln!("Incoming file: \"{file_name}\" ({})", format_bytes(size)),
    }
}

/// Ask how to handle an existing destination file.
pub async fn prompt_file_exists(path: &Path) -> Result<FileExistsChoice> {
    if let Some(tx) = sink() {
        let (reply, rx) = oneshot::channel();
        tx.send(UiEvent::FileExists {
            path: path.to_path_buf(),
            reply,
        })
        .map_err(|_| anyhow!("TUI closed"))?;
        return rx.await.map_err(|_| anyhow!("TUI closed"));
    }
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || prompt_file_exists_blocking(&path)).await?
}

fn prompt_file_exists_blocking(path: &Path) -> Result<FileExistsChoice> {
    print!(
        "Warning: file exists: {}\n[o]verwrite / [r]ename / [c]ancel: ",
        path.display()
    );
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    match input.trim().to_lowercase().as_str() {
        "o" | "overwrite" => Ok(FileExistsChoice::Overwrite),
        "r" | "rename" => Ok(FileExistsChoice::Rename),
        _ => Ok(FileExistsChoice::Cancel),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A code that arrives wrapped is a code: everything that carries one may
    /// break it across lines, and the container is the same bytes either way.
    #[test]
    fn a_wrapped_code_is_read_as_one_value() {
        let code = sample_code();
        let wrapped: String = code
            .as_bytes()
            .chunks(64)
            .map(|row| format!("{}\n", String::from_utf8_lossy(row)))
            .collect();
        assert!(wrapped.lines().count() > 1, "the sample should wrap");

        let mut reader = std::io::Cursor::new(wrapped.into_bytes());
        assert_eq!(read_code(&mut reader, "sender code").unwrap(), code);
    }

    /// The common case still finishes on its own Enter rather than waiting for
    /// a line that is not coming.
    #[test]
    fn a_single_line_code_needs_no_terminator() {
        let code = sample_code();
        // Nothing after the newline: a reader that wanted more would block on
        // a terminal, and here it would read past the value.
        let mut reader = std::io::Cursor::new(format!("{code}\n").into_bytes());
        assert_eq!(read_code(&mut reader, "sender code").unwrap(), code);
    }

    /// Text that will never decode — an expired code, a paste that lost a line
    /// — ends at the blank line and is reported, not waited on.
    #[test]
    fn an_unreadable_paste_ends_at_a_blank_line() {
        let mut reader = std::io::Cursor::new(b"not-a-code
still-not

left over
".to_vec());
        assert_eq!(read_code(&mut reader, "sender code").unwrap(), "not-a-codestill-not");

        let mut empty = std::io::Cursor::new(b"

".to_vec());
        assert_eq!(
            read_code(&mut empty, "sender code").unwrap_err().to_string(),
            "no sender code on stdin"
        );
    }

    /// A code as a sender hands it over, for the readers above.
    fn sample_code() -> String {
        use crate::code::payload::{
            CODE_SALT_LEN, PUBLIC_KEY_LEN, PayloadKind, SignalingPayload, encode, now_ms,
            to_clipboard,
        };
        to_clipboard(
            &encode(&SignalingPayload {
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
                anon: None,
            })
            .unwrap(),
        )
    }

    #[test]
    fn confirmation_code_input_rejects_whitespace_only() {
        let error = validate_confirmation_code_input(" \t\r\n ").unwrap_err();
        assert_eq!(error.to_string(), "no confirmation code entered");
    }

    #[test]
    fn confirmation_code_input_returns_trimmed_value() {
        assert_eq!(
            validate_confirmation_code_input("  A4BC-D9ZT \n").unwrap(),
            "A4BC-D9ZT"
        );
    }
}
