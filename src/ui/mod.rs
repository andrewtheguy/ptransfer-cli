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
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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
    Status(String),
    /// A newer form of the most recent [`UiEvent::Status`] line — its progress
    /// while it runs, or its completion ("Doing X..." → "Did X (elapsed)").
    /// The TUI replaces that line instead of appending, so a step that reports
    /// a hundred times still costs one row.
    StatusDone(String),
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
    #[cfg(feature = "tor")]
    ShowTorAddress {
        file_name: String,
        size: u64,
        address: String,
        password: String,
    },
    /// The onion descriptor is published, so the address is now reachable.
    #[cfg(feature = "tor")]
    TorPublished,
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

/// Informational status line (stderr).
pub fn status(line: &str) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::Status(line.to_string()));
    } else {
        eprintln!("{line}");
    }
}

/// Informational status line with elapsed time, completing the step announced
/// by the preceding [`status`] call.
pub fn status_timed(line: &str, elapsed: Duration) {
    let full = format!("{line} ({})", format_elapsed(elapsed));
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::StatusDone(full));
    } else {
        eprintln!("{full}");
    }
}

/// Replace the most recent status line with a newer form of the same step.
///
/// For a long step whose only news is that it is still going. The TUI
/// overwrites the row it already has, so a minute of Tor bootstrap progress
/// costs one line rather than a scrolling wall of them; without a sink each
/// update is its own line on stderr, which is why callers throttle.
pub fn status_update(line: &str) {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::StatusDone(line.to_string()));
    } else {
        eprintln!("{line}");
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
#[cfg(feature = "tor")]
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
#[cfg(feature = "tor")]
pub fn tor_published() {
    if let Some(tx) = sink() {
        let _ = tx.send(UiEvent::TorPublished);
        return;
    }
    // The line callers script against: nothing can connect before it.
    println!("ready");
    let _ = std::io::stdout().flush();
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
