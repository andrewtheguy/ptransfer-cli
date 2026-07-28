//! Full-screen TUI wizard: the default interface when the binary runs with no
//! arguments.
//!
//! The wizard collects a [`app::WizardPlan`] first, then:
//! - Nostr plans stay inside the TUI ([`transfer_screen`]), with live status,
//!   PIN panel, progress gauge, and the file-exists modal.
//! - Manual plans tear the terminal down and run the existing plain-text flow,
//!   because the SS03 offer/answer blobs must be copy/pasteable — an alternate
//!   screen would get in the way. The TUI is never re-entered afterward.
//!
//! The process performs exactly one transfer and exits, so the UI event sink
//! installed for Nostr transfers is never uninstalled.

mod app;
mod dir_picker;
mod file_browser;
mod transfer_screen;
mod widgets;

use anyhow::{Context, Result};
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, KeyEvent, KeyModifiers,
};
use ratatui::DefaultTerminal;

use crate::util::OnConflict;
use crate::{archive, ui, webrtc};

use app::WizardPlan;

/// Run the interactive wizard end to end.
pub async fn run() -> Result<()> {
    let mut guard = TerminalGuard::init()?;
    let plan = match app::run_wizard(guard.terminal()).await? {
        Some(plan) => plan,
        None => return Ok(()), // clean quit from the main menu
    };

    match plan {
        WizardPlan::SendNostr(_) | WizardPlan::ReceiveNostr { .. } => {
            transfer_screen::run(guard.terminal(), plan).await
        }

        WizardPlan::SendManual(paths) => {
            drop(guard); // back to the normal terminal for the code swap
            let source =
                tokio::task::spawn_blocking(move || archive::prepare_send_source(&paths)).await??;
            webrtc::send_file_manual(&source).await
        }

        WizardPlan::ReceiveManual { output } => {
            drop(guard);
            let code = ui::prompt_code("Paste the sender's offer code:").await?;
            webrtc::receive_file_manual(code.trim(), Some(output), OnConflict::Prompt).await
        }
    }
}

/// Raw mode disables signal handling, so Ctrl-C arrives as a key event.
fn is_ctrl_c(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && key.code == crossterm::event::KeyCode::Char('c')
}

/// Restores the terminal on drop (early `?` returns, clean exits) in addition
/// to the panic hook `ratatui::try_init` installs (which also covers
/// `panic = "abort"` release builds — the hook runs before the abort).
struct TerminalGuard {
    terminal: DefaultTerminal,
}

impl TerminalGuard {
    fn init() -> Result<Self> {
        let terminal = ratatui::try_init().context("Cannot initialize the terminal")?;
        if let Err(error) = crossterm::execute!(std::io::stdout(), EnableBracketedPaste) {
            ratatui::restore();
            return Err(error).context("Cannot enable terminal paste handling");
        }
        Ok(Self { terminal })
    }

    fn terminal(&mut self) -> &mut DefaultTerminal {
        &mut self.terminal
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(std::io::stdout(), DisableBracketedPaste);
        ratatui::restore();
    }
}
