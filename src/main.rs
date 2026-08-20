//! ptransfer-cli: the pTransfer command-line client for peer-to-peer file transfer.
//!
//! Running with no arguments launches the full-screen TUI wizard, which covers
//! sending/receiving files and folders in both Nostr PIN mode and manual PT01
//! copy/paste mode. The `test` subcommand exposes the same flows as a
//! non-interactive plain-text mode for testing. QR support is intentionally
//! not part of this CLI.
//! Build with: cargo build --release

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use ptransfer_cli::util::{OnConflict, is_interrupted};
use ptransfer_cli::{archive, tui, webrtc};

#[derive(Parser)]
#[command(name = "ptransfer")]
#[command(about = "Secure peer-to-peer file transfer, compatible with pTransfer")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Non-interactive plain-text mode, for testing only
    Test {
        #[command(subcommand)]
        command: TestCommands,

        /// Use verbose logging
        #[arg(short, long, global = true)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum TestCommands {
    /// Send files and/or folders; multiple inputs are bundled into one ZIP.
    /// Defaults to pTransfer Nostr PIN mode.
    Send {
        /// Files and/or directories to send
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Use manual PT01 copy/paste signaling instead of Nostr PIN mode
        #[arg(long)]
        manual: bool,
    },

    /// Receive a file. Defaults to pTransfer Nostr PIN mode.
    Receive {
        /// PIN for Nostr mode, or sender offer code with --manual
        code: String,

        /// Output directory (defaults to the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Use manual PT01 copy/paste signaling instead of Nostr PIN mode
        #[arg(long)]
        manual: bool,

        /// Replace the destination file if it already exists (default: fail)
        #[arg(long)]
        overwrite: bool,
    },
}

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install Rustls crypto provider");

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
        .block_on(async_main());

    if let Err(e) = result {
        if is_interrupted(&e) {
            // 128 + SIGINT(2) = 130, the conventional Unix exit code.
            std::process::exit(130);
        }
        eprintln!("Error: {e:?}");
        std::process::exit(1);
    }
}

fn init_logging(default_filter: &str) {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .init();
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // Logging writes to stderr and would scribble on the alternate
            // screen, so it is off by default in the TUI. RUST_LOG overrides.
            init_logging("off");
            tui::run().await
        }

        Some(Commands::Test { command, verbose }) => {
            // Without --verbose, keep the transfer output clean: suppress
            // info/debug/trace log noise from this crate and its dependencies,
            // leaving only warnings and errors. RUST_LOG still overrides both.
            let log_level = if verbose { "debug" } else { "warn" };
            init_logging(&format!("{log_level},webrtc_ice=error"));

            match command {
                TestCommands::Send { paths, manual } => {
                    let source =
                        tokio::task::spawn_blocking(move || archive::prepare_send_source(&paths))
                            .await??;
                    if manual {
                        webrtc::send_file_manual(&source).await
                    } else {
                        webrtc::send_file_nostr(&source).await
                    }
                }

                TestCommands::Receive {
                    code,
                    output,
                    manual,
                    overwrite,
                } => {
                    let on_conflict = if overwrite {
                        OnConflict::Overwrite
                    } else {
                        OnConflict::Fail
                    };
                    if manual {
                        webrtc::receive_file_manual(code.trim(), output, on_conflict).await
                    } else {
                        webrtc::receive_file_nostr(code.trim(), output, on_conflict).await
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_selects_the_tui() {
        let cli = Cli::try_parse_from(["ptransfer"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn bare_invocation_accepts_no_flags() {
        assert!(Cli::try_parse_from(["ptransfer", "--verbose"]).is_err());
        assert!(Cli::try_parse_from(["ptransfer", "send", "x"]).is_err());
    }

    #[test]
    fn test_send_takes_multiple_paths() {
        let cli =
            Cli::try_parse_from(["ptransfer", "test", "send", "a.txt", "b", "dir"]).unwrap();
        let Some(Commands::Test {
            command: TestCommands::Send { paths, manual },
            ..
        }) = cli.command
        else {
            panic!("expected test send");
        };
        assert_eq!(paths.len(), 3);
        assert!(!manual);
    }

    #[test]
    fn test_send_requires_a_path() {
        assert!(Cli::try_parse_from(["ptransfer", "test", "send"]).is_err());
    }

    #[test]
    fn test_receive_requires_a_code() {
        assert!(Cli::try_parse_from(["ptransfer", "test", "receive"]).is_err());
    }

    #[test]
    fn test_receive_parses_overwrite() {
        let cli = Cli::try_parse_from([
            "ptransfer",
            "test",
            "receive",
            "PIN123",
            "--overwrite",
        ])
        .unwrap();
        let Some(Commands::Test {
            command: TestCommands::Receive {
                code, overwrite, ..
            },
            ..
        }) = cli.command
        else {
            panic!("expected test receive");
        };
        assert_eq!(code, "PIN123");
        assert!(overwrite);
    }
}
