//! ptransfer-cli: the pTransfer command-line client for peer-to-peer file transfer.
//!
//! Running with no arguments launches the full-screen TUI wizard, which covers
//! sending and receiving files and folders over PIN exchange. The `test`
//! subcommand exposes the same flows as a non-interactive plain-text mode for
//! testing. QR support is intentionally not part of this CLI.
//! Build with: cargo build --release

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(feature = "tor")]
use ptransfer_cli::tor;
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

    /// Tor onion-service transport
    #[cfg(feature = "tor")]
    Tor {
        #[command(subcommand)]
        command: TorCommands,

        /// Use verbose logging
        #[arg(short, long, global = true)]
        verbose: bool,
    },
}

/// File transfer over an ephemeral v3 onion service, plus the echo proof of
/// concept the transport was built against.
///
/// `send` publishes an address and a one-time password; `receive` needs
/// nothing but those two strings. `serve`/`connect` are the echo POC.
#[cfg(feature = "tor")]
#[derive(Subcommand)]
enum TorCommands {
    /// Publish an onion address and a password, then send to whoever
    /// authenticates with them. Multiple inputs are bundled into one ZIP.
    Send {
        /// Files and/or directories to send
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Onion virtual port to listen on
        #[arg(short, long, default_value_t = tor::DEFAULT_PORT)]
        port: u16,
    },

    /// Receive a file from an onion address, using the sender's password.
    Receive {
        /// The `.onion` address printed by `ptransfer tor send`
        address: String,

        /// The password printed by `ptransfer tor send`
        password: String,

        /// Onion virtual port to connect to
        #[arg(short, long, default_value_t = tor::DEFAULT_PORT)]
        port: u16,

        /// Output directory (defaults to the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Replace the destination file if it already exists (default: fail)
        #[arg(long)]
        overwrite: bool,
    },

    /// Publish an ephemeral onion address and echo back every line received.
    Serve {
        /// Onion virtual port to listen on
        #[arg(short, long, default_value_t = tor::DEFAULT_PORT)]
        port: u16,
    },

    /// Send one line to an onion address and print what comes back.
    Connect {
        /// The `.onion` address printed by `ptransfer tor serve`
        address: String,

        /// Onion virtual port to connect to
        #[arg(short, long, default_value_t = tor::DEFAULT_PORT)]
        port: u16,

        /// Text to send
        #[arg(short, long, default_value = "hello")]
        message: String,
    },
}

#[derive(Subcommand)]
enum TestCommands {
    /// Send files and/or folders; multiple inputs are bundled into one ZIP.
    Send {
        /// Files and/or directories to send
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,
    },

    /// Receive a file.
    Receive {
        /// PIN shown by the sender
        code: String,

        /// Output directory (defaults to the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

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
                TestCommands::Send { paths } => {
                    let source =
                        tokio::task::spawn_blocking(move || archive::prepare_send_source(&paths))
                            .await??;
                    webrtc::send_file_nostr(&source).await
                }

                TestCommands::Receive {
                    code,
                    output,
                    overwrite,
                } => {
                    let on_conflict = if overwrite {
                        OnConflict::Overwrite
                    } else {
                        OnConflict::Fail
                    };
                    webrtc::receive_file_nostr(code.trim(), output, on_conflict).await
                }
            }
        }

        #[cfg(feature = "tor")]
        Some(Commands::Tor { command, verbose }) => {
            // Bootstrapping from an empty directory cache takes a while and
            // says nothing on stdout, so keep info-level progress on by
            // default here. RUST_LOG still overrides.
            init_logging(if verbose { "debug" } else { "info" });

            match command {
                TorCommands::Send { paths, port } => tor::transfer::send(paths, port).await,

                TorCommands::Receive {
                    address,
                    password,
                    port,
                    output,
                    overwrite,
                } => {
                    let on_conflict = if overwrite {
                        OnConflict::Overwrite
                    } else {
                        OnConflict::Fail
                    };
                    tor::transfer::receive(
                        address.trim(),
                        port,
                        password.trim(),
                        output,
                        on_conflict,
                    )
                    .await
                }

                TorCommands::Serve { port } => tor::echo::serve(port).await,

                TorCommands::Connect {
                    address,
                    port,
                    message,
                } => {
                    let reply = tor::echo::connect(address.trim(), port, &message).await?;
                    println!("{reply}");
                    Ok(())
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
            command: TestCommands::Send { paths },
            ..
        }) = cli.command
        else {
            panic!("expected test send");
        };
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn test_send_requires_a_path() {
        assert!(Cli::try_parse_from(["ptransfer", "test", "send"]).is_err());
    }

    #[test]
    fn test_receive_requires_a_code() {
        assert!(Cli::try_parse_from(["ptransfer", "test", "receive"]).is_err());
    }

    #[cfg(feature = "tor")]
    #[test]
    fn tor_serve_defaults_to_the_onion_port() {
        let cli = Cli::try_parse_from(["ptransfer", "tor", "serve"]).unwrap();
        let Some(Commands::Tor {
            command: TorCommands::Serve { port },
            ..
        }) = cli.command
        else {
            panic!("expected tor serve");
        };
        assert_eq!(port, tor::DEFAULT_PORT);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn tor_send_takes_multiple_paths() {
        let cli =
            Cli::try_parse_from(["ptransfer", "tor", "send", "a.txt", "b", "dir"]).unwrap();
        let Some(Commands::Tor {
            command: TorCommands::Send { paths, port },
            ..
        }) = cli.command
        else {
            panic!("expected tor send");
        };
        assert_eq!(paths.len(), 3);
        assert_eq!(port, tor::DEFAULT_PORT);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn tor_receive_requires_an_address_and_a_password() {
        assert!(Cli::try_parse_from(["ptransfer", "tor", "receive"]).is_err());
        assert!(Cli::try_parse_from(["ptransfer", "tor", "receive", "abc.onion"]).is_err());

        let cli = Cli::try_parse_from([
            "ptransfer",
            "tor",
            "receive",
            "abc.onion",
            "PIN123",
            "--overwrite",
        ])
        .unwrap();
        let Some(Commands::Tor {
            command:
                TorCommands::Receive {
                    address,
                    password,
                    overwrite,
                    ..
                },
            ..
        }) = cli.command
        else {
            panic!("expected tor receive");
        };
        assert_eq!(address, "abc.onion");
        assert_eq!(password, "PIN123");
        assert!(overwrite);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn tor_connect_requires_an_address_and_defaults_the_message() {
        assert!(Cli::try_parse_from(["ptransfer", "tor", "connect"]).is_err());

        let cli = Cli::try_parse_from([
            "ptransfer",
            "tor",
            "connect",
            "abc.onion",
            "--port",
            "1234",
        ])
        .unwrap();
        let Some(Commands::Tor {
            command:
                TorCommands::Connect {
                    address,
                    port,
                    message,
                },
            ..
        }) = cli.command
        else {
            panic!("expected tor connect");
        };
        assert_eq!(address, "abc.onion");
        assert_eq!(port, 1234);
        assert_eq!(message, "hello");
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
