//! ptransfer-cli: the pTransfer command-line client for peer-to-peer file transfer.
//!
//! Running with no arguments launches the full-screen TUI wizard, which covers
//! all three transfer modes. The `code` and `tor` subcommands run Code Exchange
//! and the onion transport non-interactively, and the `test` subcommand exposes
//! PIN Exchange the same way for testing. QR support is intentionally not part
//! of this CLI: Code Exchange codes are copied and pasted as text.
//! Build with: cargo build --release

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use ptransfer_cli::tor;
use ptransfer_cli::crypto::pin::PinKind;
use ptransfer_cli::util::{OnConflict, is_interrupted};
use ptransfer_cli::{archive, code, tui, webrtc};

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

    /// Code Exchange: hand-carried offer and response codes
    Code {
        #[command(subcommand)]
        command: CodeCommands,

        /// Use verbose logging
        #[arg(short, long, global = true)]
        verbose: bool,
    },

    /// Tor onion-service transport (experimental)
    Tor {
        #[command(subcommand)]
        command: TorCommands,

        /// Use verbose logging
        #[arg(short, long, global = true)]
        verbose: bool,
    },
}

/// File transfer with no signaling server: the sender's offer and the
/// receiver's response are carried by hand, as base64 text.
///
/// The web app can carry the same codes as QR grids; this CLI does not, since
/// there is no camera at a terminal. Codes go to stdout and everything else to
/// stderr, so either side can be piped.
#[derive(Subcommand)]
enum CodeCommands {
    /// Show an offer code, then take the receiver's response.
    ///
    /// Multiple inputs are bundled into one ZIP.
    Send {
        /// Files and/or directories to send
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Fall back to Tor when no direct connection can be made
        /// (experimental).
        ///
        /// Changes nothing about the exchange itself. If the direct WebRTC
        /// route fails, the file goes over a temporary onion service this
        /// process publishes, coordinated over onion-service Nostr relays —
        /// with no address and no password for anyone to carry, both being
        /// derived from the exchange. Caps the transfer at 100 MiB, needs
        /// internet on both devices, and starts a Tor bootstrap as soon as the
        /// code is shown. Without it, a failed direct route ends the transfer.
        #[arg(long)]
        anonymous: bool,
    },

    /// Take a sender's offer code, then show the response to give back.
    ///
    /// The offer is read from stdin — a prompt at a terminal, one line from a
    /// pipe. There is no flag for the anonymous fallback: the code says
    /// whether the sender selected it.
    Receive {
        /// Output directory (defaults to the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Replace the destination file if it already exists (default: fail)
        #[arg(long)]
        overwrite: bool,

        /// Answer as if no direct connection were possible, so the transfer
        /// takes the sender's fallback.
        ///
        /// The response goes back with none of this device's network routes in
        /// it, which is the situation a device behind a hostile NAT is in
        /// anyway — the only way to exercise the fallback from a network where
        /// a direct connection would succeed. Refused for a code whose sender
        /// selected no fallback, since that would only kill a working
        /// transfer.
        #[arg(long)]
        simulate_no_direct: bool,
    },
}

/// File transfer over an ephemeral v3 onion service.
///
/// `send` publishes an address and a one-time password; `receive` needs
/// nothing but those two strings.
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
    ///
    /// The password is read from stdin — a prompt at a terminal, one line from
    /// a pipe — never from the command line.
    Receive {
        /// The `.onion` address printed by `ptransfer tor send`
        address: String,

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
}

#[derive(Subcommand)]
enum TestCommands {
    /// Send files and/or folders; multiple inputs are bundled into one ZIP.
    Send {
        /// Files and/or directories to send
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Carry signaling to onion-service relays over Tor (experimental).
        ///
        /// Mints a 16-character PIN instead of a 12-character one; the
        /// receiver reads the mode off that length and needs no flag of its
        /// own. Hides both devices' IP addresses from the Nostr relays. The file
        /// bytes still travel over the direct WebRTC data channel.
        #[arg(long)]
        anonymous: bool,
    },

    /// Receive a file.
    ///
    /// The PIN is read from stdin — a prompt at a terminal, one line from a
    /// pipe — never from the command line. Its length says which relay pool
    /// the sender is on, so anonymous signaling needs no flag here.
    Receive {
        /// Output directory (defaults to the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Replace the destination file if it already exists (default: fail)
        #[arg(long)]
        overwrite: bool,
    },
}

/// Read one line of secret from stdin, prompting with `label` at a terminal.
///
/// Nothing the receiving side is handed is a command-line argument, because an
/// argument is public: every other process on the machine can read it out of
/// the process list, and an interactive shell writes it to history. That would
/// matter little for a secret with a short life, but the receiver holds one
/// across a whole connection attempt — tens of seconds for PIN Exchange, and
/// minutes when a Tor bootstrap is in front of it — and it is the credential
/// whoever grabs it uses to collect the file first.
///
/// `noun` names the value in the two error messages, so a receiver that piped
/// the wrong thing is told which input was empty.
async fn read_secret(label: &'static str, noun: &'static str) -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};

    tokio::task::spawn_blocking(move || {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            eprint!("{label}: ");
            std::io::stderr().flush()?;
        }
        let mut input = String::new();
        if stdin.lock().read_line(&mut input)? == 0 {
            anyhow::bail!("no {noun} on stdin");
        }
        let secret = input.trim();
        if secret.is_empty() {
            anyhow::bail!("no {noun} entered");
        }
        Ok(secret.to_string())
    })
    .await?
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
                TestCommands::Send {
                    paths,
                    anonymous,
                } => {
                    let pin_kind = if anonymous {
                        PinKind::Anonymous
                    } else {
                        PinKind::Standard
                    };

                    let source =
                        tokio::task::spawn_blocking(move || archive::prepare_send_source(&paths))
                            .await??;
                    webrtc::send_file_nostr(&source, pin_kind).await
                }

                TestCommands::Receive { output, overwrite } => {
                    let on_conflict = if overwrite {
                        OnConflict::Overwrite
                    } else {
                        OnConflict::Fail
                    };
                    let pin = read_secret("PIN", "PIN").await?;
                    webrtc::receive_file_nostr(&pin, output, on_conflict).await
                }
            }
        }

        Some(Commands::Code { command, verbose }) => {
            // An anonymous fallback can spend minutes inside a Tor bootstrap
            // saying nothing, so keep info-level progress on by default, as the
            // `tor` subcommand does. RUST_LOG still overrides.
            init_logging(if verbose {
                "debug"
            } else {
                "info,webrtc_ice=error"
            });

            match command {
                CodeCommands::Send { paths, anonymous } => {
                    let source =
                        tokio::task::spawn_blocking(move || archive::prepare_send_source(&paths))
                            .await??;
                    code::send_file_code(&source, anonymous).await
                }

                CodeCommands::Receive {
                    output,
                    overwrite,
                    simulate_no_direct,
                } => {
                    let on_conflict = if overwrite {
                        OnConflict::Overwrite
                    } else {
                        OnConflict::Fail
                    };
                    // Read like a secret rather than taken as an argument: the
                    // offer is the secret for the whole transfer, and an
                    // argument is readable in the process list for as long as
                    // the receiver runs.
                    let offer = read_secret("Sender code", "sender code").await?;
                    code::receive_file_code(&offer, output, on_conflict, simulate_no_direct)
                        .await
                }
            }
        }

        Some(Commands::Tor { command, verbose }) => {
            // Bootstrapping from an empty directory cache takes a while and
            // says nothing on stdout, so keep info-level progress on by
            // default here. RUST_LOG still overrides.
            init_logging(if verbose { "debug" } else { "info" });

            match command {
                TorCommands::Send { paths, port } => tor::transfer::send(paths, port).await,

                TorCommands::Receive {
                    address,
                    port,
                    output,
                    overwrite,
                } => {
                    let on_conflict = if overwrite {
                        OnConflict::Overwrite
                    } else {
                        OnConflict::Fail
                    };
                    let password = read_secret("Password", "password").await?;
                    tor::transfer::receive(
                        address.trim(),
                        port,
                        &password,
                        output,
                        on_conflict,
                    )
                    .await
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
            command: TestCommands::Send { paths, .. },
            ..
        }) = cli.command
        else {
            panic!("expected test send");
        };
        assert_eq!(paths.len(), 3);
    }

    /// The sender is the only side that chooses anonymous signaling; the
    /// receiver is told by the PIN it is handed, so there is deliberately no
    /// flag for it.
    #[test]
    fn only_test_send_takes_anonymous() {
        let cli =
            Cli::try_parse_from(["ptransfer", "test", "send", "a.txt", "--anonymous"]).unwrap();
        let Some(Commands::Test {
            command: TestCommands::Send { anonymous, .. },
            ..
        }) = cli.command
        else {
            panic!("expected test send");
        };
        assert!(anonymous);

        assert!(Cli::try_parse_from(["ptransfer", "test", "receive", "--anonymous"]).is_err());
    }

    #[test]
    fn test_send_requires_a_path() {
        assert!(Cli::try_parse_from(["ptransfer", "test", "send"]).is_err());
    }

    /// The PIN comes from stdin, so an argument that looks like one is rejected
    /// rather than quietly published in the process list — the same rule the
    /// Tor transport's password follows.
    #[test]
    fn test_receive_never_takes_the_pin_as_an_argument() {
        assert!(Cli::try_parse_from(["ptransfer", "test", "receive"]).is_ok());
        assert!(Cli::try_parse_from(["ptransfer", "test", "receive", "PIN123"]).is_err());
        assert!(
            Cli::try_parse_from(["ptransfer", "test", "receive", "PIN123", "--overwrite"])
                .is_err()
        );
    }

    #[test]
    fn code_send_takes_multiple_paths_and_the_anonymous_option() {
        let cli = Cli::try_parse_from([
            "ptransfer", "code", "send", "a.txt", "b", "dir", "--anonymous",
        ])
        .unwrap();
        let Some(Commands::Code {
            command: CodeCommands::Send { paths, anonymous },
            ..
        }) = cli.command
        else {
            panic!("expected code send");
        };
        assert_eq!(paths.len(), 3);
        assert!(anonymous);

        assert!(Cli::try_parse_from(["ptransfer", "code", "send"]).is_err());
    }

    /// The sender's code is the secret for the whole transfer, so it follows
    /// the same rule every other secret does: stdin, never an argument.
    #[test]
    fn code_receive_never_takes_the_sender_code_as_an_argument() {
        assert!(Cli::try_parse_from(["ptransfer", "code", "receive"]).is_ok());
        assert!(Cli::try_parse_from(["ptransfer", "code", "receive", "UFQwMabc"]).is_err());

        // The receiving side is told which fallback to expect by the code
        // itself, so there is deliberately no anonymous flag here.
        assert!(Cli::try_parse_from(["ptransfer", "code", "receive", "--anonymous"]).is_err());
    }

    #[test]
    fn code_receive_parses_its_options() {
        let cli = Cli::try_parse_from([
            "ptransfer",
            "code",
            "receive",
            "--overwrite",
            "--simulate-no-direct",
        ])
        .unwrap();
        let Some(Commands::Code {
            command:
                CodeCommands::Receive {
                    overwrite,
                    simulate_no_direct,
                    ..
                },
            ..
        }) = cli.command
        else {
            panic!("expected code receive");
        };
        assert!(overwrite);
        assert!(simulate_no_direct);

        // Simulating a dead route is the receiver's affordance alone: the
        // sending side has nothing to pretend about.
        assert!(
            Cli::try_parse_from(["ptransfer", "code", "send", "a.txt", "--simulate-no-direct"])
                .is_err()
        );
    }

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

    #[test]
    fn tor_receive_takes_an_address_and_never_a_password() {
        assert!(Cli::try_parse_from(["ptransfer", "tor", "receive"]).is_err());
        // The password comes from stdin, so an argument that looks like one is
        // rejected rather than quietly published in the process list.
        assert!(
            Cli::try_parse_from(["ptransfer", "tor", "receive", "abc.onion", "PIN123"]).is_err()
        );

        let cli = Cli::try_parse_from([
            "ptransfer",
            "tor",
            "receive",
            "abc.onion",
            "--port",
            "1234",
            "--overwrite",
        ])
        .unwrap();
        let Some(Commands::Tor {
            command:
                TorCommands::Receive {
                    address,
                    port,
                    overwrite,
                    ..
                },
            ..
        }) = cli.command
        else {
            panic!("expected tor receive");
        };
        assert_eq!(address, "abc.onion");
        assert_eq!(port, 1234);
        assert!(overwrite);
    }

    #[test]
    fn test_receive_parses_overwrite() {
        let cli = Cli::try_parse_from(["ptransfer", "test", "receive", "--overwrite"]).unwrap();
        let Some(Commands::Test {
            command: TestCommands::Receive { overwrite, .. },
            ..
        }) = cli.command
        else {
            panic!("expected test receive");
        };
        assert!(overwrite);
    }
}
