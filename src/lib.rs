//! ptransfer-cli: the pTransfer command-line client for peer-to-peer file transfer.
//!
//! This crate re-implements pTransfer's crypto and wire formats so files
//! and folders can be transferred between the CLI and the browser app over a
//! WebRTC data channel. PIN exchange over Nostr is the only signaling mode.
//! Multiple files/folders are bundled into one ZIP on the fly, exactly like the
//! web app. The interactive interface is a full-screen TUI wizard; QR codes and
//! word-based PIN entry are intentionally not supported.

pub mod archive;
pub mod crypto;
pub mod signaling;
pub mod tor;
pub mod transfer;
pub mod tui;
pub mod ui;
pub mod util;
pub mod webrtc;
pub mod wire;
