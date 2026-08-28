//! ptransfer-cli: the pTransfer command-line client for peer-to-peer file transfer.
//!
//! This crate re-implements pTransfer's crypto and wire formats so files
//! and folders can be transferred between the CLI and the browser app over a
//! WebRTC data channel. Two signaling modes reach it: PIN Exchange over Nostr
//! relays, and Code Exchange, whose offer and response are carried by hand as
//! base64 text.
//! Multiple files/folders are bundled into one ZIP on the fly, exactly like the
//! web app. The interactive interface is a full-screen TUI wizard; QR codes and
//! word-based PIN entry are intentionally not supported — a Code Exchange code
//! is copied and pasted as text here.

pub mod archive;
pub mod code;
pub mod crypto;
pub mod signaling;
pub mod tor;
pub mod transfer;
pub mod tui;
pub mod ui;
pub mod util;
pub mod webrtc;
pub mod wire;
