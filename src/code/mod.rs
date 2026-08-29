//! Code Exchange: the transfer mode with no signaling server at all.
//!
//! The sender's offer and the receiver's response are both carried by a
//! person. Nothing about the exchange touches a relay — not even the response,
//! which enters the sender's session only when its operator pastes it in, and
//! that paste is the mode's confirmation step.
//!
//! The web app can carry those two codes as QR grids or as base64 text; this
//! CLI carries them as **base64 text**. Drawing the offer as a QR grid is on
//! the roadmap; reading the response back from one is not, since there is no
//! camera at a terminal, so the response stays text either way.
//!
//! - [`payload`]: the PT01 container the codes travel in.
//! - [`keys`]: the ECDH agreement and every key derived off it.
//! - [`sender`] / [`receiver`]: the two halves of the exchange.
//! - [`nostr_file`]: the ordinary fallback, when the two devices turn out to
//!   have no direct route between them — the file itself relayed through
//!   public Nostr relays, in place of TURN.
//! - [`control`] and [`relay`]: the anonymous fallback, which the sender picks
//!   instead — the same sealed control channel carried over Tor, and the file
//!   over an onion service rather than on relays.
//!
//! Which fallback a transfer has is the sender's own choice and is carried in
//! the offer: `anon: true` asks for the Tor one, a `relays` list names the
//! control relays of the clearnet one, and an offer carrying neither has no
//! fallback at all — a failed direct route ends that transfer.

pub mod control;
pub mod keys;
pub mod nostr_file;
pub mod payload;
pub mod receiver;
pub mod relay;
pub mod sender;

pub use receiver::receive_file_code;
pub use sender::send_file_code;
