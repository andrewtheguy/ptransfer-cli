//! Code Exchange: the transfer mode with no signaling server at all.
//!
//! The sender's offer and the receiver's response are both carried by a
//! person. Nothing about the exchange touches a relay — not even the response,
//! which enters the sender's session only when its operator pastes it in, and
//! that paste is the mode's confirmation step.
//!
//! The web app can carry those two codes as QR grids or as base64 text; this
//! CLI carries them as **base64 text only**. There is no camera at a terminal,
//! so a QR path would only add a format neither side of a CLI transfer could
//! use.
//!
//! - [`payload`]: the PT01 container the codes travel in.
//! - [`keys`]: the ECDH agreement and every key derived off it.
//! - [`sender`] / [`receiver`]: the two halves of the exchange.
//! - [`control`] and [`relay`]: the anonymous fallback, for when the two
//!   devices turn out to have no direct route between them.
//!
//! What this CLI does **not** implement is the web app's ordinary clearnet
//! fallback, the Nostr file relay: an offer minted here therefore names no
//! relays, and an offer received from the web app that names some is still
//! taken — its direct path is the same — but a failed direct route ends the
//! transfer rather than moving it onto those relays.

pub mod control;
pub mod keys;
pub mod payload;
pub mod receiver;
pub mod relay;
pub mod sender;

pub use receiver::receive_file_code;
pub use sender::send_file_code;
