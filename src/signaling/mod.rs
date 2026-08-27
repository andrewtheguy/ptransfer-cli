//! Signaling: exchanging WebRTC offers/answers between peers over Nostr
//! relays, authenticated by the PIN's SPAKE2 exchange.
//!
//! Two relay pools, chosen by the PIN's length and nothing else: the clearnet
//! one in [`nostr`], and — in a build with the `tor` feature — the
//! onion-service one in [`anonymous`].

/// Anonymous signaling over onion-service relays. Requires the `tor` feature,
/// which is what brings in the Tor client it runs on.
#[cfg(feature = "tor")]
pub mod anonymous;
pub mod nostr;
