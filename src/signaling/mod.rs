//! Signaling: exchanging WebRTC offers/answers between peers over Nostr
//! relays, authenticated by the PIN's SPAKE2 exchange.
//!
//! Two relay pools, chosen by the PIN's length and nothing else: the clearnet
//! one in [`nostr`] and the onion-service one in [`anonymous`].

/// Anonymous signaling over onion-service relays, on the Tor client in
/// [`crate::tor`].
pub mod anonymous;
pub mod nostr;
