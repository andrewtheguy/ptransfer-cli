//! What counts as a clearnet relay URL, and the seed pool discovery starts
//! from.
//!
//! One canonical form is used for identity, deduplication, exclusion, and the
//! socket itself. It has to be one form: a ring position indexes into a relay
//! list, an exclusion set decides what may not carry chunks, and a URL that
//! compares unequal to itself under a trailing slash would quietly break both.

use anyhow::{Context, Result, bail};
use nostr_sdk::prelude::Url;

/// The relays discovery is seeded from and the control channel is probed
/// against: the clearnet signaling pool this CLI already holds. They are
/// queried and used for control, never for chunks.
pub use crate::signaling::nostr::DEFAULT_RELAYS as SEED_RELAYS;

/// Names RFC 2606/6761 reserves, so a listed "relay" there is placeholder
/// junk. The reserved domains resolve — IANA runs them for documentation —
/// but will never host a relay; the reserved TLDs are guaranteed not to.
const RESERVED_DOMAINS: [&str; 3] = ["example.com", "example.net", "example.org"];
const RESERVED_TLDS: [&str; 2] = [".test", ".invalid"];

/// The canonical form of a clearnet relay URL, or `None` when it is not one.
///
/// Only `wss://` on a public host. Onion, local, and IP-literal hosts are
/// refused here rather than filtered later: this is the one function every
/// relay list an offer, a discovery event, or an announcement carries has to
/// pass through, so it is where "a relay is a public WebSocket host" is
/// decided once.
pub fn normalize_relay_url(raw: &str) -> Option<String> {
    let url = Url::parse(raw.trim()).ok()?;
    if url.scheme() != "wss" || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = url.host_str()?;
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".onion")
        || host.ends_with(".local")
        || RESERVED_TLDS.iter().any(|tld| host.ends_with(tld))
        || RESERVED_DOMAINS
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
    {
        return None;
    }
    // IP literals: typically private or test relays no peer could reach.
    if host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.') || host.contains(':') {
        return None;
    }
    let port = url.port().map(|port| format!(":{port}")).unwrap_or_default();
    let path = url.path().trim_end_matches('/');
    let query = url
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    Some(format!("wss://{host}{port}{path}{query}"))
}

/// The canonical form of every URL in a list, dropping what is not a relay.
pub fn canonical(urls: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    urls.into_iter()
        .filter_map(|url| normalize_relay_url(url.as_ref()))
        .filter(|url| seen.insert(url.clone()))
        .collect()
}

/// The relays an offer names, in canonical form.
///
/// A list that is malformed — not relay URLs, repeated, or longer than an
/// offer may carry — invalidates the offer rather than being trimmed: it is
/// covered by the offer digest the answer's confirmation tag is bound to, so
/// something that is not a relay list there is not an offer either side made.
pub fn offer_relays(relays: &[String], max: usize, min: usize) -> Result<Vec<String>> {
    if relays.len() > max {
        bail!("an offer may not name more than {max} relays");
    }
    let mut canonical = Vec::with_capacity(relays.len());
    for relay in relays {
        if relay.len() >= 200 {
            bail!("an offer names something too long to be a relay URL");
        }
        let normalized =
            normalize_relay_url(relay).context("an offer names something that is not a relay")?;
        if canonical.contains(&normalized) {
            bail!("an offer names one relay twice");
        }
        canonical.push(normalized);
    }
    if canonical.len() < min {
        bail!("an offer that names relays names at least {min} of them");
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relay list written into the source is the one list that could reach
    /// the network in a form nothing else compares equal to, so it has to read
    /// exactly as it is used.
    #[test]
    fn the_seed_pool_is_written_in_canonical_form() {
        for relay in SEED_RELAYS {
            assert_eq!(normalize_relay_url(relay).as_deref(), Some(*relay));
        }
    }

    #[test]
    fn one_relay_has_one_canonical_form() {
        assert_eq!(
            normalize_relay_url("  wss://Relay.Example/  ").unwrap(),
            "wss://relay.example"
        );
        assert_eq!(
            normalize_relay_url("wss://relay.example:443").unwrap(),
            "wss://relay.example"
        );
        assert_eq!(
            normalize_relay_url("wss://relay.example:7777/path/").unwrap(),
            "wss://relay.example:7777/path"
        );
    }

    /// Everything that is not a relay a peer could reach over the clearnet.
    /// An onion address is refused here on purpose: that pool is reached
    /// through Tor by the other fallback, and a clearnet socket to it would be
    /// neither anonymous nor connectable.
    #[test]
    fn what_is_not_a_public_websocket_relay_is_refused() {
        for raw in [
            "ws://relay.example.net",
            "https://relay.example.net",
            "wss://localhost",
            "wss://relay.localhost",
            "wss://zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion",
            "wss://printer.local",
            "wss://192.0.2.10",
            "wss://[2001:db8::1]",
            "wss://relay.test",
            "wss://relay.invalid",
            "wss://example.com",
            "wss://relay.example.org",
            "wss://user:pass@relay.example.net",
            "not a url",
        ] {
            assert!(normalize_relay_url(raw).is_none(), "{raw} should be refused");
        }
    }

    #[test]
    fn an_offers_relay_list_is_taken_whole_or_not_at_all() {
        let good = vec![
            "wss://one.example".to_string(),
            "wss://two.example/".to_string(),
        ];
        assert_eq!(
            offer_relays(&good, 6, 2).unwrap(),
            vec!["wss://one.example", "wss://two.example"]
        );
        assert!(offer_relays(&good, 1, 2).is_err());
        assert!(offer_relays(&good[..1], 6, 2).is_err());
        assert!(
            offer_relays(
                &["wss://one.example".to_string(), "wss://one.example/".to_string()],
                6,
                2
            )
            .is_err()
        );
        assert!(offer_relays(&["ws://one.example.net".to_string()], 6, 1).is_err());
    }
}
