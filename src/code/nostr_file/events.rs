//! The events a relayed file is made of.
//!
//! Chunks (and the health probes shaped exactly like them) are NIP-78
//! addressable events of kind 30078:
//!
//! ```text
//! d          <transferId>:<index>     derived, so no per-chunk pointers exist
//! x          <transferId>             what a fetch filters on
//! chunk      <index> <total>
//! encryption aes-256-gcm
//! expiration <created_at + 3600>      NIP-40
//! ```
//!
//! They deliberately carry no file name, size, or plaintext hash: that
//! travels only inside the sealed manifest, and the transfer id is derived
//! from the exchange's ECDH secret rather than from the file, so a relay
//! cannot confirm which file it is holding.

use anyhow::{Context, Result};
use nostr_sdk::prelude::*;

use super::{
    D_TAG_FILTER_BATCH, EVENT_KIND_FILE_CHUNK, NOSTR_FILE_ENCRYPTION_LABEL,
    NOSTR_FILE_EXPIRATION_SEC,
};

pub fn chunk_kind() -> Kind {
    Kind::from_u16(EVENT_KIND_FILE_CHUNK)
}

pub fn chunk_d_tag(transfer_id: &str, index: usize) -> String {
    format!("{transfer_id}:{index}")
}

pub struct ChunkEvent<'a> {
    pub transfer_id: &'a str,
    pub index: usize,
    pub total: usize,
    pub content: String,
    /// unix seconds; the NIP-40 expiration is stamped an hour past it.
    pub created_at: u64,
}

pub fn build_chunk_event(keys: &Keys, params: ChunkEvent<'_>) -> Result<Event> {
    let tags = vec![
        tag("d", chunk_d_tag(params.transfer_id, params.index))?,
        tag("x", params.transfer_id.to_string())?,
        Tag::parse([
            "chunk".to_string(),
            params.index.to_string(),
            params.total.to_string(),
        ])
        .context("invalid chunk tag")?,
        tag("encryption", NOSTR_FILE_ENCRYPTION_LABEL)?,
        tag(
            "expiration",
            (params.created_at + NOSTR_FILE_EXPIRATION_SEC).to_string(),
        )?,
    ];
    EventBuilder::new(chunk_kind(), params.content)
        .tags(tags)
        .custom_created_at(Timestamp::from(params.created_at))
        .sign_with_keys(keys)
        .context("could not sign a chunk event")
}

/// A health-check probe in the production event shape — the same kind, tags,
/// expiration, codec, and size — namespaced under `probe:` so it can never
/// collide with a real transfer. A relay that caps event size below a real
/// chunk therefore fails here rather than by rejecting chunks mid-upload.
pub fn build_probe_event(keys: &Keys, content: String, now: u64) -> Result<(Event, String)> {
    let mut suffix = [0u8; 8];
    crate::crypto::chunk::fill_random(&mut suffix)?;
    let d_tag = format!(
        "probe:{}",
        suffix.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
    );
    let tags = vec![
        tag("d", d_tag.clone())?,
        tag("x", "probe")?,
        Tag::parse(["chunk".to_string(), "0".to_string(), "1".to_string()])
            .context("invalid chunk tag")?,
        tag("encryption", NOSTR_FILE_ENCRYPTION_LABEL)?,
        tag("expiration", (now + NOSTR_FILE_EXPIRATION_SEC).to_string())?,
    ];
    let event = EventBuilder::new(chunk_kind(), content)
        .tags(tags)
        .custom_created_at(Timestamp::from(now))
        .sign_with_keys(keys)
        .context("could not sign a probe event")?;
    Ok((event, d_tag))
}

/// Read an event as a chunk of this transfer, or refuse it.
///
/// Signature checking is the relay pool's job on receipt; what is checked here
/// is that the event says what it must say to be assembled — the author the
/// manifest named, this transfer, and a `d` tag that agrees with the index in
/// its own `chunk` tag. The GCM tag underneath is what actually binds the
/// content to that position; this only keeps a mislabelled event from being
/// decrypted against the wrong index in the first place.
pub fn parse_chunk_event<'a>(
    event: &'a Event,
    expected_pubkey: &PublicKey,
    transfer_id: &str,
) -> Option<(usize, &'a str)> {
    if event.kind != chunk_kind() || &event.pubkey != expected_pubkey {
        return None;
    }
    if tag_value(event, "x")? != transfer_id {
        return None;
    }
    let chunk_tag = event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().map(String::as_str) == Some("chunk"))?
        .as_slice();
    let index: usize = chunk_tag.get(1)?.parse().ok()?;
    if tag_value(event, "d")? != chunk_d_tag(transfer_id, index) {
        return None;
    }
    if event.content.is_empty() {
        return None;
    }
    Some((index, event.content.as_str()))
}

/// Filters fetching the given chunk indices by their derived `d` tags,
/// batched so one query stays around three megabytes of content.
pub fn chunk_filters(pubkey: &PublicKey, transfer_id: &str, indices: &[usize]) -> Vec<Filter> {
    indices
        .chunks(D_TAG_FILTER_BATCH)
        .map(|batch| {
            Filter::new()
                .kind(chunk_kind())
                .author(*pubkey)
                .identifiers(batch.iter().map(|index| chunk_d_tag(transfer_id, *index)))
                .limit(batch.len())
        })
        .collect()
}

fn tag(name: &str, value: impl Into<String>) -> Result<Tag> {
    Tag::parse([name.to_string(), value.into()]).context("invalid Nostr tag")
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().map(String::as_str) == Some(name))
        .and_then(|tag| tag.as_slice().get(1))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSFER_ID: &str = "c05587dba544d9543610d42f7b7b640d";

    fn chunk(index: usize) -> (Keys, Event) {
        let keys = Keys::generate();
        let event = build_chunk_event(
            &keys,
            ChunkEvent {
                transfer_id: TRANSFER_ID,
                index,
                total: 4,
                content: "0123456789".to_string(),
                created_at: 1_700_000_000,
            },
        )
        .unwrap();
        (keys, event)
    }

    /// The wire shape the two implementations meet on, tag by tag.
    #[test]
    fn a_chunk_event_is_the_shape_the_web_app_publishes() {
        let (_, event) = chunk(3);
        assert_eq!(event.kind, chunk_kind());
        assert_eq!(tag_value(&event, "d").unwrap(), "c05587dba544d9543610d42f7b7b640d:3");
        assert_eq!(tag_value(&event, "x").unwrap(), TRANSFER_ID);
        assert_eq!(tag_value(&event, "encryption").unwrap(), "aes-256-gcm");
        assert_eq!(
            tag_value(&event, "expiration").unwrap(),
            (1_700_000_000 + NOSTR_FILE_EXPIRATION_SEC).to_string()
        );
    }

    #[test]
    fn a_chunk_event_reads_back_as_its_own_index() {
        let (keys, event) = chunk(3);
        assert_eq!(
            parse_chunk_event(&event, &keys.public_key(), TRANSFER_ID),
            Some((3, "0123456789"))
        );
    }

    /// A relay answers whatever it likes. An event from another author,
    /// another transfer, or whose `d` tag disagrees with the index it claims
    /// is refused before anything is decrypted against that index.
    #[test]
    fn an_event_that_is_not_this_transfers_chunk_is_refused() {
        let (keys, event) = chunk(3);
        assert!(parse_chunk_event(&event, &Keys::generate().public_key(), TRANSFER_ID).is_none());
        assert!(parse_chunk_event(&event, &keys.public_key(), &"a".repeat(32)).is_none());

        let mismatched = EventBuilder::new(chunk_kind(), "content")
            .tags(vec![
                Tag::parse(["d".to_string(), chunk_d_tag(TRANSFER_ID, 1)]).unwrap(),
                Tag::parse(["x".to_string(), TRANSFER_ID.to_string()]).unwrap(),
                Tag::parse(["chunk".to_string(), "2".to_string(), "4".to_string()]).unwrap(),
            ])
            .sign_with_keys(&keys)
            .unwrap();
        assert!(parse_chunk_event(&mismatched, &keys.public_key(), TRANSFER_ID).is_none());
    }

    #[test]
    fn fetch_filters_are_batched() {
        let keys = Keys::generate();
        let indices: Vec<usize> = (0..120).collect();
        let filters = chunk_filters(&keys.public_key(), TRANSFER_ID, &indices);
        assert_eq!(filters.len(), 3);
    }
}
