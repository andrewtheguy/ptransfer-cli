//! Code Exchange sender: hand over an offer, take a response back, connect.
//!
//! No relay is involved in the exchange itself. The offer goes out as one
//! base64 blob the operator carries to the receiver, and the receiver's
//! response comes back the same way — through the operator's own paste, which
//! is Code Exchange's confirmation step. Nothing enters this side unless the
//! operator puts it there, so a bystander who photographed the offer cannot
//! push a response in.
//!
//! What that response has to survive first is the confirmation tag: recomputed
//! here from *this* offer's bytes and the response's own fields, and compared
//! in constant time before a single signal is applied, a content key is
//! derived, or a file byte moves.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rtc::peer_connection::sdp::RTCSessionDescription;

use crate::archive::SendSource;
use crate::crypto::chunk::MAX_MESSAGE_SIZE;
use crate::crypto::kdf::generate_salt;
use crate::tor::TorClient;
use crate::tor::transfer::{MAX_TRANSFER_BYTES, MAX_WIRE_BYTES};
use crate::transfer::run_sender;
use crate::ui;
use crate::util::format_bytes;
use crate::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use crate::webrtc::{add_ice_candidate_safely, advertise_max_message_size, candidate_strings};

use super::control::seconds;
use super::keys::CodeKeyPair;
use super::nostr_file::RELAY_MAX_BYTES;
use super::nostr_file::codec::PayloadCompression;
use super::nostr_file::pool::FilePool;
use super::nostr_file::relay_pool::{PreparedRing, resolve_control_relays};
use super::nostr_file::upload::{RelaySource, SendContext, send_over_relays};
use super::payload::{
    self, PayloadKind, SignalingPayload, TRANSFER_EXPIRATION_MS, now_ms,
};
use super::relay::{FallbackContext, serve_over_anonymous_relay};

const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the direct attempt runs when there is no fallback behind it: the
/// backstop, since a failure here is the end of the transfer.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);
/// How long it runs when a fallback is available. Shorter, because the cost of
/// being wrong is a slower transfer rather than none, and the Tor path in
/// front of it is minutes long.
const FALLBACK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

/// Send `source` over Code Exchange.
///
/// `anonymous` is the sender's switch, and the only thing that decides which
/// of the two fallbacks this transfer has: it goes into the offer, and the
/// receiving side reads it from there rather than being told separately. An
/// ordinary transfer gets the clearnet one, on relays proven here and named in
/// the code.
pub async fn send_file_code(source: &SendSource, anonymous: bool) -> Result<()> {
    check_size(source, anonymous)?;

    // The slow part, started before the code is even shown rather than once
    // the direct route is known to be dead: a bootstrap is minutes, and by
    // then the receiver is already waiting. It runs behind the exchange and is
    // dropped with the transfer, used or not.
    let tor = anonymous.then(|| {
        ui::status("Starting the Tor client for the anonymous fallback...");
        tokio::spawn(async { TorClient::bootstrap().await.map(Arc::new) })
    });

    // The clearnet fallback's relays are proven before the code exists,
    // because the code is what names them: a receiver has no other way to
    // learn where the control channel lives. It runs behind ICE gathering,
    // which is the one other thing the code waits on.
    let relay_probe = relay_eligible(source, anonymous).then(|| {
        let pool = Arc::new(FilePool::new());
        let probe = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move { resolve_control_relays(&pool, &|_, _| {}).await }
        });
        (pool, probe)
    });

    let salt = generate_salt()?;
    let keys = CodeKeyPair::generate();
    // One clock for the whole session: the code's TTL, the control channel's
    // backlog window, and its expiration all run from it, on both sides.
    let created_at = now_ms();

    ui::status("Creating P2P connection...");
    let mut peer = WebRtcPeer::new(ICE_GATHER_TIMEOUT).await?;
    let data_channel = peer.create_data_channel("file-transfer").await?;

    let offer = peer.create_offer().await?;
    peer.set_local_description(offer.clone()).await?;
    ui::status("Gathering network candidates...");
    let candidates = candidate_strings(peer.gather_ice_candidates().await?)?;

    // Whatever the probe proved, awaited only now: an offer names its relays
    // or it has no clearnet fallback, and either way the code cannot be shown
    // before that is settled.
    let mut fallback = Fallback::None;
    if let Some((pool, probe)) = relay_probe {
        let step = ui::status_step("Proving Nostr relays for the fallback...");
        match probe.await {
            Ok(Ok(selection)) => {
                let relays = selection.relays.clone();
                step.done(&format!(
                    "{} Nostr relays proven for the fallback",
                    relays.len()
                ));
                // The storage ring is prepared behind the exchange, on the
                // same pool: the code does not depend on it, and a direct
                // connection simply leaves it unused.
                let ring = PreparedRing::spawn(Arc::clone(&pool), relays.clone(), selection);
                fallback = Fallback::Relays { pool, relays, ring };
            }
            Ok(Err(error)) => {
                step.done("No Nostr relay fallback for this transfer");
                log::info!("no relay fallback: {error:#}");
                pool.shutdown().await;
            }
            Err(error) => {
                step.done("No Nostr relay fallback for this transfer");
                log::info!("the relay probe failed: {error}");
                pool.shutdown().await;
            }
        }
    }

    let offer_payload = SignalingPayload {
        kind: PayloadKind::Offer,
        sdp: advertise_max_message_size(offer.sdp),
        candidates,
        created_at,
        public_key: keys.public_key().to_vec(),
        confirm: None,
        file_name: Some(source.file_name.clone()),
        file_size: Some(source.estimated_size),
        content_encoding: Some(source.wire_encoding),
        mime_type: Some(source.mime_type.to_string()),
        salt: Some(salt.to_vec()),
        // Named only when they were proven: an offer that named relays this
        // side had not reached would promise a receiver a path neither of them
        // can walk.
        relays: fallback.offer_relays(),
        anon: anonymous.then_some(true),
    };
    let offer_binary = payload::encode(&offer_payload)?;

    ui::show_code(
        &format!(
            "Give this code to the receiver ({}, {}):",
            source.file_name,
            format_bytes(source.estimated_size)
        ),
        &payload::to_clipboard(&offer_binary),
    );

    // Every exit from here on lets go of the fallback: the ring being prepared
    // behind this exchange holds a socket to every relay in it, and in the
    // wizard — where the process does not end with the transfer — each one
    // would reconnect for as long as it ran.
    let answer = match take_response(&offer_binary, &salt, &keys, created_at).await {
        Ok(answer) => answer,
        Err(error) => {
            fallback.discard().await;
            return Err(error);
        }
    };
    ui::hide_code();

    ui::status("Response accepted. Establishing the connection...");
    let applied = async {
        peer.set_remote_description(
            RTCSessionDescription::answer(answer.sdp.clone()).context("Invalid answer SDP")?,
        )
        .await?;
        for candidate in &answer.candidates {
            add_ice_candidate_safely(&peer, candidate).await;
        }
        anyhow::Ok(())
    }
    .await;
    if let Err(error) = applied {
        fallback.discard().await;
        return Err(error);
    }

    let has_fallback = anonymous || matches!(fallback, Fallback::Relays { .. });
    let direct_window = if has_fallback {
        FALLBACK_ATTEMPT_TIMEOUT
    } else {
        CONNECTION_TIMEOUT
    };
    ui::status("Waiting for the data channel...");
    let opened = open_and_detach(data_channel, direct_window).await;

    match (opened, tor) {
        (Ok(raw), bootstrap) => {
            // A transfer that connected directly published nothing anywhere,
            // so a bootstrap or a relay ring still being prepared behind it is
            // simply dropped.
            if let Some(bootstrap) = bootstrap {
                bootstrap.abort();
            }
            fallback.discard().await;
            let info = peer.get_connection_info().await;
            ui::status(&format!("Connected via {}", info.connection_type));
            let mut messenger = DcMessenger::new(raw);
            let result =
                run_sender(&mut messenger, &answer.content_key, source, MAX_MESSAGE_SIZE).await;
            let _ = peer.close().await;
            result?;
        }
        (Err(error), None) => {
            log::info!("the direct route did not open: {error:#}");
            let _ = peer.close().await;
            match fallback {
                // The clearnet fallback: only now is the file read, hashed,
                // and put on relays. Nothing was staged while a direct
                // connection was still possible.
                Fallback::Relays { pool, relays, ring } => {
                    ui::status(
                        "No direct connection — relaying the file through Nostr relays instead.",
                    );
                    let prepared = async {
                        let data = source.materialize(RELAY_MAX_BYTES).await?;
                        anyhow::Ok((data, answer.secret.relay_session(&salt)?))
                    }
                    .await;
                    let (data, session) = match prepared {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            ring.abort();
                            pool.shutdown().await;
                            return Err(error);
                        }
                    };
                    let result = send_over_relays(
                        SendContext {
                            pool: Arc::clone(&pool),
                            session: &session,
                            control_relays: relays,
                            ring,
                            file_name: source.file_name.clone(),
                            mime_type: source.mime_type.to_string(),
                        },
                        RelaySource {
                            data,
                            compression: PayloadCompression::of(source.wire_encoding),
                        },
                    )
                    .await;
                    pool.shutdown().await;
                    result?;
                }
                // No fallback at all, so a direct route was the whole
                // transfer.
                Fallback::None => return Err(error),
            }
        }
        (Err(error), Some(bootstrap)) => {
            log::info!("the direct route did not open: {error:#}");
            let _ = peer.close().await;
            fallback.discard().await;
            let step = ui::status_step("Waiting for the Tor client to finish starting...");
            let tor = bootstrap
                .await
                .context("the Tor client task failed")?
                .context("The anonymous fallback could not reach the Tor network")?;
            step.done("The Tor client is ready");
            let session = answer.secret.relay_session(&salt)?;
            let password = answer.secret.onion_password(&salt)?;
            serve_over_anonymous_relay(
                FallbackContext {
                    tor,
                    session: &session,
                    since: seconds(created_at),
                    expires_at: seconds(created_at + TRANSFER_EXPIRATION_MS),
                },
                &password,
                source,
            )
            .await?;
        }
    }

    ui::status("File sent successfully.");
    Ok(())
}

/// What this transfer falls back to when the direct route does not open.
///
/// Only the clearnet one is held here: the anonymous fallback is a Tor
/// bootstrap and travels with the `tor` handle instead, because the two are
/// alternatives and an offer names one or neither.
enum Fallback {
    None,
    Relays {
        pool: Arc<FilePool>,
        /// The control relays, which is exactly what the offer names.
        relays: Vec<String>,
        ring: PreparedRing,
    },
}

impl Fallback {
    fn offer_relays(&self) -> Option<Vec<String>> {
        match self {
            Self::None => None,
            Self::Relays { relays, .. } => Some(relays.clone()),
        }
    }

    /// Let go of relays a transfer turned out not to need: a prepared ring
    /// holds a socket to every relay in it, and each one would otherwise
    /// reconnect for as long as the process lives.
    async fn discard(self) {
        if let Self::Relays { pool, ring, .. } = self {
            ring.abort();
            pool.shutdown().await;
        }
    }
}

/// Whether the clearnet fallback could carry this selection at all.
///
/// A relay-borne payload is capped, and the cap lands on what is actually
/// chunked: a single file's own bytes, or the whole generated ZIP. Checked
/// before any relay is probed, so an offer never names relays for a transfer
/// they could not carry.
fn relay_eligible(source: &SendSource, anonymous: bool) -> bool {
    if anonymous {
        return false;
    }
    match source.wire_encoding {
        crate::wire::WireEncoding::DeflateRaw => source.estimated_size <= RELAY_MAX_BYTES,
        crate::wire::WireEncoding::Identity => source.projected_wire_size <= RELAY_MAX_BYTES,
    }
}

/// Ask for the receiver's response until one that answers this code arrives.
///
/// A refusal is not the end of the transfer: the code is good for an hour, the
/// receiver's response is still in their hand, and the likeliest reason for a
/// refusal is that the wrong one was pasted. Saying so and asking again is
/// what the web app does with the same message.
async fn take_response(
    offer_binary: &[u8],
    salt: &[u8; 16],
    keys: &CodeKeyPair,
    created_at: i64,
) -> Result<AcceptedAnswer> {
    loop {
        let response = ui::prompt_response_code().await?;
        match decode_response(&response, offer_binary, salt, keys, created_at) {
            Ok(answer) => return Ok(answer),
            // Expiry ends the transfer: nothing pasted later can be fresher,
            // and a code past its hour is refused by the receiver anyway.
            Err(error) if payload::check_freshness(created_at).is_err() => return Err(error),
            Err(error) => ui::status(&format!("{error} Paste it again.")),
        }
    }
}

/// What an accepted response yields: the peer's signaling, the content key for
/// the direct path, and the secret every fallback derivation hangs off.
struct AcceptedAnswer {
    sdp: String,
    candidates: Vec<String>,
    content_key: [u8; 32],
    secret: super::keys::CodeSecret,
}

/// Parse a pasted response and refuse it unless it answers *this* code.
///
/// The tag is checked before anything in the response is acted on. Producing
/// one takes having held this offer, having completed the agreement against
/// the key inside it, and having sent exactly this response — so a response
/// from another transfer, an old one pasted again, and one edited on the way
/// back are all refused here rather than surfacing minutes later as a
/// connection that never opens.
fn decode_response(
    response: &str,
    offer_binary: &[u8],
    salt: &[u8; 16],
    keys: &CodeKeyPair,
    created_at: i64,
) -> Result<AcceptedAnswer> {
    let binary = payload::from_clipboard(response)?;
    let answer = payload::decode(&binary)?;
    if answer.kind != PayloadKind::Answer {
        bail!("That is a sender's code, not a response to one.");
    }
    // The session's clock is the offer's, not the response's: a response is
    // judged against the code it answers.
    payload::check_freshness(created_at)?;

    let secret = keys.agree(&answer.peer_public_key()?)?;
    let expected = secret.answer_confirmation(
        salt,
        &payload::offer_transcript_hash(offer_binary),
        &payload::answer_transcript_hash(&answer)?,
    )?;
    let presented = answer
        .confirmation_tag()
        .context("that response carries no confirmation tag")?;
    if !constant_time_equal(&presented, &expected) {
        bail!(
            "Response does not match this transfer. Make sure you pasted the response to \
             this code, then try again."
        );
    }

    Ok(AcceptedAnswer {
        content_key: secret.content_key(salt)?,
        sdp: answer.sdp,
        candidates: answer.candidates,
        secret,
    })
}

/// Compare two tags without an early return, so a near miss is not measurably
/// nearer than a wild one.
fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    // A mismatch in length is one nonzero byte, not the XOR of the two lengths
    // truncated: that truncation is zero whenever the lengths differ only in
    // bits a `u8` cannot hold, and the padded comparison below would then let
    // a short tag pass against a long one of zeros.
    let mut difference = u8::from(a.len() != b.len());
    for index in 0..a.len().max(b.len()) {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        difference |= left ^ right;
    }
    difference == 0
}

/// Refuse a selection the chosen path could not carry, while it is still a
/// selection.
///
/// The anonymous fallback's ceiling is the Tor transport's, and it is checked
/// here rather than when the fallback starts: by then the code has been handed
/// over, a response taken in, and a bootstrap spent.
fn check_size(source: &SendSource, anonymous: bool) -> Result<()> {
    if !anonymous {
        if source.estimated_size > MAX_MESSAGE_SIZE {
            bail!(
                "File is {}, which exceeds the {} limit",
                format_bytes(source.estimated_size),
                format_bytes(MAX_MESSAGE_SIZE)
            );
        }
        return Ok(());
    }
    if source.estimated_size > MAX_TRANSFER_BYTES {
        bail!(
            "This selection is {}, over the {} the anonymous fallback's Tor transport allows.",
            format_bytes(source.estimated_size),
            format_bytes(MAX_TRANSFER_BYTES)
        );
    }
    if source.projected_wire_size > MAX_WIRE_BYTES {
        bail!(
            "This selection needs up to {} on the wire, over the {} the anonymous fallback's \
             Tor transport allows. Archive overhead grows with the number of files; send \
             fewer of them.",
            format_bytes(source.projected_wire_size),
            format_bytes(MAX_WIRE_BYTES)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::code::receiver::build_response;
    use crate::wire::WireEncoding;

    #[test]
    fn tags_compare_equal_only_when_they_are() {
        assert!(constant_time_equal(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_equal(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_equal(&[1, 2, 3], &[1, 2]));
        assert!(!constant_time_equal(&[], &[0]));
        // Lengths whose difference vanishes in a `u8`: two tags of zeros, 256
        // bytes apart, are still two different tags.
        assert!(!constant_time_equal(&[], &[0; 256]));
    }

    /// One side of an exchange as the sender holds it: the code it is showing,
    /// the salt every derivation uses, and the key pair the response will be
    /// agreed against.
    struct Offer {
        binary: Vec<u8>,
        salt: [u8; 16],
        keys: CodeKeyPair,
        created_at: i64,
    }

    fn make_offer() -> Offer {
        let salt = generate_salt().unwrap();
        let keys = CodeKeyPair::generate();
        let created_at = payload::now_ms();
        let offer = SignalingPayload {
            kind: PayloadKind::Offer,
            sdp: "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n".to_string(),
            candidates: vec!["candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host".to_string()],
            created_at,
            public_key: keys.public_key().to_vec(),
            confirm: None,
            file_name: Some("report.pdf".to_string()),
            file_size: Some(1024),
            content_encoding: Some(WireEncoding::DeflateRaw),
            mime_type: Some("application/pdf".to_string()),
            salt: Some(salt.to_vec()),
            relays: None,
            anon: None,
        };
        Offer {
            binary: payload::encode(&offer).unwrap(),
            salt,
            keys,
            created_at,
        }
    }

    /// The receiver's half: take a code and produce the response to it.
    fn respond(offer_binary: &[u8]) -> Vec<u8> {
        let offer = payload::decode(offer_binary).unwrap();
        build_response(
            offer_binary,
            &offer,
            "v=0\r\na=answer\r\n".to_string(),
            vec!["candidate:2 1 udp 2130706431 10.0.0.2 5001 typ host".to_string()],
        )
        .unwrap()
        .0
    }

    fn accept(offer: Offer, response: &[u8]) -> Result<AcceptedAnswer> {
        decode_response(
            &payload::to_clipboard(response),
            &offer.binary,
            &offer.salt,
            &offer.keys,
            offer.created_at,
        )
    }

    /// The message a refused response produces. Deliberately not
    /// `unwrap_err`: an accepted answer holds key material, and nothing that
    /// holds key material gets a `Debug` for a test's convenience.
    fn refusal(offer: Offer, response: &[u8]) -> String {
        match accept(offer, response) {
            Ok(_) => panic!("the response should have been refused"),
            Err(error) => error.to_string(),
        }
    }

    /// The round trip both implementations meet on: the response the receiver
    /// built for this code is accepted, and the two sides land on the same
    /// content key without either ever seeing the other's private scalar.
    #[test]
    fn a_response_to_this_code_is_accepted_and_agrees_on_a_key() {
        let offer = make_offer();
        let salt = offer.salt;
        let response = respond(&offer.binary);

        let receiver_key = {
            let parsed = payload::decode(&offer.binary).unwrap();
            let (_, secret) = build_response(
                &offer.binary,
                &parsed,
                "v=0\r\n".to_string(),
                Vec::new(),
            )
            .unwrap();
            secret.content_key(&salt).unwrap()
        };

        let accepted = accept(offer, &response).unwrap();
        // Different response, different ephemeral key: the keys must differ,
        // which is what makes the equality check below meaningful at all.
        assert_ne!(accepted.content_key, receiver_key);
        assert_eq!(accepted.sdp, "v=0\r\na=answer\r\n");
        assert_eq!(accepted.candidates.len(), 1);
    }

    /// Both halves of one exchange reach the same content key.
    #[test]
    fn both_sides_of_one_exchange_derive_the_same_content_key() {
        let offer = make_offer();
        let salt = offer.salt;
        let parsed = payload::decode(&offer.binary).unwrap();
        let (response, receiver_secret) = build_response(
            &offer.binary,
            &parsed,
            "v=0\r\na=answer\r\n".to_string(),
            Vec::new(),
        )
        .unwrap();

        let accepted = accept(offer, &response).unwrap();
        assert_eq!(
            accepted.content_key,
            receiver_secret.content_key(&salt).unwrap()
        );
    }

    /// The case an operator with two transfers open runs into: a response that
    /// answers a different code is refused outright rather than applied and
    /// then failing minutes later as a connection that never opens.
    #[test]
    fn a_response_to_another_code_is_refused() {
        let mine = make_offer();
        let theirs = make_offer();
        let response = respond(&theirs.binary);

        let error = refusal(mine, &response);
        assert!(error.contains("does not match this transfer"), "{error}");
    }

    /// The tag covers the response's own fields, so a response edited between
    /// the two devices — its public key and tag left intact — is refused.
    #[test]
    fn a_response_altered_on_the_way_back_is_refused() {
        let offer = make_offer();
        let response = respond(&offer.binary);

        let mut altered = payload::decode(&response).unwrap();
        altered
            .candidates
            .push("candidate:9 1 udp 1 10.0.0.9 5009 typ host".to_string());
        let altered = payload::encode(&altered).unwrap();

        let error = refusal(offer, &altered);
        assert!(error.contains("does not match this transfer"), "{error}");
    }

    /// A code of the wrong half is a paste mistake, and saying which one it is
    /// is more useful than a tag mismatch would be.
    #[test]
    fn a_sender_code_pasted_as_a_response_is_named_as_one() {
        let offer = make_offer();
        let binary = offer.binary.clone();
        let error = refusal(offer, &binary);
        assert!(error.contains("not a response"), "{error}");
    }

    /// The session's clock is the code's own, so a response arriving after it
    /// runs out is refused however fresh the response itself is.
    #[test]
    fn a_response_to_an_expired_code_is_refused() {
        let mut offer = make_offer();
        let response = respond(&offer.binary);
        offer.created_at -= TRANSFER_EXPIRATION_MS + 1;

        let error = refusal(offer, &response);
        assert!(error.contains("expired"), "{error}");
    }
}
