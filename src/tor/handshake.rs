//! Password-authenticated handshake for the Tor onion transport.
//!
//! The receiver arrives holding exactly two things — the `.onion` address and
//! the password the sender printed — and the handshake turns those into a
//! mutually authenticated content key. It is the same SPAKE2 (RFC 9382) machinery
//! PIN Exchange uses, with the relay-shaped parts removed: there is no
//! rendezvous to look up and no third party to bind identities to, so the
//! address itself is the transfer identity ([`PakeIdentities::tor`]).
//!
//! ```text
//! receiver -> sender   hello    { version, pakeMessage: pB }
//! sender   -> receiver offer    { version, pakeMessage: pA, salt }
//! receiver -> sender   claim    { sealed }        <- proves the client knows the password
//! sender   -> receiver confirm  { sealed(metadata) } <- proves the service knows it too
//! receiver -> sender   ready | cancel
//! ```
//!
//! Neither seal can be opened by anyone who did not run this exact SPAKE2
//! session, so opening one *is* the key confirmation: a wrong password produces
//! two different roots and the claim simply fails to open. There is no
//! confirmation code for a human to compare, because there is nothing for one
//! to catch — unlike a PIN, which is short enough to be raced with a live
//! guess, the address and password together are only ever handed over as a
//! pair.
//!
//! Tor already authenticates the *service* to the client (the address is its
//! public key) and encrypts the stream end to end. This layer adds what that
//! cannot: proof the connecting client is the intended receiver rather than
//! anyone who came across the address.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::crypto::aes::{self, AES_KEY_LEN};
use crate::crypto::kdf::{SALT_LEN, TorSessionKeys, generate_salt};
use crate::crypto::spake2::{
    PAKE_MESSAGE_LEN, PakeIdentities, PakeRole, PakeRun, derive_pake_secret, is_valid_pake_message,
};
use crate::wire::TransferMetadata;

use super::wire::TorMessenger;

/// Version of this handshake. Bumped with any change to the frames below; a
/// mismatch is refused rather than negotiated, because there is exactly one
/// implementation and it ships as one binary.
pub const TOR_HANDSHAKE_VERSION: u32 = 1;

/// The frames the handshake exchanges, all as text frames carrying JSON.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum Frame {
    Hello {
        version: u32,
        /// SPAKE2 element pB (base64, 33-byte compressed P-256 point).
        #[serde(rename = "pakeMessage")]
        pake_message: String,
    },
    Offer {
        version: u32,
        /// SPAKE2 element pA (base64, 33-byte compressed P-256 point).
        #[serde(rename = "pakeMessage")]
        pake_message: String,
        /// Per-transfer HKDF salt (base64, 16 bytes).
        salt: String,
    },
    Claim {
        sealed: String,
    },
    Confirm {
        sealed: String,
    },
    Ready,
    Cancel,
}

/// Plaintext inside the receiver's sealed claim.
///
/// The seal is the proof; the body only restates what the seal is *about*, so
/// that a payload lifted from one direction or one address cannot be replayed
/// into another even if the keys ever collided.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimBody {
    #[serde(rename = "type")]
    body_type: String,
    version: u32,
    onion: String,
}

/// Plaintext inside the sender's sealed confirm: the same binding, plus what
/// the receiver is about to be handed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmBody {
    #[serde(rename = "type")]
    body_type: String,
    version: u32,
    onion: String,
    metadata: TransferMetadata,
}

const CLAIM_TYPE: &str = "claim";
const CONFIRM_TYPE: &str = "confirm";

/// How a client's connection to the onion service ended.
pub enum ServiceHandshake {
    /// The receiver authenticated and is ready to be sent the file.
    Ready(Box<TorSessionKeys>),
    /// The receiver authenticated and then declined — a destination conflict
    /// it cancelled, say. The password is untouched, so the service can keep
    /// waiting for it to come back.
    Cancelled,
}

/// What the receiver holds once the service has proved it knows the password.
pub struct ClientHandshake {
    pub keys: Box<TorSessionKeys>,
    pub metadata: TransferMetadata,
}

/// Run the onion service's side: authenticate the client, then tell it what is
/// on offer.
///
/// Every error here is one failed authentication from the caller's point of
/// view — a wrong password and a peer speaking gibberish are deliberately not
/// distinguished, because the difference is only ever useful to whoever is
/// guessing.
pub async fn run_service_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    messenger: &mut TorMessenger<S>,
    password: &str,
    onion: &str,
    metadata: &TransferMetadata,
) -> Result<ServiceHandshake> {
    let Frame::Hello {
        version,
        pake_message,
    } = recv_frame(messenger).await?
    else {
        bail!("expected a hello frame");
    };
    check_version(version)?;
    let peer_message = decode_pake_message(&pake_message)?;

    let run = PakeRun::start(PakeRole::Sender, &derive_pake_secret(password))?;
    let our_message = BASE64.encode(run.message());
    let salt = generate_salt()?;
    send_frame(
        messenger,
        &Frame::Offer {
            version: TOR_HANDSHAKE_VERSION,
            pake_message: our_message,
            salt: BASE64.encode(salt),
        },
    )
    .await?;

    let keys = run
        .finish(&peer_message, &PakeIdentities::tor(onion))?
        .tor_session_keys(&salt)?;

    // Opening the claim is the whole authentication: only a peer that ran this
    // SPAKE2 session against the same password holds the key that sealed it.
    let Frame::Claim { sealed } = recv_frame(messenger).await? else {
        bail!("expected a claim frame");
    };
    let claim: ClaimBody = open_sealed(&keys.claim, &sealed).context(
        "the receiver could not be authenticated: wrong password, or a different onion service",
    )?;
    if claim.body_type != CLAIM_TYPE || claim.version != TOR_HANDSHAKE_VERSION {
        bail!("the receiver sent an unexpected claim body");
    }
    if claim.onion != onion {
        bail!("the receiver authenticated against a different address");
    }

    send_frame(
        messenger,
        &Frame::Confirm {
            sealed: seal(
                &keys.confirm,
                &ConfirmBody {
                    body_type: CONFIRM_TYPE.to_string(),
                    version: TOR_HANDSHAKE_VERSION,
                    onion: onion.to_string(),
                    metadata: metadata.clone(),
                },
            )?,
        },
    )
    .await?;

    match recv_frame(messenger).await? {
        Frame::Ready => Ok(ServiceHandshake::Ready(Box::new(keys))),
        Frame::Cancel => Ok(ServiceHandshake::Cancelled),
        _ => bail!("expected the receiver to answer ready or cancel"),
    }
}

/// Run the connecting receiver's side, up to the point where it knows what it
/// is being offered. The caller then answers with [`send_ready`] or
/// [`send_cancel`].
pub async fn run_client_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    messenger: &mut TorMessenger<S>,
    password: &str,
    onion: &str,
) -> Result<ClientHandshake> {
    let run = PakeRun::start(PakeRole::Receiver, &derive_pake_secret(password))?;
    send_frame(
        messenger,
        &Frame::Hello {
            version: TOR_HANDSHAKE_VERSION,
            pake_message: BASE64.encode(run.message()),
        },
    )
    .await?;

    let Frame::Offer {
        version,
        pake_message,
        salt,
    } = recv_frame(messenger).await?
    else {
        bail!("expected an offer frame");
    };
    check_version(version)?;
    let peer_message = decode_pake_message(&pake_message)?;
    let salt = BASE64
        .decode(&salt)
        .context("the sender sent a malformed salt")?;
    if salt.len() != SALT_LEN {
        bail!("the sender sent a {}-byte salt", salt.len());
    }

    let keys = run
        .finish(&peer_message, &PakeIdentities::tor(onion))?
        .tor_session_keys(&salt)?;

    send_frame(
        messenger,
        &Frame::Claim {
            sealed: seal(
                &keys.claim,
                &ClaimBody {
                    body_type: CLAIM_TYPE.to_string(),
                    version: TOR_HANDSHAKE_VERSION,
                    onion: onion.to_string(),
                },
            )?,
        },
    )
    .await?;

    // A wrong password fails here, at the sender's confirm: the sender could
    // not open our claim, so it hangs up rather than answering, and this side
    // sees a closed stream rather than a rejection. Nothing is sent back that
    // would tell a guesser which of the two it was.
    let confirm = recv_frame(messenger)
        .await
        .context("the sender stopped answering after the claim; check the password")?;
    let Frame::Confirm { sealed } = confirm else {
        bail!("expected a confirm frame");
    };
    let confirm: ConfirmBody = open_sealed(&keys.confirm, &sealed)
        .context("the sender could not be authenticated: check the password")?;
    if confirm.body_type != CONFIRM_TYPE || confirm.version != TOR_HANDSHAKE_VERSION {
        bail!("the sender sent an unexpected confirm body");
    }
    if confirm.onion != onion {
        bail!("the sender authenticated against a different address");
    }
    if confirm.metadata.content_type != "file" {
        bail!("the sender describes unsupported content");
    }

    Ok(ClientHandshake {
        keys: Box::new(keys),
        metadata: confirm.metadata,
    })
}

/// Tell the sender to start sending.
pub async fn send_ready<S: AsyncRead + AsyncWrite + Unpin + Send>(
    messenger: &mut TorMessenger<S>,
) -> Result<()> {
    send_frame(messenger, &Frame::Ready).await
}

/// Tell the sender the transfer will not go ahead.
pub async fn send_cancel<S: AsyncRead + AsyncWrite + Unpin + Send>(
    messenger: &mut TorMessenger<S>,
) -> Result<()> {
    send_frame(messenger, &Frame::Cancel).await
}

fn check_version(version: u32) -> Result<()> {
    if version != TOR_HANDSHAKE_VERSION {
        bail!(
            "the peer speaks Tor transfer version {version}, this build speaks \
             {TOR_HANDSHAKE_VERSION}"
        );
    }
    Ok(())
}

fn decode_pake_message(encoded: &str) -> Result<Vec<u8>> {
    let message = BASE64
        .decode(encoded)
        .context("the peer sent a malformed PAKE element")?;
    // Screen the element before the scalar multiplication in `finish`.
    if !is_valid_pake_message(&message) {
        bail!("the peer sent a {PAKE_MESSAGE_LEN}-byte PAKE element that is not a curve point");
    }
    Ok(message)
}

fn seal<T: Serialize>(key: &[u8; AES_KEY_LEN], body: &T) -> Result<String> {
    Ok(BASE64.encode(aes::encrypt(key, &serde_json::to_vec(body)?)?))
}

fn open_sealed<T: for<'de> Deserialize<'de>>(key: &[u8; AES_KEY_LEN], sealed: &str) -> Result<T> {
    let sealed = BASE64.decode(sealed).context("malformed sealed payload")?;
    Ok(serde_json::from_slice(&aes::decrypt(key, &sealed)?)?)
}

async fn send_frame<S: AsyncRead + AsyncWrite + Unpin + Send>(
    messenger: &mut TorMessenger<S>,
    frame: &Frame,
) -> Result<()> {
    messenger.send_string(&serde_json::to_string(frame)?).await
}

async fn recv_frame<S: AsyncRead + AsyncWrite + Unpin + Send>(
    messenger: &mut TorMessenger<S>,
) -> Result<Frame> {
    let text = messenger.recv_string().await?;
    serde_json::from_str(&text).context("the peer sent an unrecognized handshake frame")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::WireEncoding;

    const ONION: &str = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion:9735";
    const PASSWORD: &str = "ABCDEFGHJKLA";

    fn metadata() -> TransferMetadata {
        TransferMetadata {
            content_type: "file".to_string(),
            file_name: "report.pdf".to_string(),
            file_size: 4096,
            content_encoding: WireEncoding::DeflateRaw,
            mime_type: "application/octet-stream".to_string(),
        }
    }

    /// Run both sides against each other over an in-memory duplex.
    async fn exchange(
        service_password: &str,
        client_password: &str,
        service_onion: &str,
        client_onion: &str,
    ) -> (Result<ServiceHandshake>, Result<ClientHandshake>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (mut service, mut client) = (TorMessenger::new(a), TorMessenger::new(b));

        let service_password = service_password.to_string();
        let service_onion = service_onion.to_string();
        let served = tokio::spawn(async move {
            let outcome =
                run_service_handshake(&mut service, &service_password, &service_onion, &metadata())
                    .await;
            // Hold the stream open until the client is done reading.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            outcome
        });

        let received = run_client_handshake(&mut client, client_password, client_onion).await;
        if received.is_ok() {
            send_ready(&mut client).await.unwrap();
        }
        (served.await.unwrap(), received)
    }

    #[tokio::test]
    async fn the_matching_password_agrees_on_keys_and_metadata() {
        let (served, received) = exchange(PASSWORD, PASSWORD, ONION, ONION).await;

        let ServiceHandshake::Ready(service_keys) = served.unwrap() else {
            panic!("the receiver should be ready");
        };
        let received = received.unwrap();
        assert_eq!(service_keys.content, received.keys.content);
        assert_eq!(received.metadata.file_name, "report.pdf");
        assert_eq!(received.metadata.content_encoding, WireEncoding::DeflateRaw);
    }

    #[tokio::test]
    async fn a_wrong_password_authenticates_neither_side() {
        let (served, received) = exchange(PASSWORD, "ABCDEFGHJKLZ", ONION, ONION).await;

        // The service refuses at the claim, and the client never sees a confirm.
        assert!(served.is_err());
        assert!(received.is_err());
    }

    #[tokio::test]
    async fn the_address_is_bound_into_the_session() {
        // Same password, but the client believes it reached a different
        // service — which is what a proxied handshake would look like.
        let other = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:9735";
        let (served, received) = exchange(PASSWORD, PASSWORD, ONION, other).await;

        assert!(served.is_err());
        assert!(received.is_err());
    }

    #[tokio::test]
    async fn a_receiver_may_decline_after_seeing_the_metadata() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (mut service, mut client) = (TorMessenger::new(a), TorMessenger::new(b));

        let served = tokio::spawn(async move {
            run_service_handshake(&mut service, PASSWORD, ONION, &metadata()).await
        });

        run_client_handshake(&mut client, PASSWORD, ONION)
            .await
            .unwrap();
        send_cancel(&mut client).await.unwrap();

        assert!(matches!(
            served.await.unwrap().unwrap(),
            ServiceHandshake::Cancelled
        ));
    }

    #[tokio::test]
    async fn a_version_mismatch_is_refused_rather_than_negotiated() {
        assert!(check_version(TOR_HANDSHAKE_VERSION).is_ok());
        assert!(check_version(TOR_HANDSHAKE_VERSION + 1).is_err());
    }

    #[test]
    fn a_pake_element_must_be_a_curve_point() {
        assert!(decode_pake_message("not base64!").is_err());
        assert!(decode_pake_message(&BASE64.encode([0u8; PAKE_MESSAGE_LEN])).is_err());
        assert!(decode_pake_message(&BASE64.encode([2u8; 8])).is_err());
    }

    #[test]
    fn a_seal_only_opens_under_its_own_key() {
        let body = ClaimBody {
            body_type: CLAIM_TYPE.to_string(),
            version: TOR_HANDSHAKE_VERSION,
            onion: ONION.to_string(),
        };
        let sealed = seal(&[3u8; AES_KEY_LEN], &body).unwrap();

        let opened: ClaimBody = open_sealed(&[3u8; AES_KEY_LEN], &sealed).unwrap();
        assert_eq!(opened.onion, ONION);
        assert!(open_sealed::<ClaimBody>(&[4u8; AES_KEY_LEN], &sealed).is_err());
    }
}
