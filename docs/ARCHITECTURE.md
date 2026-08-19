# Architecture

`secure-send-cli` is a CLI client for `secure-send-web`. The web app is the source
of truth for protocol shape and compatibility.

## Modes

### Nostr PIN Mode

This is the default mode. The PIN locates the sender's rendezvous event and
authenticates a SPAKE2 (RFC 9382, P-256) password-authenticated key exchange;
it derives no keys on its own. Signaling, content, handshake-seal, and
confirmation-code keys are all HKDF expansions off the SPAKE2 transcript root,
which mixes fresh ephemeral scalars from both sides.

**PIN and PAKE secret.** The PIN is 12 case-sensitive characters (11 data + 1
position-weighted checksum) from a 55-character alphabet of letters and digits
that excludes ambiguous `0`, `1`, `I`, `O`, `i`, `l`, and `o`. There are no
symbols. Entry preserves exact case and filters unsupported characters. Its
leading three characters are a public locator segment used only for relay
lookup, so effective strength is 55⁸ ≈ 46.3 bits.

- `hint:<bucket>` — 8-hex-character event lookup tag, derived by HKDF-SHA256
  (salt `secure-send:pin:v3`) directly from the public locator and scoped to the
  2-minute rotation bucket (`floor(now_ms / 120000)`). It is a candidate filter,
  not an authenticator, and carries at most ~17.3 bits, so collisions are
  expected.
- `w` — the SPAKE2 password scalar: `HKDF-SHA256(ikm = pin, salt =
  "secure-send:spake2-w:v3", info = "w", len = 48)` reduced mod the P-256 order
  and serialized as 32 big-endian bytes. There is deliberately **no** key
  stretching: stretching only helps against offline guessing, and a balanced
  PAKE leaves nothing to grind. Online guessing is metered instead — the sender
  runs at most `CLAIM_VERIFY_LIMIT` (100) claim verifications per PIN
  generation, and the receiver claims at most `MAX_CLAIM_CANDIDATES` (8)
  rendezvous candidates per attempt.

**Rotation.** The sender mints and publishes a fresh PIN every 2 minutes
(`PIN_ROTATION_MS`), honors only PINs minted in its current or immediately
previous bucket, and attaches a NIP-40 expiration at the end of the PIN's
second bucket. The receiver derives hints for its current and previous buckets
and refuses rendezvous events older than the 4-minute maximum (`PIN_TTL_MS`).
The TUI `r` key (and the web app's
refresh button) mints a fresh PIN immediately, dropping all retained
generations. The sender keeps rotating for up to 30 minutes — a resource
backstop, not a security bound — before giving up.

**Handshake.**

1. Sender generates a 16-byte salt, transfer id, and ephemeral Nostr key. Per
   rotation it mints a fresh PIN, starts a fresh SPAKE2 run
   (`pA = x·G + w·M`), and publishes a kind `24243` rendezvous event:
   - `content`: **plaintext** JSON with `type=rendezvous`, transfer id, the
     sender's Nostr pubkey, `pakeMessage` (base64, 33-byte compressed P-256
     point), a fresh handshake nonce, and relays. Encrypting it under a
     PIN-derived key would reintroduce the offline guessing target the PAKE
     removes, so it is not encrypted — and file metadata is deliberately absent.
   - tags: `h`, `s` (salt), `t`, `type=rendezvous`, `expiration`.
2. Receiver derives the hints, fetches matching kind `24243` events, and keeps
   up to 8 structurally valid candidates (newest first, one per transfer id):
   the payload must name the event's own author and transfer id, and its
   element must be a valid non-identity curve point. Nothing distinguishes the
   real sender yet — the rendezvous is plaintext and proves nothing.
3. For each candidate the receiver runs its side of the PAKE
   (`pB = y·G + w·N`), finishes it against the candidate's element, and
   computes a versioned SHA-256 transcript over the rendezvous type, transfer
   id, sender identity, element, nonce, relays, and salt. It publishes one kind
   `24242` claim per candidate (`type=claim`, tags `p=<sender>`, `t`) whose
   content is `{"sealed":<base64>,"pake":<base64 pB>}`: the body is sealed with
   the session's `claim` key, and `pB` rides in plaintext because the sender
   must finish its own side before any key exists. The body echoes the sender
   nonce, contributes a fresh receiver nonce, and binds both Nostr identities
   plus the transcript hash.
4. Sender verifies the claim against every retained PIN generation whose bucket
   is still active and whose verification budget remains — each attempt spends
   one unit of `CLAIM_VERIFY_LIMIT`, which is the online-guessing meter. It
   finishes the SPAKE2 run against `pB`, derives the seal keys, and tries the
   claim seal. The first claim that opens *and* matches the generation's nonce,
   the transfer id, both identities, and the generation's transcript hash locks
   the transfer; rotation stops and every other claim is ignored. Invalid claims
   are silently ignored, never fatal.
5. Sender publishes the kind `24242` confirm (`type=confirm`) **immediately** on
   verification, sealed with the session's `confirm` key. It echoes both nonces,
   both identities, and the transcript hash, and it delivers the file metadata
   (`contentType`, `fileName`, `fileSize`, `fileSizeExact`, `mimeType`). The
   receiver allows 60 seconds for it and verifies every echoed field.
6. Both sides derive an 8-character Crockford Base32 confirmation code from 40
   HKDF-SHA256 bits over the SPAKE2 root with info
   `secure-send:nostr-session:v3:confirmation|<transfer-id>|<sender-nonce>|<receiver-nonce>|<transcript-hash>|<metadata-hash>`,
   where the metadata hash is a versioned SHA-256 digest of the confirmed
   metadata. The receiver displays it; the sender publishes no WebRTC signal and
   no file byte until its operator enters a normalized match, waiting up to 150
   seconds. A mismatch is retryable. The receiver allows 180 seconds for the
   sender's first signal, which is how it learns the code matched.
7. Both sides derive the session keys with HKDF-SHA256 over the SPAKE2
   transcript root and the public transfer salt:
   `secure-send:nostr-session:v3:signals` (relay-carried WebRTC signaling) and
   `secure-send:nostr-session:v3:content` (P2P file chunks). The claim/confirm
   seal keys use the `:claim` and `:confirm` labels off the same root.
8. Sender and receiver exchange kind `24242` WebRTC signal events (`offer`,
   `answer`, `candidate`), encrypted with the session signals key.
   - Signal events use tags `t`, `p=<sender pubkey>`, and `type=signal`.
   - Sender-side answer subscriptions filter by `t`, `p=<sender pubkey>`, and
     receiver author.
   - Receiver-side offer subscriptions filter by `t` and sender author only,
     matching `secure-send-web`.
   - Offer and answer bundles are republished while the P2P connection is
     pending so relay misses do not strand the session, and each bundle's
     events are published concurrently so one slow relay does not serialize
     the exchange.
9. File bytes transfer directly over the WebRTC data channel using the session
   content key. Completion is the data channel `ACK`; no relay event is
   published after signaling.

Default relays match `secure-send-web`. Transport is direct-only: STUN servers
assist NAT traversal, but no TURN relay is configured, so a transfer fails
rather than route file bytes through a relay.

### Manual SS03 Mode

Manual mode is explicit: `send --manual` and `receive --manual`.

The signaling payload is the web app's SS03 format:

```text
JSON -> raw DEFLATE -> "mag!" || compressed -> time-bucket XOR
     -> "SS03" || obfuscated -> standard base64
```

Manual offer payloads contain SDP, ICE candidate strings, file metadata,
`fileSizeExact` (false for a streamed ZIP whose advertised size is an input
estimate), created-at timestamp, sender P-256 public key, and salt. Manual
answer payloads contain SDP, ICE candidate strings, created-at timestamp, and
receiver P-256 public key.

Both sides derive the AES content key with:

```text
HKDF-SHA256(
  ikm = P-256 ECDH shared X coordinate,
  salt = offer salt,
  info = "secure-send-mutual",
  len = 32
)
```

## Data Channel Protocol

Each plaintext chunk is at most 128 KiB. Each encrypted binary data-channel
message is:

```text
2-byte chunk index (big-endian) || 12-byte nonce || ciphertext || 16-byte tag
```

The chunk index is also AES-GCM additional authenticated data.

After all chunks, the sender sends:

```text
DONE:<total_chunks>:<total_bytes>
```

The final byte count authenticates the length of streamed ZIPs, whose output
size was not known during signaling. The receiver authenticates and persists
the full file, then replies:

```text
ACK
```

Active P2P transfers use a 60-second idle/stall window rather than an overall
wall-clock deadline. The sender applies the window to each chunk hand-off while
waiting for WebRTC backpressure to clear and sending the message. The receiver
arms the same window once the data channel is open and resets it for every
incoming data-channel message, including
`DONE:<total_chunks>:<total_bytes>`.

The maximum transfer size is 2 GiB (`MAX_MESSAGE_SIZE`), matching
`secure-send-web`; both ends stream chunk by chunk, so the bound is not RAM.
For multi-file/folder sends the CLI walks and validates the selection first,
then starts a store-mode ZIP writer only after the data channel opens. A
bounded channel applies backpressure between blocking file reads/ZIP output
and async encryption/WebRTC sends, so no complete archive or temporary ZIP is
created. The advertised ZIP size is the input byte count as a progress hint;
the sender enforces the limit against actual output and seals the final length
in `DONE`.

## Scope

The CLI intentionally has no legacy signaling protocol, no resume path, no QR
support, no relay discovery, and no custom fallback mode.
