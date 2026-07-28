# Architecture

`secure-send-cli` is a CLI client for `secure-send-web`. The web app is the source
of truth for protocol shape and compatibility.

## Modes

### Nostr PIN Mode

This is the default mode. The PIN authenticates the handshake; it derives no
content keys. Signaling and content keys come from an ephemeral P-256 ECDH
exchange.

**PIN and PIN root.** The PIN is 12 case-sensitive characters (11 data + 1
position-weighted checksum) from a 69-character alphabet that excludes
ambiguous `0`, `1`, `I`, `O`, `i`, `l`, and `o`. Entry preserves exact case
and filters unsupported characters. The PIN root is
`PBKDF2-SHA256(pin, "secure-send:pin-root:v2", 600k)`; every PIN-scoped value
is an HKDF-SHA256 expansion off it (salt
`secure-send:pin:v2`) with a distinct info label:

- `hint:<bucket>` — 16-hex-char event lookup tag, scoped to the 5-minute
  rotation bucket (`floor(now_ms / 300000)`).
- `auth` — AES-256-GCM key sealing the claim/confirm handshake payloads.
- `rendezvous` — AES-256-GCM key sealing the rendezvous payload.
- `fingerprint` — 12 lowercase hex chars, shown locally on both sides for a
  human visual check; never published.

**Rotation.** The sender mints and publishes a fresh PIN every 5 minutes
(`PIN_ROTATION_MS`), honors only PINs minted in its current or immediately
previous bucket, and attaches a NIP-40 expiration at the end of the PIN's
second bucket. The receiver derives hints for its current and previous buckets
and refuses rendezvous events older than the 10-minute maximum (`PIN_TTL_MS`).
The TUI `r` key (and the web app's
refresh button) mints a fresh PIN immediately, dropping all retained
generations. The sender keeps rotating for up to 30 minutes — a resource
backstop, not a security bound — before giving up.

**Handshake.**

1. Sender generates a 16-byte salt, transfer id, ephemeral Nostr key, and an
   ephemeral P-256 ECDH key pair; per rotation it publishes a kind `24243`
   rendezvous event:
   - `content`: `base64(nonce || ciphertext || tag)` sealed with the
     rendezvous key; payload carries `type=rendezvous`, transfer id, the
     sender's Nostr pubkey and ECDH public key (base64, 65-byte uncompressed),
     a fresh handshake nonce, relays, and file metadata.
   - tags: `h`, `s` (salt), `t`, `type=rendezvous`, `expiration`.
2. Receiver derives the hints, fetches matching kind `24243` events, decrypts
   the freshest candidate, and validates that the sealed payload names the
   event's own author and transfer id (a copied ciphertext republished under
   another identity is rejected).
3. Receiver publishes a kind `24242` claim (`type=claim`, tags `p=<sender>`,
   `t`) sealed with the auth key: it echoes the sender's nonce and ECDH key,
   and contributes a fresh receiver nonce and the receiver's ECDH public key.
4. Sender verifies the claim against every retained PIN generation, locks the
   transfer to the first valid claimant, stops rotating, and replies with a
   kind `24242` confirm (`type=confirm`) sealed with the same auth key,
   echoing both nonces and the receiver's ECDH key.
5. Both sides run ECDH and derive the session keys with HKDF-SHA256 over the
   shared X coordinate and the public transfer salt:
   `secure-send:nostr-session:v2:signals` (relay-carried WebRTC signaling) and
   `secure-send:nostr-session:v2:content` (P2P file chunks).
6. Sender and receiver exchange kind `24242` WebRTC signal events (`offer`,
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
7. File bytes transfer directly over the WebRTC data channel using the session
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
