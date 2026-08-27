# Architecture

`ptransfer-cli` provides the `ptransfer` command-line client for pTransfer.

The normative wire contract is the web app's `docs/INTEROP_PROTOCOL.md`, which
specifies PIN Exchange and the shared data-channel transfer layer and carries an
interop protocol version independent of pTransfer's app version. This build
implements version `1` (`package.metadata.ptransfer-protocol-version`). This
document describes how the CLI realizes that contract; where the two disagree,
the spec wins.

The web app's Code Exchange — hand-carried QR/clipboard offer and answer codes —
is deliberately outside that contract while it is still taking shape, and is not
implemented here. PIN exchange is the CLI's only signaling mode. The wizard's
mode menu still lists Code Exchange in the web app's position, so a mode's
number means the same thing in both interfaces; selecting it reports that it is
not implemented and goes no further.

## PIN Exchange

The PIN locates the sender's rendezvous event and
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
  (salt `ptransfer:pin:v4`) directly from the public locator and scoped to the
  2-minute rotation bucket (`floor(now_ms / 120000)`). It is a candidate filter,
  not an authenticator, and carries at most ~17.3 bits, so collisions are
  expected.
- `w` — the SPAKE2 password scalar: `HKDF-SHA256(ikm = pin, salt =
  "ptransfer:spake2-w:v4", info = "w", len = 48)` reduced mod the P-256 order
  and serialized as 32 big-endian bytes. There is deliberately **no** key
  stretching: stretching only helps against offline guessing, and a balanced
  PAKE leaves nothing to grind. Online guessing is metered instead — the sender
  runs at most `CLAIM_VERIFY_LIMIT` (100) claim verifications per PIN
  generation, and the receiver publishes at most `MAX_CLAIM_ATTEMPTS` (16)
  claims per attempt (`MAX_CLAIM_CANDIDATES` (8) initial candidates plus
  re-claims).

**Single-use rendezvous elements.** Every SPAKE2 ephemeral scalar is used for
exactly one protocol execution, on both sides, as RFC 9382 §7 requires
("Randomly generated values, e.g., x and y, MUST NOT be reused"). The receiver
picks a fresh `y` for every claim it publishes. The sender picks a fresh `x`
for every rendezvous element it publishes, and each published element is
consumed by the **first claim that targets it** — the sender finishes the run
once, against that claim's `pB`, whether or not the claim verifies.
`PakeRun::finish` takes `self`, so a second finish of the same scalar does not
compile.

Two mechanisms make that workable with a broadcast rendezvous:

- Claims carry a plaintext `target` field: the transcript hash of the exact
  rendezvous the claim was derived against. It routes the claim to the one
  element it spends, so a claim naming a spent, expired, or foreign target
  costs the sender nothing (no curve work, no budget). The target carries no
  authority — the sealed claim body echoes the same hash, and that echo is
  what is verified — and leaks nothing, being a hash of already-public data.
- When a claim consumes an element without verifying, the sender immediately
  publishes a **replacement rendezvous** for the same PIN generation: fresh
  `x`, fresh element, fresh nonce, same transfer id, hint, bucket, and salt.
  The receiver keeps a live subscription on its hints while waiting for the
  confirm; a replacement authored by the same key as a rendezvous it already
  claimed is re-claimed with a fresh `y`, up to `MAX_CLAIM_ATTEMPTS` total
  claims. So an honest receiver that lost the race to a junk claim converges
  on the transfer instead of timing out.

The guessing economics are unchanged: every verification the sender runs is
still exactly one online PIN guess, metered by `CLAIM_VERIFY_LIMIT`, and every
claim the receiver publishes still hands that candidate's author one guess,
metered by `MAX_CLAIM_ATTEMPTS`. What the budgets additionally bound is churn:
each failed verification costs the sender one replacement publish, and a
claimed candidate's author cannot milk unbounded guesses by rotating
replacement elements at the receiver. A claim flood can still exhaust a
generation's budget and stall it until rotation — a nuisance, not a compromise
(availability is a non-goal).

**Rotation.** The sender mints and publishes a fresh PIN every 2 minutes
(`PIN_ROTATION_MS`), honors only PINs minted in its current or immediately
previous bucket, and attaches a NIP-40 expiration at the end of the PIN's
second bucket. The receiver derives hints for its current and previous buckets
and refuses any rendezvous event whose `created_at` did not land in one of
those same two buckets — a bucket test rather than a maximum age, so an event
stamped in the future cannot claim to be newer than the real sender forever.
The TUI `r` key (and the web app's
refresh button) mints a fresh PIN immediately, dropping all retained
generations. The sender keeps rotating for up to 30 minutes — a resource
backstop, not a security bound — before giving up.

**Handshake.**

1. Sender generates a 16-byte salt, transfer id, and ephemeral Nostr key. Per
   rotation it mints a fresh PIN, starts a fresh SPAKE2 run
   (`pA = x·G + w·M`), and publishes a kind `4243` rendezvous event. A regular
   kind, not an ephemeral one, so relays retain it and a receiver that connects
   after publication still finds it:
   - `content`: **plaintext** JSON with `type=rendezvous`, transfer id, the
     sender's Nostr pubkey, `pakeMessage` (base64, 33-byte compressed P-256
     point), a fresh handshake nonce, and relays. Encrypting it under a
     PIN-derived key would reintroduce the offline guessing target the PAKE
     removes, so it is not encrypted — and file metadata is deliberately absent.
   - tags: `h`, `s` (salt), `t`, `type=rendezvous`, `expiration`.
2. Receiver derives the hints, fetches matching kind `4243` events, and keeps
   up to 8 structurally valid candidates (newest first, one per transfer id):
   the payload must name the event's own author and transfer id, and its
   element must be a valid non-identity curve point. Nothing distinguishes the
   real sender yet — the rendezvous is plaintext and proves nothing.
3. For each candidate the receiver runs its side of the PAKE
   (`pB = y·G + w·N`), finishes it against the candidate's element, and
   computes a versioned SHA-256 transcript over the rendezvous type, transfer
   id, sender identity, element, nonce, relays, and salt. It publishes one kind
   `24243` claim per candidate (`type=claim`, tags `p=<sender>`, `t`) whose
   content is `{"sealed":<base64>,"pake":<base64 pB>,"target":<transcript
   hash>}`: the body is sealed with the session's `claim` key, `pB` rides in
   plaintext because the sender must finish its own side before any key
   exists, and `target` names the exact rendezvous the claim spends. The body
   echoes the sender nonce, contributes a fresh receiver nonce, and binds both
   Nostr identities plus the transcript hash.
4. Sender routes the claim by its `target` to the one retained generation
   whose current element it names — provided that generation's bucket is still
   active and its verification budget remains; a claim naming a spent,
   expired, or foreign target is ignored for free. The matching element is
   consumed before any verification (single-use), and the attempt spends one
   unit of `CLAIM_VERIFY_LIMIT`, the online-guessing meter. The sender
   finishes the SPAKE2 run against `pB`, derives the seal keys, and tries the
   claim seal. A claim that opens *and* matches the publication's nonce, the
   transfer id, both identities, and the sealed transcript hash locks the
   transfer; rotation stops and every other claim is ignored. A claim that
   fails leaves the sender silent on the handshake channel but triggers a
   replacement rendezvous publish for that generation (fresh `x`, element, and
   nonce), which the waiting receiver re-claims. Invalid claims are silently
   ignored, never fatal.
5. Sender publishes the kind `24243` confirm (`type=confirm`) **immediately** on
   verification, sealed with the session's `confirm` key. It echoes both nonces,
   both identities, and the transcript hash, and it delivers the file metadata
   (`contentType`, `fileName`, `fileSize`, `contentEncoding`, `mimeType`). The
   receiver allows 60 seconds for it and verifies every echoed field.
   `fileSize` is the sender's *input* size — a progress hint, never the wire
   length — and `contentEncoding` is one of `deflate-raw` or `identity`; any
   other value fails to parse and the confirm is ignored.
6. Both sides derive an 8-character Crockford Base32 confirmation code from 40
   HKDF-SHA256 bits over the SPAKE2 root with info
   `ptransfer:nostr-session:v4:confirmation|<transfer-id>|<sender-nonce>|<receiver-nonce>|<transcript-hash>|<metadata-hash>`,
   where the metadata hash is a versioned SHA-256 digest of the confirmed
   metadata. The receiver displays it; the sender publishes no WebRTC signal and
   no file byte until its operator enters a normalized match, waiting up to 150
   seconds. A mismatch is retryable. The receiver allows 180 seconds for the
   sender's first signal, which is how it learns the code matched.
7. Both sides derive the session keys with HKDF-SHA256 over the SPAKE2
   transcript root and the public transfer salt:
   `ptransfer:nostr-session:v4:signals` (relay-carried WebRTC signaling) and
   `ptransfer:nostr-session:v4:content` (P2P file chunks). The claim/confirm
   seal keys use the `:claim` and `:confirm` labels off the same root.
8. Sender and receiver exchange kind `24243` WebRTC signal events (`offer`,
   `answer`, `candidate`), encrypted with the session signals key.
   - Signal events use tags `t`, `p=<sender pubkey>`, and `type=signal`.
   - Sender-side answer subscriptions filter by `t`, `p=<sender pubkey>`, and
     receiver author.
   - Receiver-side offer subscriptions filter by `t` and sender author only,
     matching pTransfer.
   - Offer and answer bundles are republished while the P2P connection is
     pending so relay misses do not strand the session, and each bundle's
     events are published concurrently so one slow relay does not serialize
     the exchange.
9. File bytes transfer directly over the WebRTC data channel using the session
   content key. Completion is the data channel `ACK`; no relay event is
   published after signaling.

Default relays match pTransfer. Transport is direct-only: STUN servers
assist NAT traversal, but no TURN relay is configured, so a transfer fails
rather than route file bytes through a relay.

## Tor Onion Transport

Behind the non-default `tor` cargo feature, and deliberately outside the interop
protocol: nothing here is specified by `INTEROP_PROTOCOL.md`, and the web app
does not speak it. v1 is CLI to CLI, capped at 1 MiB per transfer.

The sender publishes an ephemeral v3 onion service and mints a one-time
password with the same generator PIN Exchange uses. Those two strings are the
whole rendezvous: no relay, no lookup hint, no third-party identity, and no
event to correlate. Unlike a PIN, the password's *entire* 12 characters are
secret — there is no public locator segment, because there is nothing public to
look anything up in.

**Framing.** A Tor stream is a byte stream, so
`[1-byte kind][4-byte big-endian length][payload]` frames restore the discrete
binary/text messages the choreography needs, with the length capped at one
encrypted chunk. Above that framing the transfer is the *same* code as PIN
Exchange — `run_sender`/`run_receiver` are generic over a `Messenger`, and both
transports implement it.

**Handshake.** Both peers run SPAKE2 (RFC 9382, P-256) over the stream:

```text
receiver -> sender   hello    { version, pakeMessage: pB }
sender   -> receiver offer    { version, pakeMessage: pA, salt }
receiver -> sender   claim    { sealed }
sender   -> receiver confirm  { sealed(metadata) }
receiver -> sender   ready | cancel
```

The `<host>.onion:<port>` address stands in as the transfer identity in the
SPAKE2 transcript, with fixed role labels for the two ends. Opening either seal
*is* the key confirmation: a wrong password produces two different roots and the
claim simply fails to open, so the sender hangs up without answering. Binding
the address is what stops a handshake proxied through to a *different* onion
service — both ends would derive different roots. Keys derive under
`ptransfer:tor-session:v1:{claim,confirm,content}`, so no key is ever shared
with the PIN Exchange path even off an identical root.

There is no confirmation code for a human to compare. A PIN is short enough that
a live guess can race the intended receiver, which is what that code catches;
the address and password are only ever handed over as a pair, so there is no
race to catch. The sender still counts failed connections and stops after 20.

**What each layer contributes.** Tor authenticates the *service* to the client
(the address is its public key) and encrypts the stream end to end. The password
adds the other direction: proof the connecting peer is the intended receiver
rather than anyone who came across the address. File bytes then travel under the
same AES-256-GCM chunk format as every other transfer, encrypted a second time
inside the Tor stream.

**Limits.** The 1 MiB cap is enforced on the *input* when the selection is
prepared, and the wire ceiling carries a small margin over it — deflate grows
incompressible input slightly and a ZIP adds per-entry headers, neither of which
is known until the bytes are produced.

## Wire Encoding

The compression rule is the web app's, and it is **flow-based, never
content-sniffed**:

| Payload | `contentEncoding` |
|---|---|
| A single file | `deflate-raw` |
| A generated ZIP (multiple files or a folder) | `identity` |

A single file is deflated on the fly with raw DEFLATE (RFC 1951, no zlib or
gzip wrapper — the browser's `deflate-raw`) as it is read, and inflated by the
receiver on the way to disk. A generated ZIP has already deflated each entry, so
the archive itself is never compressed a second time.

Either way the final wire length is unknown while signaling runs, which is why
the advertised size is only a hint and `DONE` carries the real count. The
receiver caps *inflated* output at the transport's ceiling as a
decompression-bomb guard, and a stream that has not ended by `DONE` is rejected as truncated —
something the byte count alone cannot detect, since every promised wire byte did
arrive.

## Data Channel Protocol

Each wire chunk is at most 128 KiB. Each encrypted binary data-channel
message is:

```text
2-byte chunk index (big-endian) || 12-byte nonce || ciphertext || 16-byte tag
```

The chunk index is also AES-GCM additional authenticated data.

After all chunks, the sender sends:

```text
DONE:<total_chunks>:<total_bytes>
```

The final byte count authenticates the wire length, which no payload knows
during signaling. The receiver appends every authenticated chunk in reliable
data-channel order — there is no positional write path, because a chunk index
cannot be turned into a file offset when the total is unknown — then persists
the full file and replies:

That ordering is a requirement on the channel, not an assumption: the CLI
creates its data channel with `ordered: true` explicitly, because `rtc` derives
its data-channel parameters from a plain `Default` and an omitted
`RTCDataChannelInit` negotiates *reliable unordered* instead. Every message
still arrives, but SCTP delivers each one as soon as it reassembles, so one
retransmit is enough for a later chunk to overtake an earlier one and for the
peer to reject the out-of-order index mid-transfer. Loopback never reorders, so
`tests/cli_to_cli_transfer.rs` asserts the negotiated ordering directly (the
answering end decodes it from the offerer's DCEP) rather than hoping a transfer
notices.

```text
ACK
```

Active P2P transfers use a 60-second idle/stall window rather than an overall
wall-clock deadline. The sender applies the window to each chunk hand-off while
waiting for WebRTC backpressure to clear and sending the message. The receiver
arms the same window once the data channel is open and resets it for every
incoming data-channel message, including
`DONE:<total_chunks>:<total_bytes>`.

The maximum transfer size is the transport's: 2 GiB (`MAX_MESSAGE_SIZE`) over a
data channel, matching pTransfer, and 1 MiB over Tor. Both ends stream chunk by
chunk, so neither bound is RAM.

Both send paths run the same shape: a blocking worker produces wire bytes — a
deflater over one file, or a ZIP writer over a walked selection — into a chunk
writer that hands complete 128 KiB chunks across a bounded channel. That channel
is the backpressure boundary between blocking filesystem work and async
encryption/WebRTC sends, so neither a complete archive nor a whole compressed
file is ever materialized, and no temporary file is created. The selection is
walked and validated first; production starts only after the data channel opens.
The advertised size is the input byte count as a progress hint; the sender
enforces the limit against actual output and seals the final length in `DONE`.

## Scope

The CLI intentionally has no legacy signaling protocol, no resume path, no QR
support, no Code Exchange, no relay discovery, and no custom fallback mode. The
Tor transport is CLI to CLI only; CLI-to-web over Tor is phase 2.
