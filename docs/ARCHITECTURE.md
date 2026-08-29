# Architecture

`ptransfer-cli` provides the `ptransfer` command-line client for pTransfer.

The normative wire contract is the web app's `docs/INTEROP_PROTOCOL.md`, which
specifies PIN Exchange and the shared data-channel transfer layer and carries an
interop protocol version independent of pTransfer's app version. This build
implements version `4` (`package.metadata.ptransfer-protocol-version`). This
document describes how the CLI realizes that contract; where the two disagree,
the spec wins.

Three transfer modes reach the same transfer layer. **PIN Exchange** is the
only relay-signaled one. **Code Exchange** has no signaling server at all: the
offer and the response are carried by a person, and this CLI carries them as
base64 text, since there is no camera at a terminal to read the QR half the web
app also offers. The **Tor onion transport** rendezvouses on the onion address
itself. Code Exchange and the Tor transport have their own wire contracts,
outside `INTEROP_PROTOCOL.md` and versioned separately — see the sections
below.

The wizard's send mode menu lists the three in the web app's order, so a mode's
number means the same thing in both interfaces. That menu belongs to the
sending side alone. The receiving side is handed one value and the modes are
distinguishable by it — a 12- or 16-character PIN, a v3 onion address with a
valid checksum, or a PT01 sender code — so the wizard classifies what was
pasted rather than asking, as the web app's receive screen does. Only the Tor
mode then needs a second input, its one-time password.

**No secret is ever a command-line argument.** Non-interactive commands take
paths and options on the command line, but read PINs, confirmation codes, and
the Tor transport's password on stdin, prompted for at a terminal or piped in
from a script. An argument is public: every other process
on the machine can read it out of the process list and an interactive shell
writes it to history, and the receiving side holds its secret for the whole
connection attempt — tens of seconds for PIN Exchange, minutes when a Tor
bootstrap is in front of it — which is exactly long enough for whoever grabs it
to collect the file first.

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
lookup, so effective strength is 55⁸ ≈ 46.3 bits. Anonymous signaling mints the
same PIN at 16 characters instead (see below); everything in this section holds
for both, with 55¹² in place of 55⁸.

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

## Anonymous Signaling

Experimental. The normative specification is the web app's
[`docs/ANONYMOUS_SIGNALING.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/ANONYMOUS_SIGNALING.md):
the PIN's length carrying the mode, the relay pool, the URL policy and the
privacy boundary are defined there, once, for both implementations. Like the
Tor transport it sits outside `INTEROP_PROTOCOL.md`, which is why an
implementation of that document alone must refuse a PIN of any other length
rather than guess. Either side of a transfer may be this CLI or a browser tab.

This section describes only what is specific to the CLI's realization of it.

**Only the relay sockets are new.** Every event, subscription, signature,
SPAKE2 exchange and sealed payload above the socket is the code the clearnet
path runs, so `src/signaling/anonymous.rs` adds only a `WebSocketTransport` —
the seam `nostr-sdk`'s relay pool already exposes — whose sockets are WebSocket
handshakes run inside onion streams opened by the Tor client in
`src/tor/client.rs`. Frames are `tokio-tungstenite`'s, capped at 1 MiB per
message; a binary frame is a protocol error rather than a silent drop.

**Where the mode is read.** `PinKind` and `classify_pin` in `src/crypto/pin.rs`
turn the PIN's length into the pool `NostrClient::connect` dials; nothing else
in the CLI decides it and there is no receive-side flag. `test send
--anonymous` mints the longer PIN, and so does the wizard's `a` toggle on the
PIN Exchange row — an option of that mode rather than a mode beside it, which
is where the web app keeps it too. The Tor transfer mode's one-time password
selects no relay pool, so it is checked against the ordinary length alone.

**Where the URL policy is enforced.** `normalize_onion_relay_url` is applied to
every pool entry before a socket is opened, and it parses the address as an
Arti `HsId` rather than pattern-matching for `.onion` — Arti routes a non-onion
host through an exit node, so this check is what stands between a bad pool
entry and a socket that sees the device's IP address.

**Timeouts and failure reporting.** A relay socket gets 180 seconds rather than
3: it is a whole rendezvous — an HSDir descriptor fetch, an introduction circuit
and a rendezvous circuit — and every socket pays for its own, which is why the
pool is kept small. The wait is for *any* relay to connect, and unlike the
clearnet path it is a hard requirement: there is no silent fallback to a
clearnet socket, so a pool that never opens is reported instead of being left
for a publish to discover. Failing to reach Tor at all and failing to reach a
relay through it are separate errors, because they are separate problems.
Publishes go to the relays that have a socket open, so one relay that is still
connecting cannot hold every event for its `OK` timeout after another relay has
already accepted it.

## Code Exchange

The wire contract is the web app's
[`docs/CODE_EXCHANGE_PROTOCOL.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/CODE_EXCHANGE_PROTOCOL.md),
which specifies the PT01 container, the payload fields, the ECDH key schedule,
both transcript digests, and the anonymous fallback's rendezvous — deliberately
outside `INTEROP_PROTOCOL.md` and versioned separately, by the container's own
`PT01` magic. Its direct transfer does use that document's §7, the shared
data-channel layer. Either side of a transfer may be this CLI or a browser tab.

This section describes only what is specific to the CLI's realization of it.

**Text, never QR.** The mode's two codes are carried by hand, and a terminal
has one way to do that: `ptransfer code send` prints the offer to **stdout**
and reads the response from **stdin**, and `ptransfer code receive` does the
reverse, so either side pipes cleanly. Everything else — status, prompts,
progress — goes to stderr. The wizard shows a code full-screen, offers it to
the system clipboard over OSC 52, and takes the response by bracketed paste.
The web app's multi-QR offer path is not implemented and does not need to be:
both sides carry the same container, and the copy/paste half is enough to
transfer with a browser on the other end.

**Three ways off the screen, because two of them do not always work.** OSC 52
is refused by terminals that do not implement it and by tmux unless it is
turned on, and a mouse selection reaches only what is drawn — a code is several
screens tall on an ordinary terminal, so no single selection can take all of
it. `s` is the third: it writes the code to a file in the temporary directory,
private to this user, and names the path. The file holds what the code holds,
so it is removed when the code leaves the screen. What the overlay offers
follows what can actually work: it stops suggesting a selection once the code
does not fit in one.

**A code is read as a code, not as a line.** Whatever carries a code may wrap
it — a mail client, a chat window, a terminal that soft-wrapped the paste — and
[`CODE_EXCHANGE_PROTOCOL.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/CODE_EXCHANGE_PROTOCOL.md)
§6 says whitespace and wrapping around a code are ignored. So the stdin
readers for the offer and the response take lines until they add up to a
container that decodes, or until a blank line or EOF says there are no more.
The first rule is what lets an unwrapped paste finish on its own Enter; the
second is how a code that will never decode is reported as that instead of
waiting for a line that would fix it.

**Modules.** `src/code/payload.rs` is the container — obfuscation, validation,
and the two transcript digests; `keys.rs` is the ECDH agreement and every
derivation off it; `sender.rs` and `receiver.rs` are the two halves of the
exchange; `control.rs` and `relay.rs` are the anonymous fallback.

**The response is the confirmation step.** Nothing enters the sending side
except through its operator's own paste, and what is pasted is checked before
it is acted on: the tag inside the response is recomputed from this offer's
bytes and the response's own fields and compared in constant time, before a
signal is applied, the content key is derived, or a byte moves. A response to
another transfer, an old one pasted again, and one altered on the way back are
all refused with the same message rather than turning into a connection that
never opens.

**Fallbacks: one of the web app's two.** An offer minted here never names
clearnet relays, because the CLI does not implement the Nostr file relay those
would exist for and an offer that named them would promise a receiver a path
this side cannot walk. A web offer that *does* name them is still taken — the
direct path is identical — but a failed direct route ends the transfer here
rather than moving onto them. What is implemented is the **anonymous** fallback
(`code send --anonymous`, or the wizard's `a` toggle on the Code Exchange row):
the control channel on the onion-service relay pool of *Anonymous Signaling*
above, and the file over a temporary onion service published on the same Tor
client, using the transport below unchanged.

**Nothing extra is handed over for it.** The Tor transport's two rendezvous
values are the password and the address. The password is derived from the ECDH
secret on both devices and never transmitted; `derive_pake_secret` takes an
opaque string, so derived key material drops into the same handshake with
nothing about it changed. The address cannot be derived — Arti mints an
ephemeral service identity — so it is announced over the sealed control
channel, and only after a response was accepted and verified. That ordering is
the security property: the sender cannot reach the shared secret before it
holds the receiver's public key, so until its operator pastes a response there
is nothing published and no password that would open the handshake.

**One Tor client, bootstrapped early.** A bootstrap is minutes, so
`code send --anonymous` starts one the moment it has a code to show and an
anonymous offer starts one on the receiving side as the code is taken in —
behind the direct attempt rather than after it fails. The same client carries
the control channel's relay sockets and publishes the onion service;
`NostrClient::connect_anonymous_with` exists so the second of those does not
pay for a second bootstrap. A transfer that connects directly drops the
bootstrap unused, having published nothing.

**The response stays up until the sender turns up.** A dead direct route —
real or simulated — does not take the response off the screen. The sender has
not taken it in yet, so it is still the only thing the transfer is waiting on,
and the fallback runs behind it: the control channel is opened, the `hello`
goes out, and the wait for the sender's announcement is the wait for the code
to be handed over, bounded by the session's own hour rather than by a
connection timeout. The code comes down at the moment the sender appears — the
data channel opening on the direct route, the onion announcement on the
fallback — which is the same point the web app's response page gives way, and
for the same reason. While it is up, the overlay carries the last few status
lines beneath the code, because it covers the log and a Tor client that is
still bootstrapping is the other half of what its reader needs to know.

**Status lines are addressed, not positional.** `ui::status_step` returns a
handle that rewrites its own line ("Fetching the Tor directory..." → "Fetched
the Tor directory (36.5 s)"), keyed by an id the TUI matches against the rows
it holds. Steps overlap here — the Tor bootstrap reports from a background task
while the foreground reports its own progress — and a "replace the last line"
rule made them overwrite each other, leaving a log that read as a sequence that
never happened.

**Windows.** The sender gives the direct route 20 seconds when it has a
fallback and 120 when it does not; the receiver gives it 120 either way, since
its wait starts before the sender has even seen the response. These are local
policy, not contract.

**Exercising the fallback.** `code receive --simulate-no-direct` builds the
response with an empty candidate list and drops the peer connection before the
sender can reach it, so the sender's direct attempt fails the way it would
behind a hostile NAT and the fallback runs for real. It is refused for a code
that selected no fallback, where it would only kill a working transfer. The web
app offers the same affordance on its response page, which is what lets the two
implementations test the Tor path against each other on a network where a
direct connection would otherwise always succeed.

The wizard has it too, as a `Tab` toggle on the receive box, and only while
what is in that box decodes to an offer that named the fallback — the same
condition the web app hides the option behind. The web app puts it under the
response's advanced options and rebuilds a live connection when it is used;
the wizard asks a keystroke earlier, before anything has been started, so
arming it needs no teardown. The flag is refused rather than hidden on the
command line, because there the code is read after the option.

## Tor Onion Transport

The wire contract is the web app's
[`docs/TOR_TRANSPORT.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/TOR_TRANSPORT.md),
which specifies the onion address binding, the password, the SPAKE2 handshake
frames, the key schedule, the stream framing, and the bounds — deliberately
outside `INTEROP_PROTOCOL.md` and carrying its own `TOR_HANDSHAKE_VERSION`
(`1`). This build implements that version; where the two disagree, the spec
wins. Either side of a transfer may be this CLI or a browser tab.

This section describes only what is specific to the CLI's realization of it.

**Modules.** `src/tor/service.rs` publishes the ephemeral onion service and
`client.rs` assembles the Tor client that connects to one; `config.rs` is the
settings those managers read; `memstate.rs` and `netdir.rs` are the in-memory
state store and network directory; `wire.rs` is the framed `TorMessenger`;
`handshake.rs` is the spec's handshake; `transfer.rs` is the accept loop and
the caps.

**One transfer layer, two transports.** `run_sender`/`run_receiver` are generic
over a `Messenger`, so above the framing the Tor path runs the *same* code as
PIN Exchange rather than a parallel implementation. `TorMessenger` restores the
discrete binary/text messages the choreography needs from a byte stream.

**Tor state never leaves memory.** There is no Tor state directory, cache or
keystore: the network directory, guard and vanguard state, and onion-service
identity key are values in the process. A transfer cannot touch a system Tor or
an existing `~/.local/share/arti`. Transfer output is separate: receiving uses
a destination `.part` file, which can remain after an abrupt process kill. The
cost of memory-only Tor state is that every command bootstraps from cold.

This is why the client is assembled from Arti's managers rather than taken
whole from `arti-client`: `tor-dirmgr` (SQLite plus a blob directory) and
`tor-hsservice` (`tor_persist::StateDirectory`) are the two crates that require
a filesystem and expose no seam to replace it — arti#1186, unscheduled
upstream. Everything below them takes its storage as a trait, so `netdir.rs`
implements `NetDirProvider`, `memstate.rs` implements `StateMgr`, and
`service.rs` implements the onion service on `tor-proto`. `tor-chanmgr`,
`tor-guardmgr`, `tor-circmgr` and `tor-hsclient` are used unchanged, which
matters for more than convenience: relay authentication — self-signed TLS bound
to an identity by the CERTS cell — stays Arti's rather than becoming a
certificate verifier written here.

**The password comes from stdin, never argv**, like every other secret this CLI
reads (above). The address is the half of the pair that may be an argument: it
is not a secret on its own, and a receiver still cannot authenticate without the
password.

**Waiting for the peer's close.** The spec makes whoever sends the last frame
wait for the peer to close, and Arti is why it matters here: it hands bytes to
the circuit from background tasks, so a process that writes and exits takes
that frame with it. The close is therefore the delivery receipt for the
receiver's `ACK`, and its absence is reported — but not as a failure, since by
then the file is written and verified and only the sender's knowledge of that
is in doubt.

**Input caps.** The spec's 100 MiB bound is enforced on the input when the
selection is prepared (`prepare_send_source_with_cap`), and the wire ceiling
carries the spec's margin over it. The spec's 1 MiB *suggestion* is exactly
that: an oversized selection prints a line saying the transfer will be slow and
then goes ahead.

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
`tests/webrtc.rs` asserts the negotiated ordering directly (the answering end
decodes it from the offerer's DCEP) rather than hoping a transfer notices.

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
data channel, matching pTransfer, and 100 MiB over Tor. The selected input is
checked before sending; the transfer layer separately checks encoded wire bytes
and decoded output as it streams. A near-limit selection can therefore pass the
input check but fail if its wire form grows beyond the cap. Neither bound is a
RAM requirement.

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
support, no relay discovery, and no custom fallback mode. Code Exchange's codes
are therefore text only, and its clearnet Nostr file-relay fallback — which
would need relay discovery — is not implemented, so an offer minted here names
no relays and a failed direct route ends the transfer. The Tor transport
interoperates with the web app in both directions and is capped at 100 MiB per
transfer, with no resume; Code Exchange's anonymous fallback runs over it and
inherits that cap. Anonymous signaling interoperates in both directions too and
is experimental on both sides: it changes which relays carry the handshake and
nothing else, so it inherits every limit above.
