# ptransfer-cli

CLI companion for [pTransfer](https://github.com/andrewtheguy/ptransfer).

This project is pre-release software. No backward compatibility or legacy
protocol support is maintained.

## What It Does

The `ptransfer` command sends and receives files and folders with the same wire
formats as pTransfer. Running the binary with no arguments launches a
full-screen TUI wizard that walks through the whole transfer: send or receive,
file/folder selection, output directory, and the PIN, sender code, or onion
address appropriate to the transfer.

- PIN exchange over Nostr, compatible with the web app's PIN Exchange, is the
  default and the only relay-signaled mode: a case-sensitive 12-character PIN
  (fresh every 2 minutes; the sender can also mint a new one on demand with `r`)
  drives a SPAKE2 password-authenticated key exchange that derives the actual
  signaling and content keys. Nothing published to a relay can test a PIN guess
  offline. The receiver then reads an 8-character confirmation code to the
  sender; nothing is sent until the sender enters a match.
- Code Exchange, compatible with the web app's, is the mode with no signaling
  server at all: the sender shows a code, a person carries it to the receiver,
  and the receiver's response comes back the same way — the sender's own paste
  of that response is what admits a receiver, and it is checked against the
  code being shown before anything moves. The web app can carry those codes as
  QR grids; this CLI carries them as base64 text, which is enough to transfer
  with a browser on the other end. Drawing the offer as a QR grid is planned
  ([`docs/ROADMAP.md`](docs/ROADMAP.md)); reading one is not, since there is no
  camera at a terminal. See [Code Exchange](#code-exchange) below.
- The Nostr relay fallback is what carries a Code Exchange transfer when no
  direct route can be made, and it is the ordinary one — nothing to turn on.
  The sender proves a handful of public relays before the code is shown and
  names them in it; if the direct connection then fails, the file goes out as
  encrypted 48 KiB pieces spread across a ring of storage relays discovered
  behind the exchange, and the receiver fetches them and says which it could
  not get. Nothing is uploaded ahead of time, the pieces expire after an hour,
  and it caps the transfer at 100 MiB.
- Anonymous signaling (experimental) is the same PIN
  Exchange with the relay sockets carried through Tor to a separate pool of
  onion-service relays, so no Nostr relay sees either device's IP address. The
  sender turns it on and the PIN it mints is 16 characters instead of 12; the
  receiver reads the mode off that length and is not asked. File bytes still
  take the direct WebRTC data channel, so this does not make a transfer
  anonymous.
- Anonymous signaling and relay (experimental) is Code Exchange's own option,
  and the alternative to that fallback rather than an addition to it: when no
  direct route can be made, the file goes over a temporary onion service the
  sender publishes, coordinated over a pool of onion-service relays. Nothing
  extra is handed over for it — the password is derived from the exchange on
  both devices and the address is announced over the encrypted control channel
  — and it caps the transfer at 100 MiB too.
- Tor Onion Service is a separate transfer mode, not a
  variant of PIN Exchange: the sender publishes a throwaway v3 onion service and
  a one-time password, and those two strings are the whole rendezvous — no
  Nostr relay, no signaling server, and no WebRTC. The file bytes travel through
  onion service itself, so it is slow and capped at 100 MiB, and it
  interoperates with the web app's Tor Onion Service in both directions. See
  [Tor Onion Service](#tor-onion-service) below.
- A single file is deflated on the wire and restored by the receiver. Multiple
  files and folders are bundled into a single ZIP on the fly, exactly like the
  web app (`<folder>_<timestamp>.zip` for one folder, `files_<timestamp>.zip`
  otherwise), with each entry deflated; the archive itself is never compressed
  a second time. Compressed bytes flow directly into encryption and WebRTC
  without a complete archive or temporary scratch file. Received ZIPs are
  saved as-is; extraction is up to you.
- WebRTC data-channel transfer using the web app's encrypted chunk protocol.
  The WebRTC path itself is direct-only (STUN, no TURN relay). PIN Exchange
  therefore fails if it cannot open a direct route; Code Exchange can instead
  switch to the public-relay or Tor fallback its offer selected.
- No QR code support yet: drawing an offer QR is on the roadmap, reading one
  is not. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

In PIN Exchange the file bytes flow over the WebRTC data channel, and Nostr
relays carry only the handshake and WebRTC signaling events. The rendezvous
event that advertises a transfer is plaintext JSON — a blinded SPAKE2 element and routing fields, with
no file metadata — because encrypting it under a PIN-derived key would
reintroduce the offline guessing target the PAKE removes. The claim, confirm
(which carries the file metadata), and signaling payloads are all encrypted.

## Install

The release installers fetch a native executable. It needs no language runtime
or package manager; ordinary operating-system libraries are still used.

### Quick Install (Linux & macOS)

The shell installer supports Linux x86_64/aarch64 and macOS Apple Silicon.

```bash
curl -sSL https://andrewtheguy.github.io/ptransfer-cli/install.sh | bash
```

By default the installer pulls the latest **stable** release. Use `--prerelease`
for the newest prerelease, or pass an explicit tag to pin to a specific build.
Examples:

```bash
# Latest prerelease
curl -sSL https://andrewtheguy.github.io/ptransfer-cli/install.sh | bash -s -- --prerelease

# Pin to a specific tag
curl -sSL https://andrewtheguy.github.io/ptransfer-cli/install.sh | bash -s <release-tag>
```

### From Source

```bash
cargo build --release
```

## Usage

Run the binary with no arguments to start the TUI wizard — it takes no CLI
arguments at all:

```bash
ptransfer
```

The wizard covers everything interactively: choose send or receive; when
sending, choose the transfer mode and pick files and/or folders in the built-in
browser (Space to multi-select); when receiving, browse to the output directory
(or create a new folder with `n`) and paste whatever the sender handed over.
Transfers run inside the TUI with live status and progress.

Only the sending side picks a mode. Its menu lists the same three modes as the
web app in the same order, so an option's position means the same thing in both.
The anonymous option is not a mode there either: it belongs to the row it is
on — signaling over Tor for PIN Exchange, a Tor fallback for Code Exchange —
toggled with `a` and off unless asked for, the same place the web app keeps it.

The receiving side is never asked which mode to use. A PIN, an onion address
and a sender code are told apart by their own contents, and a PIN's length says
which relay pool its sender is on, so the single receive box reads the mode off
what lands in it and names what it recognized — the same way the web app's
receive screen works.
A PIN or a sender code starts the transfer; an onion address asks for the
one-time password on the next screen, since that is a separate secret. A sender
code is kilobytes of base64, so the box reports it by length rather than trying
to draw it. Something of the right shape
that fails its checksum is called out as a typo while it is still being typed.

### Non-Interactive PIN Exchange

The `pin` subcommand runs PIN Exchange without the wizard, for scripts and
pipes. The sender prints a PIN; the receiver enters it and prints a
confirmation code; the sender enters that, and the transfer starts.

```bash
ptransfer pin send ./file.bin
# 7Kq2mXp9Rt4L
# Enter the receiver's 8-character confirmation code: <the code the receiver printed>
```

Hand the PIN to the receiver, who runs:

```bash
ptransfer pin receive --output ./downloads
# PIN: <the PIN the sender printed>
# J4X9PQ2M
```

Both secrets are read from stdin, never taken as an argument — an argument
would be readable by every other process on the machine for as long as the
process holding it runs. At a terminal each is prompted for; from a script,
pipe it in: `printf '%s\n' "$PIN" | ptransfer pin receive --output ./downloads`
for the receiver, and the confirmation code goes to the *sender's* stdin the
same way, so a script that drives `pin send` keeps its stdin open and writes
the code there once the receiver has printed it. The `tor receive` command
applies the same rule to its password.

The PIN is case-sensitive, 12 characters — 16 with `--anonymous`, which the
receiver reads off the length and needs no flag for — and the sender prints a
fresh one each time it rotates (every 2 minutes) until a receiver claims the
transfer; enter the PIN currently shown exactly. The 8-character confirmation
code is not case-sensitive. Each side prints only its own secret on stdout, so
redirecting it yields just that; everything else goes to stderr. Multiple
paths or a folder are sent as one ZIP. If the destination file already exists
the receiver fails; pass `--overwrite` to replace it.

```bash
# Anonymous signaling; the receiver needs no flag
ptransfer pin send --anonymous ./file.bin
```

### Code Exchange

No relay carries the exchange: the sender shows a code, a person carries it to
the receiver, and the receiver's response comes back the same way. Relays only
appear if the direct connection fails, and only then.

```bash
# Sending side. It prints the code and then waits, so leave it running.
ptransfer code send ./file.bin > offer.txt

# Receiving side, with the sender's code on stdin. It prints the response and
# then waits too.
ptransfer code receive --output ./downloads < offer.txt > response.txt

# Back on the sending side: paste the response at its prompt, or pipe it in.
```

Codes go to stdout and everything else to stderr, so either side pipes cleanly
and neither command needs a terminal. Both codes are read from stdin rather
than taken as arguments: the offer is the secret for the whole transfer, and an
argument is readable by every other process on the machine for as long as the
command runs. A code that arrives wrapped across lines is still a whole code —
lines are read until they add up to one, or until a blank line ends the paste.

Pasting the response back is the confirmation step, and it is checked before it
is acted on. The response carries a tag bound to the exact code being shown and
to the response's own contents, so a response to a different transfer, an old
one pasted again, or one altered on the way back is refused with *Response does
not match this transfer* rather than turning into a connection that never
opens. Anyone who obtained the code before it expired could produce a matching
response, so treat the code as the secret for the whole transfer — what selects
the recipient is the sender accepting the response that person returned, the
same role the 8-character code plays in PIN Exchange.

A code expires an hour after it is made. Multiple paths or a folder are sent as
one ZIP, exactly as in PIN Exchange. If the destination file already exists the
receiver fails; pass `--overwrite` to replace it.

When no direct connection can be made, the file goes through public Nostr
relays instead. That is the ordinary fallback and there is nothing to turn on:
before the code is shown, the sender proves a few relays with a real
write-and-read round trip and names them in the code, and behind the exchange
it discovers and health-checks a ring of storage relays. Only if the direct
attempt then fails is the file read, hashed, and published — as encrypted 48
KiB pieces, one copy each, spread across that ring — while the receiver fetches
them and acknowledges what it could not get; only those pieces are sent again,
somewhere else. Both sides derive the key and the transfer id from the exchange
itself, so no relay is ever told what it is holding, and every event asks the
relays to drop it after an hour. It carries at most 100 MiB, and a selection
over that is sent without naming relays, since a code that named them would
promise a path this side could not walk.

Proving those relays is most of what the sending side is doing in the seconds
before a code appears: dead relays in the built-in pool are replaced by
discovered ones proven at full chunk size, and the probe stops the moment the
gap is filled. A sender that cannot prove at least two relays names none — the
transfer then has no fallback rather than a broken one.

What those probes learn is kept between runs, the way the web app keeps it in
IndexedDB: a relay cache of every relay discovered, when it was last probed,
whether it passed, and how fast. A relay that passed stays cached until it
fails; failures and unprobed listings expire after seven days. A later transfer leads its
candidate list with relays already proven, so it fills its ring from the first
batch instead of sampling the population again, and successive transfers
rotate through the proven relays rather than all landing on the same few.
Behind every transfer a background sweep enumerates the whole relay population
and probes as far as the transfer lasts, so the next one is not limited to
what this one happened to need. The cache is one JSON file,
`ptransfer/relay-cache.json` under the platform's per-user cache directory
(`~/.cache` on Linux, `~/Library/Caches` on macOS), holding relay URLs and verdicts and nothing about any transfer;
several commands running at once share it safely. `PTRANSFER_RELAY_CACHE=off`
keeps it in memory for one run, and `PTRANSFER_RELAY_CACHE=<directory>` moves
it.

`--anonymous` replaces that fallback with one that runs inside Tor:

```bash
ptransfer code send --anonymous ./file.bin
```

It changes nothing about the exchange — the code and the response are still
carried by hand — and a direct WebRTC connection is still tried first. What it
adds is where the file goes when there is no direct route: over a temporary
onion service the sender publishes, with the two sides meeting over an
encrypted control channel on onion-service Nostr relays. Neither of the Tor
transport's two rendezvous values is handed over: the password is derived from
the exchange on both devices and never transmitted, and the address is
announced over that control channel, only after the sender has accepted a
response. Both devices need internet, both spend a Tor bootstrap (started as
soon as the code is shown, behind the direct attempt), the transfer is capped
at 100 MiB, and it fails more often than a direct connection. The receiver
needs no flag: the code says which fallback the sender chose. The two are
alternatives — an anonymous code names no clearnet relays, because that pool is
a constant on both sides.

The receiving side has one option of its own, `--simulate-no-direct`, which
answers as if no direct connection were possible: the response goes back with
none of this device's network routes in it, so the sender falls back. It is the
only way to exercise the fallback from a network where a direct connection
would succeed — the situation a device behind a hostile NAT is in anyway — and
it exists only for a code that carries a fallback, since anywhere else it would
only kill a working transfer. The web app offers the same thing as
*Simulate no direct connection* under its response page's advanced options.

A code with no fallback at all — no relays named and no anonymous flag — is
still a valid code, and a failed direct route simply ends that transfer.

The wizard covers the same transfer: the sender picks **Code Exchange** from
its mode menu (with `a` for the anonymous fallback), and the receiver pastes
the code into the one box it asks for. The wizard shows a code full-screen,
offers it to the system clipboard over OSC 52 where the terminal allows it, and
takes the response by paste. Where the clipboard is refused, `s` writes the
code to a file and names the path — a code is taller than an ordinary terminal,
so a mouse selection cannot take all of it. That file holds the same secret the
code does and is removed as soon as the code leaves the screen. A response stays on screen until the sender turns
up — a direct route that dies, or is simulated dead, does not clear it, because
the sender still needs it to start the fallback — with what is happening behind
it reported underneath. Pasting a code whose sender chose the anonymous
fallback also brings up the receiving side's own option, `Tab` for *Simulate no
direct connection* — the wizard's form of `--simulate-no-direct`, asked before
the transfer starts rather than while a connection is already running.

The container the codes travel in, the ECDH key schedule behind them, the
confirmation tag, and the anonymous fallback's rendezvous are specified in the
web app's
[`docs/CODE_EXCHANGE_PROTOCOL.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/CODE_EXCHANGE_PROTOCOL.md),
which both implementations follow; `docs/ARCHITECTURE.md` covers what is
specific to this one.

### Tor Onion Service

The sender publishes a throwaway v3 onion service and a one-time password; the
`.onion` address and that password are the only things the receiver needs. No
relay, no account, and no signaling server is involved — the address *is* the
rendezvous.

```bash
ptransfer tor send ./file.bin
# address:  zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion
# password: QBp9UR873Xzn
# ready
```

Hand both lines to the receiver, who runs:

```bash
ptransfer tor receive <address> --output ./downloads
# Password: <the password the sender printed>
```

The password is read from stdin, never taken as an argument — an argument would
be readable by every other process on the machine for as long as the receiver
spends bootstrapping Tor. At a terminal it is prompted for; from a script, pipe
it in (`printf '%s\n' "$PASSWORD" | ptransfer tor receive <address>`).

`send` prints the address and password as soon as they exist, then `ready` once
the descriptor is published and the service is actually reachable — wait for
`ready` before connecting. Those three lines are all that goes to stdout, so
redirecting it still yields just them; both ends narrate the rest on stderr —
Tor's own bootstrap percentage, the descriptor going up, the connection and the
handshake, each with how long it took, then byte progress. A Tor transfer spends
a minute or two before anything moves, and that time is accounted for rather
than silent. The printed address leaves the default virtual
port (9735) implicit, since neither side offers it as a choice; `--port` sets
another one, which then shows up in the address, and a port in the address wins
over `--port` on the receiving side. Multiple paths or a folder
are sent as one ZIP, exactly as in PIN Exchange. If the destination file already
exists the receiver fails; pass `--overwrite` to replace it.

The transport carries at most **100 MiB** per transfer. Anything over 1 MiB
prints a note and sends it anyway: throughput over Tor depends on the circuit
you get — the same file can arrive in moments or crawl — and this transport
cannot resume, so a transfer that drops starts over. Whether that trade is
worth it is your call, not the tool's. The other end may be another CLI or a
pTransfer browser tab; both speak the same handshake.

These `tor` subcommands are the non-interactive form. The wizard covers the same
transfer: the sender picks **Tor Onion Service** from its mode menu, and the
receiver just pastes the address into the one box it asks for.

The password authenticates both ends through the same SPAKE2 exchange PIN
Exchange uses, with the relay-shaped parts removed, and the `.onion` address is
bound into the transcript so a handshake proxied through to a different service
fails. The handshake, the key schedule, the framing, and the bounds are
specified in the web app's
[`docs/TOR_TRANSPORT.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/TOR_TRANSPORT.md),
which both implementations follow; `docs/ARCHITECTURE.md` covers what is
specific to this one.

#### How the Tor Client Is Set Up

Each process runs its own Tor client that reads no configuration file and never
touches a system Tor or an existing `~/.local/share/arti`. It writes no Tor
directory, guard or vanguard state, or onion-service identity key: those are
ordinary values in the process's memory. This does not describe transfer
output — a receiver writes its destination through a `.part` file, which an
abruptly killed process can leave behind.

That takes some assembly, because `arti-client` cannot do it. Two crates in
Arti require a filesystem and expose no seam to replace it: `tor-dirmgr` keeps
the directory in a SQLite database plus a `dir_blobs/` directory, and
`tor-hsservice` keeps onion-service state through `tor_persist::StateDirectory`,
a concrete type whose `raw_subdir` hands out real files. Fully in-memory
operation is [arti#1186](https://gitlab.torproject.org/tpo/core/arti/-/work_items/1186),
which is not scheduled upstream. So this crate uses the layers *below* those
two, each of which takes its storage as a trait:

- `tor-chanmgr`, `tor-guardmgr`, `tor-circmgr` and `tor-hsclient` are Arti's,
  unchanged. The guard and vanguard managers take any `tor_persist::StateMgr`,
  so they get an in-memory one (`src/tor/memstate.rs`). Keeping `tor-chanmgr`
  also keeps relay authentication Arti's: Tor relays present self-signed
  certificates and are identified by the CERTS cell instead, so replacing that
  layer would mean writing a certificate verifier that accepts anything.
- The directory is downloaded and validated here (`src/tor/netdir.rs`) and
  served through `tor_netdir::NetDirProvider` from an `RwLock`. The checks are
  the ones Arti's own directory manager makes, in the same order: the consensus
  must be timely (within Arti's own tolerance for clock skew), it must be signed
  by enough directory authorities from Arti's built-in list, every authority
  certificate is signature- and lifetime-checked before it may vouch for
  anything, a microdescriptor is only accepted if the consensus asked for its
  digest, and a consensus that requires subprotocols this build does not
  implement is refused rather than used anyway. `tor-netdoc`'s
  `dangerously_assume_timely` and `dangerously_assume_wellsigned` escape hatches
  are not used.
- The onion service is implemented here (`src/tor/service.rs`) on `tor-proto`:
  identity key, `ESTABLISH_INTRO`, descriptor signing and upload, and the
  `INTRODUCE2` → `RENDEZVOUS1` handshake. Introduction points that drop their
  circuits are replaced and the descriptor republished; introductions already
  answered are remembered in memory, which is the replay defence
  `tor-hsservice` writes to a per-introduction-point log on disk.

Because nothing is cached between runs, every command bootstraps the Tor
directory from scratch; expect around a minute before the serving side prints an
address and a little more before it prints `ready`.

## Protocol Compatibility

The normative wire contract is the sibling pTransfer checkout's
[`docs/INTEROP_PROTOCOL.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/INTEROP_PROTOCOL.md).
It covers PIN Exchange and the shared data-channel transfer layer, and carries
an interop protocol version independent of pTransfer's app version. This build
implements version `4`, declared in
`package.metadata.ptransfer-protocol-version`. Code Exchange, its Nostr relay
fallback, anonymous signaling, and the Tor transport sit outside that document
and have their own contracts and fail-closed version boundaries in the web
app's [`docs/CODE_EXCHANGE_PROTOCOL.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/CODE_EXCHANGE_PROTOCOL.md),
[`docs/NOSTR_FILE_RELAY.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/NOSTR_FILE_RELAY.md),
[`docs/ANONYMOUS_SIGNALING.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/ANONYMOUS_SIGNALING.md),
and [`docs/TOR_TRANSPORT.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/TOR_TRANSPORT.md).

- Rendezvous event: Nostr kind `4243` (a regular kind, so relays retain it for a
  receiver that connects after the sender published), tagged with a rotation-bucket-scoped
  PIN hint and a NIP-40 expiration. The payload is plaintext JSON carrying a
  blinded SPAKE2 element — nothing in it is PIN-testable, and file metadata is
  deliberately absent.
- Claim/confirm handshake and WebRTC signal events: Nostr kind `24243`
  (ephemeral).
- Default relays match pTransfer.
- The PIN reduces to the SPAKE2 password scalar `w` (HKDF-SHA256 to 384 bits,
  reduced mod the P-256 order); there is no key stretching because nothing
  published permits offline guessing. The public lookup hint is derived only
  from the PIN's leading 3-character locator. Every key — the claim/confirm
  seals, signaling, content, and the 8-character confirmation code — is an HKDF
  expansion off the SPAKE2 transcript root, which requires ephemeral scalars
  both peers discard.
- Claim and confirm payloads bind both Nostr identities and a versioned SHA-256
  digest of the complete rendezvous transcript; the confirm additionally
  delivers the file metadata, whose own digest is bound into the confirmation
  code. The sender publishes its confirm as soon as a claim verifies, then
  publishes no WebRTC signal and no file byte until its operator enters the
  receiver's matching confirmation code.
- Online guessing is metered rather than stretched: the sender runs at most 100
  claim verifications per PIN generation, and the receiver claims at most 8
  hint-colliding rendezvous candidates per attempt.
- PIN rotation: fresh PIN every 2 minutes; only PINs minted in the current or
  immediately previous bucket are honored (roughly 2–4 minutes). The sender
  waits up to 30 minutes for a receiver before giving up.
- Wire encoding is flow-based, never content-sniffed: a single file travels
  `deflate-raw`, a generated ZIP travels `identity` because its entries are
  already deflated. The advertised file size is the input size — a progress
  hint — while `DONE` carries the authoritative wire byte count.
- File chunks use AES-256-GCM with the 2-byte chunk index as AAD, followed by
  `DONE:<chunkCount>:<byteCount>` and receiver `ACK`. Every payload is appended
  in reliable data-channel order; there is no positional write path, because no
  payload's wire length is known during signaling.

## Limits

- Maximum transfer size is 2 GiB, matching pTransfer. The selected input is
  checked before sending, and both the encoded wire payload and decoded output
  are checked as the transfer runs. A near-limit selection can therefore pass
  the input check but fail if deflate or ZIP overhead pushes its wire form over
  the limit.
- Received ZIPs are not auto-extracted, matching the web app.
- No resume support.
- No QR support yet: Code Exchange codes are copied and pasted as text.
  Drawing the offer as a QR grid is on the roadmap; reading a response QR is
  not, since there is no camera at a terminal. See
  [`docs/ROADMAP.md`](docs/ROADMAP.md).
- Both Code Exchange fallbacks carry at most 100 MiB.
- The Tor transport carries at most 100 MiB per transfer. Its browser/CLI
  interoperability contract and handshake version are specified separately
  from `INTEROP_PROTOCOL.md` in the web app's `docs/TOR_TRANSPORT.md`.
- Anonymous signaling is experimental and is specified separately from
  `INTEROP_PROTOCOL.md` too. Its relay pool is two community-listed onion
  relays that nothing monitors, so expect it to fail more often than ordinary
  PIN Exchange, and expect a cold Tor bootstrap on both sides before anything
  happens.
- No custom relay/discovery mode.
- Direct P2P only: no TURN relay fallback for the file bytes.

## Development

The Arti dependency tree is part of every build, so the first one is slow:

```bash
cargo test
cargo clippy
```

The checks that talk to the real Tor network are ignored by default, because
they take minutes and fail on a machine with no route to it. Run them
deliberately:

```bash
cargo test -- --ignored --nocapture
```

Those are the client bootstrap and the anonymous-signaling round trip in
`tests/tor_network.rs`, and `a_file_round_trips_over_a_real_onion_service` in
`src/tor/transfer.rs`, which sends a file to itself over a published service.

The live interoperability tests — this CLI against itself, and both directions
between it and the web app — live in the pTransfer repo, which is the source of
truth for everything the two share. Run them from a checkout of it:

```bash
cd ../ptransfer
bun run test:live:webrtc   # PIN Exchange over a real data channel
bun run test:live:code     # Code Exchange: direct, relay, and Tor fallbacks
bun run test:live:tor      # the Tor onion transport
```

Run the one covering what you touched: anything in Code Exchange that both
implementations share — the container, the key schedule, the confirmation tag,
the relay fallback's manifest, pieces and control channel, the anonymous
fallback's rendezvous — needs `test:live:code` before it is considered done.

They require internet access, Bun, a Chrome-family browser, and this checkout
beside that one — `PTRANSFER_CLI_ROOT` and `PTRANSFER_BIN` override where each
looks for it. The WebRTC and Code Exchange ones build this CLI themselves; the
Tor one expects a `cargo build --release` build to already be there.
Both start the web development server when needed and leave byte-verified
transfer artifacts in the temporary directory printed at the end.
