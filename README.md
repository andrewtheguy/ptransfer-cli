# ptransfer-cli

CLI companion for [pTransfer](https://github.com/andrewtheguy/ptransfer).

This project is pre-release software. No backward compatibility or legacy
protocol support is maintained.

## What It Does

The `ptransfer` command sends and receives files and folders with the same wire
formats as pTransfer. Running the binary with no arguments launches a
full-screen TUI wizard that walks through the whole transfer: send or receive,
file/folder selection, output directory, and PIN entry.

- PIN exchange over Nostr is the only signaling mode, compatible with the web
  app's PIN Exchange: a case-sensitive 12-character PIN (fresh every 2 minutes;
  the sender can also mint a new one on demand with `r`) drives a SPAKE2
  password-authenticated key exchange that derives the actual signaling and
  content keys. Nothing published to a relay can test a PIN guess offline. The
  receiver then reads an 8-character confirmation code to the sender; nothing
  is sent until the sender enters a match. The web app's Code Exchange
  (hand-carried QR/clipboard codes) is web-only and is not implemented here.
- Anonymous signaling (experimental, behind the `tor` feature) is the same PIN
  Exchange with the relay sockets carried through Tor to a separate pool of
  onion-service relays, so no relay sees either device's IP address. The sender
  turns it on and the PIN it mints is 16 characters instead of 12; the receiver
  reads the mode off that length and is not asked. File bytes still take the
  direct WebRTC data channel, so this does not make a transfer anonymous.
- A single file is deflated on the wire and restored by the receiver. Multiple
  files and folders are bundled into a single ZIP on the fly, exactly like the
  web app (`<folder>_<timestamp>.zip` for one folder, `files_<timestamp>.zip`
  otherwise), with each entry deflated; the archive itself is never compressed
  a second time. Compressed bytes flow directly into encryption and WebRTC
  without a complete archive or temporary scratch file. Received ZIPs are
  saved as-is; extraction is up to you.
- WebRTC data-channel transfer using the web app's encrypted chunk protocol.
  Transport is direct-only (STUN, no TURN relay): the transfer fails rather
  than route file bytes through a relay server.
- No QR code support in the CLI.

The file bytes flow over the WebRTC data channel. Nostr relays carry only the
handshake and WebRTC signaling events. The rendezvous event that advertises a
transfer is plaintext JSON — a blinded SPAKE2 element and routing fields, with
no file metadata — because encrypting it under a PIN-derived key would
reintroduce the offline guessing target the PAKE removes. The claim, confirm
(which carries the file metadata), and signaling payloads are all encrypted.

## Install

The release installers fetch a native, standalone executable. You only need the
binary in your PATH; no runtime dependencies or package managers are required.

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

### Quick Install (Windows)

The Windows installer supports x86_64 (AMD64).

```powershell
irm https://andrewtheguy.github.io/ptransfer-cli/install.ps1 | iex
```

By default the PowerShell installer pulls the latest **stable** release. Because
parameter binding is unavailable when piping into `iex`, pass flags via
`$env:PTRANSFER_CLI_INSTALL_ARGS`. Examples:

```powershell
# Latest prerelease
$env:PTRANSFER_CLI_INSTALL_ARGS='-PreRelease'; irm https://andrewtheguy.github.io/ptransfer-cli/install.ps1 | iex

# Pin to a specific tag
$env:PTRANSFER_CLI_INSTALL_ARGS='<release-tag>'; irm https://andrewtheguy.github.io/ptransfer-cli/install.ps1 | iex
```

### From Source

```bash
cargo build --release --all-features
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

Only the sending side picks a mode. Its menu lists the web app's modes in the
web app's order, so an option's position means the same thing in both, and adds
the CLI's own Tor Onion Service after them in a build with the `tor` feature.
Anonymous signaling is not a mode there either: it is an option of PIN
Exchange, toggled with `a` on that row and off unless asked for, the same place
the web app keeps it. Picking Code Exchange says it is not implemented and
stays on the menu; the other modes run a transfer.

The receiving side is never asked which mode to use. A PIN and an onion address
are told apart by their own contents, and a PIN's length says which relay pool
its sender is on, so the single receive box reads the mode off what lands in it
and names what it recognized — the same way the web app's receive screen works.
A PIN starts the transfer; an onion address asks for the one-time password on
the next screen, since that is a separate secret. Something of the right shape
that fails its checksum is called out as a typo while it is still being typed.

### Non-Interactive Test Mode

The `test` subcommand exists for testing only. Paths and options come from
arguments; every secret — the PIN, the Tor transport's password, the
confirmation code — is read from stdin, prompted for at a terminal and piped in
from a script, so that none of them appears in the process list.

```bash
ptransfer test send /path/to/file more-files a-folder

# The PIN is typed at the prompt, or piped
ptransfer test receive --output /path/to/dir
echo "$PIN" | ptransfer test receive --output /path/to/dir

# Anonymous signaling (requires --features tor); the receiver needs no flag
ptransfer test send --anonymous /path/to/file
```

The sender prints a case-sensitive 12-character PIN on stdout — 16 characters
with `--anonymous` — and prints a fresh one each time it rotates (every 2
minutes) until a receiver claims the transfer; enter the PIN currently shown
exactly. The receiver then prints an
8-character confirmation code which the sender must enter before the transfer
continues. Multiple paths or a folder are sent as one ZIP. If the destination
file already exists the receiver fails; pass `--overwrite` to replace it.

### Tor Onion Service

Built behind the non-default `tor` cargo feature (`cargo build --features tor`).
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

#### Echo Proof of Concept

The transport was built against a bare echo, which is still there. Instance A
publishes an ephemeral onion address and echoes back every line it receives:

```bash
ptransfer tor serve
# zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion
# ready
```

Instance B sends one line to that address and prints the echo:

```bash
ptransfer tor connect <address>.onion --message hello
# hello
```

`serve` prints the `.onion` address as soon as the identity key exists, then
`ready` once the descriptor is published, exactly like `send`. `connect` takes
the whole line `serve` prints.

#### How the Tor Client Is Set Up

Each process runs its own Tor client that reads no configuration file and never
touches a system Tor or an existing `~/.local/share/arti`. It writes nothing,
anywhere: the directory, the guard and vanguard state, and the onion service's
identity key are all ordinary values in the process's memory. There is no
storage to clean up, so a process killed outright leaves nothing behind, and
the behaviour is identical on every platform.

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
It covers PIN Exchange and the shared data-channel transfer layer — exactly what
this CLI implements — and carries an interop protocol version independent of
pTransfer's app version. This build implements version `4`, declared in
`package.metadata.ptransfer-protocol-version`.

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

- Maximum transfer size is 2 GiB, matching pTransfer. It is enforced against
  the wire bytes as they are produced, so a selection whose payload crosses the
  limit fails while it is being generated and sent.
- Received ZIPs are not auto-extracted, matching the web app.
- No resume support.
- No QR support.
- No Code Exchange: hand-carried offer/answer codes are web-only.
- The Tor transport carries at most 100 MiB per transfer and is not part of
  the interop protocol; it has a spec of its own that the web app shares.
- Anonymous signaling is experimental and is not part of the interop protocol
  either. Its relay pool is two community-listed onion relays that nothing
  monitors, so expect it to fail more often than ordinary PIN Exchange, and
  expect a cold Tor bootstrap on both sides before anything happens.
- No custom relay/discovery mode.
- Direct P2P only: no TURN relay fallback for the file bytes.

## Development

Run checks with all features (`--all-features` includes `tor`, which pulls in
the Arti dependency tree and is slow to build the first time):

```bash
cargo test --all-features
cargo clippy --all-features
```

Run the live CLI-to-CLI and bidirectional CLI/web interoperability test:

```bash
bun tests/live_interop_e2e.ts
```

It requires internet access, Bun, a Chrome-family browser, and a pTransfer
checkout in the sibling `ptransfer` folder. Set `PTRANSFER_WEB_ROOT`,
`PTRANSFER_WEB_URL`, or `CHROME_PATH` to override those defaults. The script builds
the CLI with all features, starts the web development server when needed, and
leaves byte-verified transfer artifacts in the temporary directory printed at
the end.
