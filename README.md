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

The wizard covers everything interactively: choose send or receive, choose the
transfer mode, pick files and/or folders in the built-in browser (Space to
multi-select), and when receiving, browse to the output directory (or create a
new folder with `n`) and enter the PIN. Transfers run inside the TUI with live
status and progress.

The mode menu lists the web app's modes in the web app's order, so an option's
position means the same thing in both, and adds the CLI's own Tor Onion Service
as a third entry in a build with the `tor` feature. Picking Code Exchange says it
is not implemented and stays on the menu; the other modes run a transfer. Over
Tor the wizard shows the sender's address and password on the transfer screen,
and asks the receiver for both.

### Non-Interactive Test Mode

The `test` subcommand exists for testing only. Initial inputs come from
arguments; confirmation codes are read from stdin and can be piped.

```bash
ptransfer test send /path/to/file more-files a-folder
ptransfer test receive <PIN> --output /path/to/dir
```

The sender prints a case-sensitive 12-character PIN on stdout, and prints a
fresh one each time it rotates (every 2 minutes) until a receiver claims the
transfer; enter the PIN currently shown exactly. The receiver then prints an
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
# address:  zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion:9735
# password: QBp9UR873Xzn
# ready
```

Hand both lines to the receiver, who runs:

```bash
ptransfer tor receive <address> <password> --output ./downloads
```

`send` prints the address and password as soon as they exist, then `ready` once
the descriptor is published and the service is actually reachable — wait for
`ready` before connecting. A port in the address wins over `--port`, which
otherwise sets the onion virtual port on either side. Multiple paths or a folder
are sent as one ZIP, exactly as in PIN Exchange. If the destination file already
exists the receiver fails; pass `--overwrite` to replace it.

v1 is CLI to CLI and carries at most **1 MiB** per transfer — a Tor circuit is
slow enough that anything larger wants resume support, which this does not have.
CLI-to-web is phase 2.

These `tor` subcommands are the non-interactive form. The wizard covers the same
transfer under **Tor Onion Service** in its mode menu.

The password authenticates both ends through the same SPAKE2 exchange PIN
Exchange uses, with the relay-shaped parts removed: no rendezvous to look up, no
third-party identities, and no confirmation code for a human to compare. The
`.onion` address is bound into the SPAKE2 transcript, so a handshake proxied
through to a *different* onion service derives a different key and every seal
under it fails. Tor already authenticates the service to the client and encrypts
the stream; the password adds what that cannot — proof the *connecting* peer is
the intended receiver rather than anyone who came across the address. File bytes
then travel under the same encrypted chunk format as every other transfer, so
they are encrypted a second time inside the Tor stream.

#### Echo Proof of Concept

The transport was built against a bare echo, which is still there. Instance A
publishes an ephemeral onion address and echoes back every line it receives:

```bash
ptransfer tor serve
# zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion:9735
# ready
```

Instance B sends one line to that address and prints the echo:

```bash
ptransfer tor connect <address>.onion:9735 --message hello
# hello
```

`serve` prints the `.onion` address as soon as the identity key exists, then
`ready` once the descriptor is published, exactly like `send`. `connect` takes
the whole line `serve` prints.

#### How the Tor Client Is Set Up

Each process runs its own Arti client that reads no configuration file and
never touches a system Tor or an existing `~/.local/share/arti`. The service
identity key lives only in Arti's in-memory keystore, so every `send` or `serve`
gets a new address and there is no key on disk to lose. Arti still requires filesystem
paths for its directory cache and client state (fully in-memory state is
[arti#1186](https://gitlab.torproject.org/tpo/core/arti/-/work_items/1186), not
scheduled), so those go in a private directory under `/dev/shm` — a tmpfs, so in
RAM — falling back to the platform temp directory off Linux. That tree is
deleted on a graceful shutdown: `send` and `serve` unwind on Ctrl-C or
`SIGTERM`, and `receive` and `connect` on returning. A process killed outright leaves it behind until the
next reboot (or the platform's temp-directory cleanup off Linux).

Because nothing is cached between runs, every command bootstraps the Tor
directory from scratch; expect several seconds before the serving side prints an
address and up to a minute more before it prints `ready`.

## Protocol Compatibility

The normative wire contract is the sibling pTransfer checkout's
[`docs/INTEROP_PROTOCOL.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/INTEROP_PROTOCOL.md).
It covers PIN Exchange and the shared data-channel transfer layer — exactly what
this CLI implements — and carries an interop protocol version independent of
pTransfer's app version. This build implements version `2`, declared in
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
- The Tor transport carries at most 1 MiB per transfer, is CLI to CLI only, and
  is not part of the interop protocol.
- `ptransfer tor receive` takes the password as a command-line argument, so it
  is visible to other users on the same machine through the process list. The
  wizard asks for it interactively instead.
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
