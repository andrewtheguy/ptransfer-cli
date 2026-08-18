# secure-send-cli

CLI companion for [`secure-send-web`](https://github.com/andrewtheguy/secure-send-web).

This project is pre-release software. No backward compatibility or legacy
protocol support is maintained.

## What It Does

`secure-send-cli` sends and receives files and folders with the same wire
formats as `secure-send-web`. Running the binary with no arguments launches a
full-screen TUI wizard that walks through the whole transfer: send or receive,
file/folder selection, signaling mode, output directory, and PIN entry.

- Nostr PIN signaling by default, compatible with the web app's Auto Exchange
  mode: a case-sensitive 12-character PIN (fresh every 2 minutes; the sender
  can also mint a new one on demand with `r`) authenticates an ephemeral ECDH
  exchange that derives the actual signaling and content keys. The receiver
  then reads an 8-character confirmation code to the sender; nothing is sent
  until the sender enters a match.
- Manual SS03 copy/paste signaling, compatible with the web app's manual
  exchange codes. When chosen in the wizard, the TUI exits back to the normal
  terminal so the offer/response codes can be copy/pasted.
- Multiple files and folders are bundled into a single ZIP on the fly, exactly
  like the web app (`<folder>_<timestamp>.zip` for one folder,
  `files_<timestamp>.zip` otherwise). ZIP bytes flow directly into encryption
  and WebRTC without a complete archive or temporary scratch file. Received
  ZIPs are saved as-is; extraction is up to you.
- WebRTC data-channel transfer using the web app's encrypted chunk protocol.
  Transport is direct-only (STUN, no TURN relay): the transfer fails rather
  than route file bytes through a relay server.
- No QR code support in the CLI.

The file bytes flow over the WebRTC data channel. Nostr relays carry only
encrypted handshake metadata and WebRTC signaling events.

## Install

The release installers fetch a native, standalone executable. You only need the
binary in your PATH; no runtime dependencies or package managers are required.

### Quick Install (Linux & macOS)

The shell installer supports Linux x86_64/aarch64 and macOS Apple Silicon.

```bash
curl -sSL https://andrewtheguy.github.io/secure-send-cli/install.sh | bash
```

By default the installer pulls the latest **stable** release. Use `--prerelease`
for the newest prerelease, or pass an explicit tag to pin to a specific build.
Examples:

```bash
# Latest prerelease
curl -sSL https://andrewtheguy.github.io/secure-send-cli/install.sh | bash -s -- --prerelease

# Pin to a specific tag
curl -sSL https://andrewtheguy.github.io/secure-send-cli/install.sh | bash -s <release-tag>
```

### Quick Install (Windows)

The Windows installer supports x86_64 (AMD64).

```powershell
irm https://andrewtheguy.github.io/secure-send-cli/install.ps1 | iex
```

By default the PowerShell installer pulls the latest **stable** release. Because
parameter binding is unavailable when piping into `iex`, pass flags via
`$env:SECURE_SEND_CLI_INSTALL_ARGS`. Examples:

```powershell
# Latest prerelease
$env:SECURE_SEND_CLI_INSTALL_ARGS='-PreRelease'; irm https://andrewtheguy.github.io/secure-send-cli/install.ps1 | iex

# Pin to a specific tag
$env:SECURE_SEND_CLI_INSTALL_ARGS='<release-tag>'; irm https://andrewtheguy.github.io/secure-send-cli/install.ps1 | iex
```

### From Source

```bash
cargo build --release --all-features
```

## Usage

Run the binary with no arguments to start the TUI wizard — it takes no CLI
arguments at all:

```bash
secure-send-cli
```

The wizard covers everything interactively: choose send or receive, pick files
and/or folders in the built-in browser (Space to multi-select), choose the
signaling mode, and when receiving, browse to the output directory (or create
a new folder with `n`) and enter the PIN. Nostr PIN transfers run inside the
TUI with live status and progress; manual SS03 transfers drop back to the
plain terminal for the code swap.

### Non-Interactive Test Mode

The `test` subcommand exists for testing only. Initial inputs come from
arguments; sender-side manual response codes and Nostr confirmation codes are
read from stdin and can be piped.

Nostr PIN mode:

```bash
secure-send-cli test send /path/to/file more-files a-folder
secure-send-cli test receive <PIN> --output /path/to/dir
```

The sender prints a case-sensitive 12-character PIN on stdout, and prints a
fresh one each time it rotates (every 2 minutes) until a receiver claims the
transfer; enter the PIN currently shown exactly. The receiver then prints an
8-character confirmation code which the sender must enter before the transfer
continues. Multiple paths or a folder are sent as one ZIP. If the destination
file already exists the receiver fails; pass `--overwrite` to replace it.

Manual SS03 mode:

```bash
secure-send-cli test send --manual /path/to/file
secure-send-cli test receive --manual <OFFER-CODE>
```

The sender prints an offer code and waits for the response code on stdin. The
receiver takes the offer code as an argument and prints a response code.

## Protocol Compatibility

The CLI follows `secure-send-web` as the source of truth:

- Rendezvous event: Nostr kind `24243`, tagged with a rotation-bucket-scoped
  PIN hint and a NIP-40 expiration; payload sealed with the PIN-derived
  rendezvous key.
- Claim/confirm handshake and WebRTC signal events: Nostr kind `24242`.
- Default relays match `secure-send-web`.
- The PIN root is PBKDF2-SHA256 (600k iterations, salt
  `secure-send:pin-root:v2`); the handshake auth and rendezvous keys are HKDF
  expansions off that root. The public lookup hint is derived only from the
  PIN's leading 3-character locator. The PIN derives no content keys —
  signaling, content, and the 8-character confirmation code come from an
  ephemeral P-256 ECDH exchange authenticated by the claim/confirm handshake.
- Claim and confirm payloads bind both Nostr identities and a versioned SHA-256
  digest of the complete rendezvous transcript. The sender publishes no
  confirm or WebRTC signal until its operator enters the receiver's matching
  ECDH-derived confirmation code.
- PIN rotation: fresh PIN every 2 minutes; only PINs minted in the current or
  immediately previous bucket are honored (roughly 2–4 minutes). The sender
  waits up to 30 minutes for a receiver before giving up.
- Manual signaling uses SS03 payloads.
- File chunks use AES-256-GCM with the 2-byte chunk index as AAD, followed by
  `DONE:<chunkCount>:<byteCount>` and receiver `ACK`.

## Limits

- Maximum transfer size is 2 GiB, matching `secure-send-web`. For a generated
  ZIP this applies to the final archive, so a selection whose ZIP crosses the
  limit fails while it is being generated and sent.
- Received ZIPs are not auto-extracted, matching the web app.
- No resume support.
- No QR support.
- No custom relay/discovery mode.
- Direct P2P only: no TURN relay fallback for the file bytes.

## Development

Run checks with all features:

```bash
cargo test --all-features
cargo clippy --all-features
```

Run the live CLI-to-CLI and bidirectional CLI/web interoperability test:

```bash
node tests/live_interop_e2e.mjs
```

It requires internet access, Node/npm, a Chrome-family browser, and a
`secure-send-web` checkout next to this repository. Set
`SECURE_SEND_WEB_ROOT`, `SECURE_SEND_WEB_URL`, or `CHROME_PATH` to override
those defaults. The script builds the CLI with all features, starts the web
development server when needed, and leaves byte-verified transfer artifacts in
the temporary directory printed at the end.

Do not run `cargo fmt` for this repo.
