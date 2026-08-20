# Use Cases

The interactive interface is the TUI wizard — run `ptransfer` with no
arguments and follow the screens. The examples below show the equivalent
non-interactive `test` mode, which exists for testing only.

## Send Between CLI and pTransfer

Run `ptransfer`, choose **Send**, pick files and/or folders in the
browser (Space to multi-select), and choose PIN mode. Enter the displayed PIN
in pTransfer's receive mode. Multiple files or a folder arrive as one
ZIP, exactly as if they had been sent from the web app.

Test mode:

```bash
ptransfer test send ./file.bin ./photos
```

## Receive From pTransfer

Start a send in pTransfer, then run `ptransfer`, choose
**Receive** and PIN mode, pick the output directory, and enter the PIN.

Test mode (fails if the destination exists; add `--overwrite` to replace):

```bash
ptransfer test receive <PIN> --output ./downloads
```

## CLI to CLI

Run the wizard on both machines — **Send** on one, **Receive** on the other —
and enter the sender's PIN on the receiving side. Read the receiver's
8-character confirmation code back to the sender and enter it there to start
the transfer.

Test mode:

```bash
ptransfer test send ./file.bin
ptransfer test receive <PIN>
```

## Manual Copy/Paste Signaling

Use this when Nostr relays are unavailable but both peers can still establish a
WebRTC connection. Choose **Manual copy/paste exchange** in the wizard; the TUI
exits back to the normal terminal so the PT01 offer and response codes can be
copied and pasted between the peers.

Test mode (the sender reads the response code from stdin):

```bash
ptransfer test send --manual ./file.bin
ptransfer test receive --manual <OFFER-CODE>
```

Manual mode exchanges PT01 offer and answer text. It does not add QR support.
