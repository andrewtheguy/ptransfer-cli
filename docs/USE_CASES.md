# Use Cases

The interactive interface is the TUI wizard — run `ptransfer` with no
arguments and follow the screens. The examples below show the equivalent
non-interactive `test` mode, which exists for testing only.

## Send Between CLI and pTransfer

Run `ptransfer`, choose **Send** and pick files and/or folders in the browser
(Space to multi-select). Enter the displayed PIN in pTransfer's receive page.
Multiple files or a folder arrive as one ZIP, exactly as if they had been sent
from the web app.

Test mode:

```bash
ptransfer test send ./file.bin ./photos
```

## Receive From pTransfer

Start a send in pTransfer with **PIN Exchange**, then run `ptransfer`, choose
**Receive**, pick the output directory, and enter the PIN.

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

## Over Tor

Needs a build with the `tor` feature. The sender publishes a throwaway onion
service; the address and the printed password are the only things the receiver
needs, and no relay or signaling server is involved at all. The other end may be
another CLI or a pTransfer browser tab, at most 100 MiB per transfer — and
slow enough that far less than that is the sensible size.

In the wizard, choose **Send** or **Receive** and then **Tor Onion Service**.
The sending side shows the address and password to hand over; the receiving side
asks for both after the output directory.

Test mode:

```bash
# sender: prints the address and password, then `ready`
ptransfer tor send ./file.bin

# receiver: wait for `ready`, then use both printed values. The password is
# read from stdin — prompted at a terminal, piped in from a script — so that it
# never appears in the process list.
ptransfer tor receive <address> --output ./downloads
```
