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
**Receive**, pick the output directory, and paste the PIN. There is no mode to
choose on this side — the PIN itself says which one it is.

Test mode (fails if the destination exists; add `--overwrite` to replace):

```bash
# The PIN is read from stdin, never from the command line
ptransfer test receive --output ./downloads
```

## CLI to CLI

Run the wizard on both machines — **Send** on one, **Receive** on the other —
and enter the sender's PIN on the receiving side. Read the receiver's
8-character confirmation code back to the sender and enter it there to start
the transfer.

Test mode:

```bash
ptransfer test send ./file.bin
ptransfer test receive   # then type or pipe the PIN
```

## Over Tor

Needs a build with the `tor` feature. The sender publishes a throwaway onion
service; the address and the printed password are the only things the receiver
needs, and no Nostr relay or signaling server is involved. Tor relays still
carry the circuits. The other end may be
another CLI or a pTransfer browser tab, at most 100 MiB per transfer — and
slow enough that far less than that is the sensible size.

In the wizard, the sending side chooses **Send** and then **Tor Onion Service**,
and gets the address and password to hand over. The receiving side chooses
**Receive**, picks the output directory and pastes the address into the same box
a PIN would go into; being an onion address is what selects this mode, and the
password is asked for on the screen after it.

Test mode:

```bash
# sender: prints the address and password, then `ready`
ptransfer tor send ./file.bin

# receiver: wait for `ready`, then use both printed values. The password is
# read from stdin — prompted at a terminal, piped in from a script — so that it
# never appears in the process list.
ptransfer tor receive <address> --output ./downloads
```

## Hiding your IP address from the signaling relays

Needs a build with the `tor` feature, and is experimental. This is an ordinary
PIN Exchange transfer — the file still travels over the direct WebRTC data
channel, at full speed and up to the usual 2 GiB — with only the handshake moved
onto a separate pool of Nostr relays reached as onion services. No Nostr relay
sees either device's IP address. The other WebRTC peer and the STUN servers
still do, so this is not an anonymous transfer.

The sender turns it on and gets a 16-character PIN instead of a 12-character
one. The receiver is asked nothing: the length is what says which relay pool to
look on, so pasting the PIN is the whole of it. Both sides bootstrap Tor from
cold first, which takes about a minute before anything else happens, and the
relay pool is community-maintained and monitored by nobody — expect this to fail
more often than an ordinary PIN Exchange.

In the wizard, the sending side chooses **Send**, then **PIN Exchange**, and
presses `a` to turn **Anonymous signaling** on before picking files — it is an
option of that mode, not a mode of its own, exactly as it is in the web app.
The receiving side does exactly what it does for any other PIN.

Test mode:

```bash
# sender: prints a 16-character PIN
ptransfer test send --anonymous ./file.bin

# receiver: no flag; the PIN says the rest, and comes in on stdin
ptransfer test receive --output ./downloads
```
