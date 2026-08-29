# Use Cases

The interactive interface is the TUI wizard — run `ptransfer` with no
arguments and follow the screens. The examples below show the equivalent
non-interactive commands: the `pin`, `code` and `tor` subcommands, one per
mode.

## Send Between CLI and pTransfer

Run `ptransfer`, choose **Send** and pick files and/or folders in the browser
(Space to multi-select). Enter the displayed PIN in pTransfer's receive page.
Multiple files or a folder arrive as one ZIP, exactly as if they had been sent
from the web app.

Non-interactive:

```bash
ptransfer pin send ./file.bin ./photos
```

## Receive From pTransfer

Start a send in pTransfer with **PIN Exchange**, then run `ptransfer`, choose
**Receive**, pick the output directory, and paste the PIN. There is no mode to
choose on this side — the PIN itself says which one it is.

Non-interactive (fails if the destination exists; add `--overwrite` to replace):

```bash
# The PIN is read from stdin, never from the command line
ptransfer pin receive --output ./downloads
```

## CLI to CLI

Run the wizard on both machines — **Send** on one, **Receive** on the other —
and enter the sender's PIN on the receiving side. Read the receiver's
8-character confirmation code back to the sender and enter it there to start
the transfer.

Non-interactive:

```bash
ptransfer pin send ./file.bin
ptransfer pin receive   # then type or pipe the PIN
```

## Code Exchange

Choose **Code Exchange** in the sending wizard and carry the sender code to
the receiver, then carry the receiver's response back. A browser can scan or
paste those containers; the CLI carries the same bytes as text, so either end
may be a browser tab or another CLI.

The ordinary public-Nostr fallback is automatic when no direct route can be
made and the sender could prove enough relays before showing its code. Press
`a` on the sending wizard's Code Exchange row to select the experimental Tor
fallback instead; the receiver needs no flag because the sender code names the
choice.

Non-interactive commands:

```bash
# Leave this process running after it writes the offer; it will ask for the
# receiver's response on stdin.
ptransfer code send ./file.bin > offer.txt

ptransfer code receive --output ./downloads < offer.txt > response.txt

# Paste response.txt into the still-running sender.
```

Use `ptransfer code send --anonymous ./file.bin` to select the Tor fallback.
The receiver can add `--simulate-no-direct` when deliberately exercising
either available fallback on a network where a direct connection would work.

## Over Tor

The sender publishes a throwaway onion service; the address and the printed password are the only things the receiver
needs, and no Nostr relay or signaling server is involved. Tor relays still
carry the circuits. The other end may be
another CLI or a pTransfer browser tab, at most 100 MiB per transfer — and
slow enough that far less than that is the sensible size.

In the wizard, the sending side chooses **Send** and then **Tor Onion Service**,
and gets the address and password to hand over. The receiving side chooses
**Receive**, picks the output directory and pastes the address into the same box
a PIN would go into; being an onion address is what selects this mode, and the
password is asked for on the screen after it.

Non-interactive:

```bash
# sender: prints the address and password, then `ready`
ptransfer tor send ./file.bin

# receiver: wait for `ready`, then use both printed values. The password is
# read from stdin — prompted at a terminal, piped in from a script — so that it
# never appears in the process list.
ptransfer tor receive <address> --output ./downloads
```

## Hiding your IP address from the signaling relays

Experimental. This is an ordinary
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

Non-interactive:

```bash
# sender: prints a 16-character PIN
ptransfer pin send --anonymous ./file.bin

# receiver: no flag; the PIN says the rest, and comes in on stdin
ptransfer pin receive --output ./downloads
```
