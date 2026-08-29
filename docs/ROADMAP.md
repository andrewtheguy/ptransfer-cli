# Roadmap

What this CLI does not do yet and means to. Everything here is specific to this
implementation; work that changes a contract both implementations follow
belongs in the web app's
[`docs/ROADMAP.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/ROADMAP.md)
instead.

## Planned

### A relay-health cache between runs

Code Exchange's clearnet fallback proves relays before the code is shown and
prepares a storage ring behind the exchange, and today it does both from
nothing on every run: the built-in seeds are probed, dead ones are replaced by
relays discovered and proven at full chunk size, and every verdict is thrown
away when the process exits. The web app keeps the same verdicts in IndexedDB
for 24 hours (`src/lib/nostr-file/relay-pool.ts`, `RelayPoolStorage`) and leads
its candidate list with relays it has already proved, so a second transfer
starts warm.

What that would mean here:

- A small store of `CachedRelay`-shaped records — last discovered, last
  succeeded, RTT, consecutive failures, and which of the two probe sizes it
  passed — merged with fresh discovery on every run rather than replacing it,
  so a sparse discovery does not discard a working fallback.
- Proven relays first in the candidate order, which is the whole benefit: the
  probe stops at its target either way, so a warm list reaches that target in
  its first batch.
- The web app's background sweep is the other half — it enumerates the relay
  population behind a transfer so the *next* one is not limited to what this
  one needed. Worth having only once there is a cache to put it in.

The open question is where the store lives. Nothing in this CLI writes to disk
today — the Tor client is assembled specifically so that no layer of it needs a
path (see `Cargo.toml`) — so a cache file under the user's cache directory is a
deliberate change of that property, not a detail. An opt-in flag, or a store
that holds only relay URLs and verdicts and nothing about any transfer, are
both ways to keep the change honest.

### Drawing an offer QR

Code Exchange's codes are carried by a person, and the web app offers two ways
to do it: a base64 blob to copy, or a grid of URL QR codes to scan. This CLI
carries the base64 half only.

The half a terminal *can* do is the drawing. `ptransfer code send` could print
the offer as the same chunked URL QR grid the web app renders, in terminal
blocks, so a phone or a laptop camera reads it straight off the screen instead
of a 1,300-character string being retyped or shuttled through a clipboard that
may not cross the machine boundary. The container and the chunking are already
specified — see `docs/CODE_EXCHANGE_PROTOCOL.md` in the web app — so this is a
rendering job, not a protocol one.

**Scanning stays out**, and that is not a scheduling decision: there is no
camera at a terminal. So a receiver's response comes back as text no matter
what, and `ptransfer code receive` still reads stdin. A QR offer therefore
helps the direction that needs it most — the offer is the larger of the two
codes — and leaves the response where it is.
