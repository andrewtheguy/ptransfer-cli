# Roadmap

What this CLI does not do yet and means to. Everything here is specific to this
implementation; work that changes a contract both implementations follow
belongs in the web app's
[`docs/ROADMAP.md`](https://github.com/andrewtheguy/ptransfer/blob/main/docs/ROADMAP.md)
instead.

## Planned

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
