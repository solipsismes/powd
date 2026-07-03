# powd

**P**roof **o**f **w**ork **d**aemon — a tiny reverse proxy that protects
websites from mass scraping by asking each new visitor's browser for a
small, one-time Hashcash-style computation.

```
Internet → nginx → powd → application
```

A human visits once, watches a progress bar for about a second, gets a
signed cookie, and never sees the check again until it expires. A scraper
that wants a million pages under a million identities has to pay for a
million proofs of work. That asymmetry — negligible for people, expensive
at scale — is the entire idea.

powd does not try to detect humans. There is no fingerprinting, no
behavioural analysis, no telemetry, and nothing about the visitor is
collected or stored. It does one thing: it makes abusive automation cost
something.

## Properties

- **One binary, zero dependencies.** Pure Go standard library. 1,141
  lines of Go plus a 179-line challenge page; auditable in an afternoon.
- **Stateless.** Challenges and cookies are self-authenticating HMAC
  tokens. No database, no Redis, no sessions, no user accounts. The only
  state is a small bounded in-memory replay cache.
- **Cheap to run.** Issuing a challenge is one HMAC; verifying a cookie is
  two hashes (~100 ns). Only the client pays for solving.
- **Private by design.** The cookie contains an expiry, an optional
  truncated binding hash, and a MAC — nothing identifying, nothing
  recoverable.
- **Boring on purpose.** It behaves like a classic Unix daemon: a config
  file, a `-t` config check, logs to stderr, graceful shutdown on SIGTERM.

## How it works

1. A request without a valid cookie on a protected path gets a `403` with
   a small self-contained challenge page (~7 KB, no external resources).
2. The page's JavaScript searches, in parallel Web Workers, for a counter
   such that `SHA256(challenge + "." + counter)` starts with `difficulty`
   leading zero bits, using the browser's own WebCrypto SHA-256.
3. It POSTs the counter to `/.powd/verify`, receives a signed `HttpOnly`
   cookie, and reloads the page it is already on — no redirects.
4. Every later request carries the cookie and is proxied straight through.

Challenges expire in minutes and can be redeemed exactly once; cookies
last `cookie_age` and are optionally bound to the User-Agent and/or a
coarse IP prefix. Formats, threat model, and every design decision are
documented in [DESIGN.md](DESIGN.md).

## Build

Go ≥ 1.22, no other requirements:

```sh
make build        # or: go build ./cmd/powd
```

## Quick start

```sh
cp powd.toml.example powd.toml   # edit listen/upstream to taste
./powd -t -c powd.toml           # validate the configuration
./powd -c powd.toml
```

Visit a protected path in a browser: you get the interstitial once, then
straight-through proxying. See [docs/deployment.md](docs/deployment.md)
for the nginx and systemd setup.

## Configuration

A flat TOML subset: strings, integers, booleans, and string arrays.
Unknown or duplicate keys are a startup error — a typo fails at boot
rather than silently running with a default.

| Key               | Default | Meaning                                                        |
|-------------------|---------|----------------------------------------------------------------|
| `listen`          | —       | address powd listens on, e.g. `":8081"` (required)             |
| `upstream`        | —       | application URL requests are proxied to (required)             |
| `difficulty`      | `18`    | required leading zero bits; each +1 doubles client work        |
| `cookie_age`      | `"24h"` | how long an issued cookie stays valid                          |
| `challenge_age`   | `"2m"`  | how long a client has to solve a challenge                     |
| `secret_file`     | unset   | path to the persistent HMAC secret; ephemeral if unset         |
| `bind_ua`         | `true`  | bind cookies to the User-Agent header                          |
| `bind_ip`         | `false` | bind cookies to the client's /24 (IPv4) or /64 (IPv6)          |
| `insecure_cookie` | `false` | omit the cookie's `Secure` attribute (plain-HTTP testing only) |
| `protect`         | `["/"]` | path prefixes requiring proof of work                          |
| `exclude`         | `[]`    | path prefixes exempt from protection (checked first)           |

Prefixes are segment-aware: `"/blog"` covers `/blog` and `/blog/…` but
not `/blogroll`. Feeds, `robots.txt`, and health checks belong in
`exclude` so machines that should read your site still can.

## Choosing a difficulty

Expected work is `2^difficulty` hashes. Measured with the WebCrypto
solver in Chromium on ordinary desktop hardware:

| Bits | Expected hashes | Rough solve time     |
|------|-----------------|----------------------|
| 14   | 16 k            | imperceptible        |
| 16   | 65 k            | ~0.3–0.8 s (measured)|
| 18   | 262 k           | ~1–3 s (default)     |
| 20   | 1 M             | ~4–12 s              |
| 22   | 4.2 M           | ~15–60 s — hostile to humans on slow devices |

Phones run roughly 2–4× slower than desktops. When in doubt, stay at the
default and raise it only under active scraping pressure.

## Security model

powd defends against forged and tampered tokens (HMAC-SHA256 with
domain separation), expired tokens, challenge replay (a solved challenge
redeems exactly once), and path-traversal bypasses of the protect list.
Verification failures are uniform 403s that reveal nothing.

Be equally clear about what it does not do: a determined adversary with
GPUs can solve challenges cheaply — Hashcash's known limit. powd raises
the *cost* of scraping at scale; it is not an access-control system, and
a cookie is a bearer token like any session cookie. If a page must not be
scraped at all, put authentication in front of it.

Operational notes:

- Without `secret_file`, the secret is random per process: a restart
  invalidates all cookies and every client re-solves once. Set
  `secret_file` for restart-proof cookies or multiple instances.
- The secret file is created with mode `0600`; powd refuses malformed
  secret files at boot.
- powd trusts `X-Real-IP` because it is deployed behind your own nginx —
  never expose it directly to the internet with `bind_ip` enabled.

## Operations

```sh
powd -c /etc/powd.toml     # run
powd -t -c /etc/powd.toml  # validate config and exit
powd -v                    # version
```

Logs go to stderr: one line at startup, proxy errors, nothing per
request. `SIGTERM`/`SIGINT` trigger a graceful drain. There is no config
reload; restart instead (with `secret_file` set, restarts are invisible
to clients).

## Development

```sh
make test    # unit + integration tests (go test ./...)
make vet
```

The Go suite covers the full lifecycle, including solving real
challenges. A separate Playwright harness drives the actual browser flow
end to end and screenshots the interstitial — see
[e2e/README.md](e2e/README.md).

## Design

The architecture, wire formats, and the reasoning behind each decision
live in [DESIGN.md](DESIGN.md). The original project specification is
preserved as [docs/SPEC.md](docs/SPEC.md).

## License

[MIT](LICENSE)
