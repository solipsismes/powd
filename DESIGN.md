# powd — Design Document

Status: draft for review, before any code is written.

This document fixes the architecture, wire protocol, challenge format, and
cookie format for powd v1, and records the reasoning behind each decision.
The guiding rule throughout: when two designs are both correct, pick the one
with fewer moving parts.

---

## 1. Language and dependencies

**Decision: Go, standard library only. Zero third-party dependencies.**

Why Go:

- `net/http` and `net/http/httputil.ReverseProxy` give us a production-grade
  HTTP server and reverse proxy in the standard library. In Rust or C we would
  need either a framework dependency or a lot of hand-written HTTP code —
  both violate the "auditable in an afternoon" goal.
- `crypto/hmac`, `crypto/sha256`, `crypto/subtle` cover all cryptography.
- Single static binary, trivial cross-compilation, no runtime to install.
  This is what makes it feel like `sshd`, not like a web app.

Why zero dependencies: the config file shown in the README is a flat TOML
subset (scalar `key = value` plus string arrays). A complete TOML library is
~5,000 lines; a parser for the subset we actually need is ~100 lines and can
be read in five minutes. We write the small parser. If the config ever needs
nesting or dates, we reconsider — it shouldn't.

Estimated total size: ~1,200 lines of Go, ~150 lines of HTML+JS.

---

## 2. Architecture

```
Internet → nginx → powd → application
```

powd is one process, one listener, no state shared between requests except
an in-memory replay cache (§6.4). One goroutine per connection, courtesy of
`net/http`. No database, no Redis, no sessions.

### 2.1 Request pipeline

Every incoming request passes through exactly one decision ladder:

```
1. Path starts with /.powd/  →  handle internally (verify endpoint), never proxied
2. Path matches exclude[]    →  proxy through
3. Path matches protect[]    →  continue to 4; otherwise proxy through
4. Valid powd cookie?        →  proxy through
5. GET/HEAD with HTML Accept →  403 + challenge page
6. Anything else             →  403 + one-line text body
```

Path matching is plain prefix matching, first match wins, `exclude` checked
before `protect`. No globs, no regex — if you need regex routing, do it in
nginx, which already has it. (Unix philosophy: don't re-implement the layer
above you.)

Step 6 exists because a POST/PUT or an API client without a cookie cannot
meaningfully receive an interstitial; the human flow always begins with a
GET navigation, which is where the challenge is served.

### 2.2 Directory structure

```
powd/
├── cmd/powd/main.go          # flag parsing, config load, wiring, signal handling
├── internal/
│   ├── config/config.go      # TOML-subset parser + validation
│   ├── token/token.go        # challenge + cookie encode/verify (all HMAC logic)
│   ├── pow/pow.go            # leading-zero-bit check on SHA-256 digests
│   ├── replay/replay.go      # bounded in-memory seen-challenge cache
│   └── server/
│       ├── server.go         # the decision ladder + reverse proxy
│       ├── verify.go         # POST /.powd/verify handler
│       └── page.html         # challenge page with inlined solver (go:embed)
├── e2e/                      # Playwright browser harness (dev-only, not a build dep)
├── powd.toml.example
├── docs/
│   ├── deployment.md         # nginx + systemd setup
│   └── SPEC.md               # the original project specification
├── Makefile                  # build / test / lint, nothing clever
├── DESIGN.md
└── README.md
```

Each `internal` package is small enough to be a single file plus a test file.
`token` is the only package touching the secret; `pow` is pure functions;
`server` composes them.

### 2.3 Trust boundary and client IP

powd is specified to sit behind nginx, so `RemoteAddr` is nginx, not the
client. powd reads the client IP from `X-Real-IP` (set by the nginx snippet
we ship). There is no "am I behind a proxy?" auto-detection — deployment is
declared, not guessed. Deterministic behaviour over cleverness.

---

## 3. HTTP protocol

powd owns the path namespace `/.powd/`. It is never proxied upstream and
should be listed nowhere; the leading dot keeps it out of casual collision
with application routes.

### 3.1 Challenge delivery

There is no separate "get a challenge" endpoint. When an unauthenticated
GET hits a protected path, the response **is** the challenge:

```
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
Cache-Control: no-store

<challenge page with embedded token, difficulty, and solver JS>
```

Why inline rather than a `GET /.powd/challenge` endpoint: one round trip,
no open-redirect machinery ("where do I go back to?" is answered by "you are
already there — reload"), and the challenge page can be fully static except
for two attribute values.

Why 403: it is honest (access is currently forbidden), it stops well-behaved
crawlers from indexing the interstitial, and unlike 401 it does not carry a
MUST-send-`WWW-Authenticate` obligation from RFC 9110. `no-store` prevents
any cache from serving a stale challenge.

The page carries the challenge in data attributes — no JSON endpoint, no
inline JSON island:

```html
<body data-challenge="powd1.1720000000.18.9f3c…" data-difficulty="18">
```

### 3.2 Verification

```
POST /.powd/verify
Content-Type: application/x-www-form-urlencoded

challenge=powd1.<expiry>.<difficulty>.<rand>.<mac>&solution=48213
```

Responses:

| Status | Meaning                                              |
|--------|------------------------------------------------------|
| 204    | Valid. `Set-Cookie: powd=…` included. Client reloads.|
| 400    | Malformed request (missing/unparseable fields).      |
| 403    | Bad MAC, expired, replayed, or wrong solution.       |

On 204 the JavaScript does `location.reload()`. The original URL never
passes through powd as a parameter, so there is no redirect target to
validate and no open-redirect class of bug at all.

403 responses are deliberately uniform (same status, same body) regardless
of *why* verification failed, so the endpoint leaks nothing useful.

### 3.3 Server verification cost

Per verify request: parse, one HMAC-SHA256, one constant-time compare, one
map lookup, one SHA-256. Microseconds. Only the client pays.

---

## 4. Challenge format

A challenge is a self-authenticating token; the server stores nothing when
issuing it.

```
powd1.<expiry>.<difficulty>.<rand>.<mac>
```

| Field        | Encoding                | Purpose                                  |
|--------------|-------------------------|------------------------------------------|
| `powd1`      | literal                 | format version; parser rejects others    |
| `expiry`     | unix seconds, decimal   | challenge TTL (config `challenge_age`, default 2m) |
| `difficulty` | decimal, leading zero **bits** | bound into the token so a client cannot ask for an easier one |
| `rand`       | 16 random bytes, hex    | uniqueness; doubles as the replay-cache key |
| `mac`        | hex HMAC-SHA256(secret, `"powd/challenge\n" + "powd1.<expiry>.<difficulty>.<rand>"`) | forgery protection |

Plain dot-separated decimal/hex text, not binary+base64: a human can read a
token off the wire and see the expiry and difficulty directly. Auditability
is a stated project value; the ~40 extra bytes are irrelevant.

The `"powd/challenge\n"` prefix is domain separation — a challenge MAC can
never be replayed as a cookie MAC or vice versa (cookies use
`"powd/cookie\n"`, §5).

### 4.1 The proof of work

The client finds a decimal counter `solution` such that:

```
SHA256( challenge_token + "." + solution )
```

has at least `difficulty` leading zero **bits**. The hash input includes the
full token, MAC and all, so work is bound to one specific server-issued
challenge and cannot be precomputed or shared across challenges.

Bits, not hex digits, because bit granularity doubles/halves expected work
per step instead of ×16, which matters once adaptive difficulty exists.

**Default difficulty: 18 bits** (≈ 262k hashes expected). With the WebCrypto
solver across `hardwareConcurrency` workers this lands in the ~0.5–3 s range
on ordinary hardware. The README's example of 22 would mean ~4.2M hashes —
tens of seconds in browser JS. The config default should embody the measured
reality, not the illustrative number; the value is one line in the config.

### 4.2 Verification order (server)

1. Parse; reject unknown version.
2. Recompute MAC; compare with `crypto/subtle.ConstantTimeCompare`. MAC
   before anything else: everything after this line is trusted data.
3. Check expiry.
4. Check `rand` against the replay cache (§6.4).
5. One SHA-256 over `token + "." + solution`; count leading zero bits
   against the difficulty *from the token*.
6. Insert `rand` into the replay cache; issue cookie.

---

## 5. Cookie format

```
Set-Cookie: powd=v1.<expiry>.<binding>.<mac>; Path=/; Max-Age=…;
            HttpOnly; SameSite=Lax; Secure
```

| Field     | Encoding              | Purpose                                       |
|-----------|-----------------------|-----------------------------------------------|
| `v1`      | literal               | format version                                |
| `expiry`  | unix seconds, decimal | cookie lifetime (config `cookie_age`, default 24h) |
| `binding` | 8-byte hex hash, or `-` | optional client binding, see below          |
| `mac`     | hex HMAC-SHA256(secret, `"powd/cookie\n" + "v1.<expiry>.<binding>"`) | integrity |

Validation on every protected request: recompute MAC (constant-time
compare), check expiry, recompute binding from the live request and compare.
Two hashes per request — negligible.

### 5.1 Binding

```
binding = hex( SHA256("powd/bind\n" + ua + "\n" + ipprefix)[:8] )
```

- `ua` — the `User-Agent` header verbatim, if `bind_ua = true` (default on).
- `ipprefix` — client IP truncated to /24 (IPv4) or /64 (IPv6), if
  `bind_ip = true` (default **off**: mobile clients hop networks constantly,
  and privacy is a stated value — with `bind_ip` off, powd never processes
  the IP beyond nginx's log).

Disabled components contribute the empty string. If both are off, the field
is the literal `-`. Because binding is recomputed from config at check time,
changing these config options simply invalidates outstanding cookies — a
clean failure mode (clients just re-solve once).

The cookie stores only a truncated hash: nothing about the user is
recoverable from the cookie value. No user ID, no session, no server-side
record. 8 bytes is plenty — binding is a hurdle for cookie sharing, not a
cryptographic identity; the MAC provides the actual integrity.

### 5.2 Cookie attributes

`HttpOnly` (page JS never needs it), `SameSite=Lax` (survives top-level
navigation, blocks CSRF-ish cross-site sends), `Path=/` (protection scopes
are powd config, not cookie scope). `Secure` is set unless config
`insecure_cookie = true` (for localhost testing).

### 5.3 Secret key

32 random bytes. If `secret_file` is set in config, read (or create with
mode 0600) at startup — cookies survive restarts and multiple powd instances
can share it. If unset, generate an ephemeral secret and log a notice; a
restart then re-challenges everyone, which is acceptable for small sites and
the zero-config default.

---

## 6. Security analysis against the stated goals

### 6.1 Forged challenges
A client-invented challenge fails the MAC check in step 1 of verification.
A client cannot lower `difficulty` because it is inside the MAC'd payload.

### 6.2 Tampered cookies
Any modification breaks the HMAC. The secret never leaves the server.
Domain-separation prefixes prevent challenge↔cookie confusion.

### 6.3 Expired challenges / cookies
Expiry is inside the MAC'd payload of both token types; checked after MAC
verification with the server clock. Challenges live minutes, cookies hours.

### 6.4 Replay
Two distinct replay surfaces:

**Challenge replay** — without defense, one solved challenge could be
redeemed repeatedly during its TTL, minting unlimited cookies for one unit
of work. Defense: an in-memory map of redeemed `rand` values, each entry
dropped at its challenge's expiry. Bounded by (redemptions/sec × challenge
TTL); a few MB at absurd rates. Capacity-capped; on overflow, oldest entries
are evicted (fail-open on memory, never crash).

This is deliberate pragmatism about "stateless": the design remains
stateless for *issuing* (no stored challenges, the expensive path under
attack) and accepts a tiny bounded cache for *redeeming*. A purist fully
stateless design simply cannot distinguish first redemption from replay;
the spec lists replay protection as a security goal, so the cache wins.
Single-process memory, not Redis — restart loses only in-flight challenges.

**Cookie replay** — cookies are bearer tokens by design; anyone holding one
passes. Bounded by expiry and (optionally) binding: a stolen cookie works
only from a matching UA (+ IP prefix if enabled). This is the same trust
model as every session cookie on the web, and per the spec we are raising
the cost of *mass* scraping, not authenticating individuals. One cookie =
one PoW; a scraper farming cookies pays per identity, which is exactly the
economics we want.

### 6.5 What powd deliberately does not defend against
A determined adversary with a GPU can solve challenges cheaply. That is
Hashcash's known limit and the spec accepts it: the goal is to make
*mass* scraping expensive, not impossible. No fingerprinting, no heuristics.

---

## 7. Challenge page and solver

One HTML page, everything inlined (CSS + JS), zero external fetches, target
< 6 KB. Content: one line of text, a `<progress>` element, `<noscript>`
explaining JS is required.

Solver design:

- `crypto.subtle.digest("SHA-256", …)` — the browser's own SHA-256, so the
  page ships **no cryptographic code to audit**. (A hand-rolled JS SHA-256
  would be ~2–5× faster; not worth the audit surface in v1. The README's
  "optional WebAssembly backend later" is the designated fast path.)
- `navigator.hardwareConcurrency` Web Workers, created from a `Blob` URL so
  the page stays self-contained. Worker *k* of *n* tests counters
  `k, k+n, k+2n, …` — disjoint by construction, no coordination.
- Each worker hashes in batches (~256) between progress messages; first
  worker to find a solution wins, main thread terminates the rest and POSTs.
- On 204: `location.reload()`. On failure: show a plain error line.
- Total: ~120 lines of modern, dependency-free JS.

Progress bar: expected work is 2^difficulty hashes, so the bar shows
`1 - (1 - 2^-d)^hashes` — an honest "probability we'd have finished by now"
rather than a fake animation.

---

## 8. Configuration

Complete v1 config surface (README keys plus the minimum the README implies
but omits — chiefly `upstream`, without which there is nothing to proxy to):

```toml
# powd.toml
listen        = ":8081"                  # required
upstream      = "http://127.0.0.1:8080"  # required
difficulty    = 18                       # leading zero bits
cookie_age    = "24h"
challenge_age = "2m"
secret_file   = "/var/lib/powd/secret"   # optional; ephemeral if unset
bind_ua       = true
bind_ip       = false
insecure_cookie = false                  # true only for local HTTP testing

protect = ["/"]
exclude = ["/rss", "/robots.txt", "/favicon.ico", "/healthz"]
```

Ten keys. Durations use Go's `time.ParseDuration` syntax. Unknown keys are
a startup **error**, not a warning — a typo'd `dificulty` must not silently
run with defaults. Fail loud at boot, run quiet forever.

CLI surface, in the tradition of `sshd -t`:

```
powd -c /etc/powd.toml    # run
powd -t -c /etc/powd.toml # test config and exit
powd -v                   # version
```

Logs to stderr, one line per event that matters (startup, config errors,
verify failures at debug level). No log files, no rotation — that's the
service manager's job.

---

## 9. Adaptive difficulty — deferred, with a designed hook

Deferred from v1 per the README's own escape hatch. Recording the analysis
so v2 doesn't start from zero:

The only server-verifiable timing signal is *(verify time − challenge issue
time)*, and the issue timestamp is already in the MAC'd token
(`expiry − challenge_age`), so **the v1 token format already carries
everything adaptive difficulty needs** — no format change later.

The trap to avoid: per-client adaptation is gameable. A client that stalls
before submitting looks slow; if the server responds by lowering difficulty,
stalling becomes an attack that costs the attacker nothing but latency.
Any future mechanism must adapt on *aggregate* solve-time percentiles or on
load signals (verify requests/sec), never on a single client's observed
time, and difficulty should be clamped to a configured floor. v1 ships
fixed difficulty; the config key stays the same, its default just becomes a
target rather than a constant.

---

## 10. Implementation plan

Order chosen so every step is testable before the next begins; pure logic
first, I/O last.

1. `git init`; module scaffold; Makefile; commit the docs.
2. `internal/config` — parser + validation + tests (table-driven, includes
   malformed-input cases).
3. `internal/token` — challenge/cookie mint + verify + tests (tampering,
   expiry, cross-domain confusion, constant-time comparison).
4. `internal/pow` — leading-zero-bit counting + tests with known vectors.
5. `internal/replay` — bounded TTL cache + tests.
6. `internal/server` — decision ladder, reverse proxy, verify endpoint;
   `httptest`-based tests including a Go-side solver (the test suite solves
   real challenges, proving client and server agree on the hash input).
7. Challenge page + solver JS; manual browser test against a toy upstream.
8. End-to-end test: toy upstream + powd + scripted client, full cookie
   lifecycle.
9. `powd.toml.example`, deployment guide in `docs/deployment.md`,
   user-facing README (install, deploy, security notes).

Each step is one commit (or a few); the repo is green at every commit.
