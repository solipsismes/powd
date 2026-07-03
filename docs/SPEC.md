# Project: `powd` — A Minimal Unix Proof-of-Work Gateway

# powd

powd is a tiny reverse proxy implementing Hashcash-inspired proof-of-work to protect websites from mass scraping.
Its goal is not to detect humans.
Its goal is to make abusive automation computationally expensive while remaining lightweight, auditable, privacy-respecting and easy to self-host.
The project intentionally follows the Unix philosophy: do one thing, do it well.

## Vision

I want to build an open-source project called **powd** ("Proof-of-Work daemon"), a small reverse proxy that protects websites from large-scale automated scraping using a lightweight, Hashcash-inspired proof-of-work challenge.

The philosophy is **not** to compete with Cloudflare or Anubis feature-for-feature. Instead, I want something that follows the Unix philosophy:

- one program
- one responsibility
- tiny codebase
- easy to audit
- easy to self-host
- very few dependencies
- understandable by a single developer in an afternoon

Think of it as what `lighttpd` is to Apache, or `doas` is to `sudo`: a deliberately minimal implementation that solves one problem elegantly.

---

# Inspiration

The project is heavily inspired by:

- Hashcash
- Anubis
- traditional Unix daemons
- reverse proxies
- the idea that websites should remain self-hostable without relying on Cloudflare

However, I do **not** want to clone Anubis.

Instead I want to build a cleaner, smaller implementation with fewer moving parts.

---

# Name

The daemon is called:

```
powd
```

meaning:

```
Proof Of Work Daemon
```

Like:

```
sshd
httpd
crond
```

It should feel like a classic Unix service.

---

# Overall architecture

```
Internet
        │
        ▼
     nginx
        │
        ▼
      powd
        │
        ▼
application
```

Nginx proxies protected locations through `powd`.

If the client already has a valid cookie:

```
pass request through
```

Otherwise:

```
show PoW page
```

Once solved:

```
issue signed cookie
redirect back
```

No sessions should be required.

---

# Philosophy

The implementation should value:

- simplicity
- auditability
- readability
- small codebase
- deterministic behaviour
- privacy

over:

- endless anti-bot heuristics
- browser fingerprinting
- ML detection
- telemetry

The project should feel "boringly correct."

---

# Things I specifically DO NOT want

No:

- canvas fingerprinting
- font fingerprinting
- audio fingerprinting
- WebGL fingerprinting
- battery API
- mouse movement analysis
- behavioural AI detection
- telemetry
- analytics

I want to rely almost entirely on proof-of-work.

---

# Challenge flow

A client requests:

```
GET /
```

If there is no valid cookie:

Server responds with a small HTML page containing:

- nonce
- expiry
- difficulty
- JavaScript solver

The browser computes:

```
SHA256(nonce + solution)
```

until:

```
hash begins with N zero bits
```

Then POSTs:

```
nonce
solution
```

Server verifies instantly.

If valid:

Issue signed cookie.

Redirect to original URL.

---

# Stateless design

I would strongly prefer a stateless design.

Instead of storing issued challenges in Redis or a database, generate self-authenticating challenge tokens.

For example:

```
challenge =
HMAC(secret,
     expiry ||
     difficulty ||
     random)
```

The server should be able to validate challenges without server-side storage whenever practical.

Likewise, authentication cookies should be signed rather than stored.

For example, a cookie may encode:

- expiry
- user agent hash (optional)
- coarse IP prefix (optional)
- HMAC signature

The exact format is up to you.

---

# Cookie flow

Simple.

```
No cookie?

↓

Challenge

↓

Solve PoW

↓

Receive signed cookie

↓

Cookie valid for configurable duration
```

No user accounts.

No database.

---

# Challenge page

I want the HTML to be tiny.

No frameworks.

No React.

No Vue.

No Tailwind.

Just plain HTML.

Example:

```
Computing proof of work...

██████████████
```

Small amount of JavaScript.

Minimal CSS.

Fast loading.

---

# JavaScript

JavaScript is acceptable.

Like Anubis, I am fine with requiring JavaScript.

Supporting no-JS browsers is **not** a goal.

However, I would like the JavaScript to be:

- modern
- dependency-free
- clean
- readable

Possibly with an optional WebAssembly backend later.

---

# Proof-of-work algorithm

Initially:

```
SHA-256
```

Hashcash-style.

Find a value satisfying:

```
SHA256(nonce + counter)
```

with configurable leading-zero difficulty.

Keep it simple.

---

# Future possibility

Later I may want to experiment with:

- Argon2
- memory-hard puzzles
- hybrid CPU + memory cost

But **not initially**.

---

# Adaptive difficulty

This is one area where I think the design can improve over a fixed difficulty.

Instead of:

```
difficulty = 22
```

I would like the server to target approximately the same wall-clock solve time on different hardware.

For example:

Desktop:
~100 ms

Phone:
~250 ms

Old laptop:
~300 ms

Fast workstation:
~80 ms

The implementation must **not trust client claims** about performance.

If adaptive difficulty is implemented, it should derive future adjustments from observed solve times or other server-verifiable information, not arbitrary values reported by the browser.

If this complicates the initial implementation too much, start with a fixed difficulty and make adaptive difficulty an optional future feature.

---

# Configuration

I imagine something as simple as:

```toml
listen = ":8081"

cookie_age = "24h"

difficulty = 22

protect = [
    "/",
    "/blog",
    "/forum"
]

exclude = [
    "/rss",
    "/robots.txt",
    "/favicon.ico",
    "/healthz"
]
```

Minimal configuration.

Easy to understand.

---

# Deployment

Typical deployment:

```
nginx
↓

proxy_pass

↓

powd

↓

application
```

It should be trivial to drop into an existing server.

---

# Performance goals

The daemon itself should consume almost no resources.

Verification should be extremely cheap.

Only the client should pay the computational cost.

---

# Security goals

Protect against:

- replay attacks
- expired challenges
- tampered cookies
- forged challenges

without introducing excessive complexity.

---

# Code quality

Please write production-quality code.

Priorities:

1. readability
2. correctness
3. simplicity

before optimization.

Prefer small, well-documented modules.

Avoid unnecessary abstractions.

---

# Deliverables

Please design and implement:

- project architecture
- directory structure
- HTTP protocol
- challenge format
- cookie format
- configuration parser
- proof-of-work engine
- JavaScript client
- verification logic
- reverse-proxy integration
- build system
- documentation

Explain every important design decision.

Where several approaches are possible, choose the one that best matches the Unix philosophy and explain why.

The end result should feel like a small, elegant Unix daemon rather than a large anti-bot platform.
