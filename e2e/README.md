# Browser end-to-end test

Verifies the piece the Go test suite cannot: the inline JavaScript solver
running in a real browser — challenge page → workers solve → verify →
cookie → reload → upstream. Also captures light/dark screenshots of the
challenge interstitial.

This is a development harness. It needs Node.js and Playwright but adds
no dependency to powd itself, which remains pure Go stdlib.

## Run

```sh
make build                          # produces ./powd at the repo root
cd e2e
npm install
npx playwright install chromium     # first time only
node browser-test.mjs
```

The script spawns its own stub upstream (port 18080) and powd
(port 18081) with a temporary config at difficulty 16, so no setup or
teardown is needed.
