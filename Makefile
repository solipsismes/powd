GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet e2e clean

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o powd ./cmd/powd

test:
	$(GO) test ./...

# Browser end-to-end test; needs Node + Playwright (see e2e/README.md).
e2e: build
	cd e2e && node browser-test.mjs

vet:
	$(GO) vet ./...

clean:
	rm -f powd
