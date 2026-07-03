GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet clean

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o powd ./cmd/powd

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -f powd
