BIN      := netforge
CMD      := ./cmd/netforge
OUT      := bin/$(BIN)
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: all build run install clean tidy lint test

all: build

## build: compile the binary to bin/netforge
build:
	@mkdir -p bin
	go build $(LDFLAGS) -o $(OUT) $(CMD)

## run: build and run locally (dry-run on by default for non-root)
run: build
	NETFORGE_DRY_RUN=true ./$(OUT)

## run-root: build and run with real kernel access (requires root / CAP_NET_ADMIN)
run-root: build
	sudo ./$(OUT)

## install: install binary to /usr/local/bin
install: build
	install -m 0755 $(OUT) /usr/local/bin/$(BIN)

## tidy: tidy and vendor Go modules
tidy:
	go mod tidy

## lint: run golangci-lint (install separately)
lint:
	golangci-lint run ./...

## test: run unit tests
test:
	go test -race -count=1 ./...

## clean: remove build artefacts
clean:
	rm -rf bin/

## help: list available targets
help:
	@grep -E '^##' Makefile | sed 's/## //'
