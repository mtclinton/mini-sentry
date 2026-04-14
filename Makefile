.PHONY: build guest run clean verbose bench samples test test-quick mini-sentry

# Detect the host OS. On Linux, build natively. On macOS, cross-compile.
UNAME_OS := $(shell uname -s)
UNAME_ARCH := $(shell uname -m)

ifeq ($(UNAME_OS),Darwin)
  # Cross-compiling from macOS — target Linux.
  # Detect Mac arch to set the right Linux target.
  ifeq ($(UNAME_ARCH),arm64)
    TARGET_GOARCH ?= arm64
  else
    TARGET_GOARCH ?= amd64
  endif
  export GOOS=linux
  export GOARCH=$(TARGET_GOARCH)
endif
# On Linux, GOOS/GOARCH are unset — Go uses native defaults.

BUILD_FLAGS := CGO_ENABLED=0

# PLATFORM selects the interception mechanism for run/verbose targets.
#   PLATFORM=ptrace    (default) — PTRACE_SYSEMU on every syscall
#   PLATFORM=seccomp            — seccomp-BPF + SECCOMP_RET_USER_NOTIF
PLATFORM ?= ptrace

# GOFER selects the VFS backend for run/verbose targets.
#   GOFER=true   (default) — separate Gofer process, RPC over Unix socket
#   GOFER=false            — in-memory VFS inside the Sentry
GOFER ?= true

build: sentry-exec guest

sentry-exec: *.go go.mod
	$(BUILD_FLAGS) go build -o sentry-exec .
	@# Keep the old name around as a symlink so existing scripts and
	@# blog-post command lines still resolve. `make clean` removes both.
	@ln -sf sentry-exec mini-sentry

# Back-compat alias: `make mini-sentry` builds sentry-exec too.
mini-sentry: sentry-exec

guest: cmd/guest/main.go
	$(BUILD_FLAGS) go build -o cmd/guest/guest ./cmd/guest

run: build
	./sentry-exec --platform=$(PLATFORM) --gofer=$(GOFER) ./cmd/guest/guest

verbose: build
	MINI_SENTRY_VERBOSE=1 ./sentry-exec --platform=$(PLATFORM) --gofer=$(GOFER) ./cmd/guest/guest

# Side-by-side getpid() benchmark across both platforms.
bench: build
	@echo "=== ptrace ==="
	./sentry-exec --platform=ptrace --benchmark ./cmd/guest/guest 2>/dev/null | grep getpid
	@echo "=== seccomp ==="
	./sentry-exec --platform=seccomp --benchmark ./cmd/guest/guest 2>/dev/null | grep getpid

# Static coreutils-like binaries for testing real syscall sequences.
# Builds echo/cat/ls/pwd against glibc with -static so there's no
# dynamic-linker / libc.so loading to worry about inside the sandbox.
# Only works on a Linux host with gcc + glibc-static installed.
samples: samples/echo samples/cat samples/ls samples/pwd samples/edges samples/stress samples/sysfuzz samples/httpget

# Full comprehensive test suite: regression + samples + sysfuzz + go fuzz +
# property tests. Use FUZZTIME to control how long each fuzz target runs.
#   make test                   # default — 30s per fuzz target
#   make test FUZZTIME=10s      # quicker smoke run
#   make test VERBOSE=1         # stream all subprocess output
test:
	FUZZTIME=$(or $(FUZZTIME),30s) VERBOSE=$(or $(VERBOSE),0) ./test_all.sh

# Quick CI-friendly smoke: 5-second fuzzing, everything else at full rigor.
test-quick:
	FUZZTIME=5s ./test_all.sh

samples/%: samples/%.c
	gcc -static -O2 -o $@ $<

clean:
	rm -f sentry-exec mini-sentry cmd/guest/guest samples/echo samples/cat samples/ls samples/pwd samples/edges samples/stress samples/sysfuzz samples/httpget
