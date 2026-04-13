#!/usr/bin/env bash
# test_all.sh — Comprehensive test harness for mini-sentry.
#
# Runs every test layer in sequence and reports a compact pass/fail
# summary at the end. Exits non-zero if any layer failed.
#
# Layers:
#   1. Guest regression across all 4 platform×VFS combos
#   2. Sample binaries (echo, cat, ls, pwd, edges, stress)
#   3. Syscall fuzzer (sysfuzz) under ptrace and seccomp
#   4. Go fuzz targets (30s each by default; override with FUZZTIME)
#   5. Property tests
#
# Env:
#   FUZZTIME=10s   ./test_all.sh   # shorter run for CI smoke tests
#   VERBOSE=1      ./test_all.sh   # stream all output, not just summaries

set -u
cd "$(dirname "$0")"

FUZZTIME="${FUZZTIME:-30s}"
VERBOSE="${VERBOSE:-0}"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

record() {
	local name="$1" status="$2" detail="${3:-}"
	RESULTS+=("$status  $name${detail:+  — $detail}")
	case "$status" in
		PASS) PASS=$((PASS + 1)) ;;
		FAIL) FAIL=$((FAIL + 1)) ;;
		SKIP) SKIP=$((SKIP + 1)) ;;
	esac
}

run_quiet() {
	# Run $@, capture output, return status. Stream to terminal if VERBOSE.
	if [[ "$VERBOSE" = "1" ]]; then
		"$@"
		return $?
	fi
	local out
	out="$("$@" 2>&1)"
	local rc=$?
	if (( rc != 0 )); then
		printf '%s\n' "$out" >&2
	fi
	return $rc
}

section() { echo; echo "=== $* ==="; }

# ── 0. build ─────────────────────────────────────────────────────────
section "build"
if run_quiet make build; then
	echo "build ok"
else
	echo "FATAL: build failed" >&2
	exit 2
fi
if run_quiet make samples; then
	echo "samples ok"
else
	echo "FATAL: samples build failed (gcc + glibc-static required)" >&2
	exit 2
fi

# ── 1. regression across 4 combos ────────────────────────────────────
section "guest regression (4 combos)"
for p in ptrace seccomp; do
	for g in true false; do
		name="guest:platform=$p,gofer=$g"
		out="$(./mini-sentry --platform=$p --gofer=$g ./cmd/guest/guest 2>/dev/null)"
		if echo "$out" | grep -q "All tests complete"; then
			record "$name" PASS
		else
			record "$name" FAIL "no 'All tests complete' marker"
		fi
	done
done

# ── 2. sample binaries ───────────────────────────────────────────────
section "samples (ptrace)"
run_sample() {
	local name="$1" expect="$2" ; shift 2
	local got
	got="$(./mini-sentry "$@" 2>/dev/null || true)"
	if [[ "$got" == *"$expect"* ]]; then
		record "sample:$name" PASS
	else
		record "sample:$name" FAIL "output mismatch (got: $(printf '%s' "$got" | head -c 80))"
	fi
}
run_sample "echo"  "regression ok"      samples/echo "regression ok"
run_sample "cat"   "mini-sentry-sandbox" samples/cat  /etc/hostname
run_sample "ls"    "greeting.txt"        samples/ls   /
run_sample "pwd"   "/"                   samples/pwd

section "samples (edges + stress)"
for p in ptrace seccomp; do
	if ./mini-sentry --platform=$p samples/edges > /dev/null 2>&1; then
		record "edges:$p" PASS
	else
		record "edges:$p" FAIL
	fi
	if ./mini-sentry --platform=$p samples/stress > /dev/null 2>&1; then
		record "stress:$p" PASS
	else
		record "stress:$p" FAIL
	fi
done

# ── 3. sysfuzz ───────────────────────────────────────────────────────
section "sysfuzz (10k random syscalls × 2 platforms)"
for p in ptrace seccomp; do
	out="$(timeout 60 ./mini-sentry --platform=$p samples/sysfuzz 2>/dev/null | grep 'sysfuzz:' || true)"
	if [[ "$out" == *PASS* ]]; then
		record "sysfuzz:$p" PASS "$out"
	else
		record "sysfuzz:$p" FAIL
	fi
done

# ── 4. Go fuzz targets ───────────────────────────────────────────────
section "go fuzz (fuzztime=$FUZZTIME each)"
for target in FuzzResolvePath FuzzGoferProtocol FuzzSyscallArgs; do
	if run_quiet go test -run='^$' -fuzz="^${target}\$" -fuzztime="$FUZZTIME"; then
		record "fuzz:$target" PASS
	else
		record "fuzz:$target" FAIL
	fi
done

# ── 5. property tests ────────────────────────────────────────────────
section "property tests"
if run_quiet go test -run 'TestFdTable|TestVirtualOverride|TestDeny|TestInMemoryDeny|TestGoferError' -v; then
	record "property:all" PASS
else
	record "property:all" FAIL
fi

# ── summary ──────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════════"
echo "  test_all.sh summary"
echo "  ----------------------"
printf '%s\n' "${RESULTS[@]}" | sed 's/^/  /'
echo "  ----------------------"
printf '  %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
echo "═══════════════════════════════════════════════════════════════════"

exit $(( FAIL > 0 ? 1 : 0 ))
