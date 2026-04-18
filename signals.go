//go:build linux

package main

// signals.go — Phase 3a: signal state + host-delivered signal routing.
//
// Maps to: gVisor's pkg/sentry/kernel/task_signals.go (+ SignalHandlers,
// SignalInfo, and the signal delivery path in Task.deliverSignal).
//
// Phase 3a is the *minimum viable* signal subsystem for mini-sentry. The
// host kernel is still the authoritative signal state — we passthrough
// rt_sigaction and rt_sigprocmask so Go's runtime continues to get its
// SIGSEGV/SIGPIPE handlers installed for real — but the Sentry now
// *mirrors* that state in its own table. That mirror gives us:
//
//   1. Observability. We can log which handler the guest installs for
//      which signal, which signals are blocked, etc. A real sandbox
//      inspects this — gVisor's Sentry makes every decision (deliver,
//      queue, default-action) from its own SignalState, never from the
//      host.
//
//   2. Signal routing. When the host kernel delivers a signal to the
//      tracee (wait4 returns a stopped-with-signal status), the platform
//      consults SignalState to decide whether to forward the signal,
//      swallow it (SIG_IGN), or allow the default action.
//
//   3. Self-targeted kill. `kill(getpid(), sig)` and `tgkill(self, sig)`
//      can be served entirely by the Sentry: ask ptrace to deliver the
//      signal to the tracee on its next resume. No kernel round-trip.
//
// Phase 3b will remove the passthrough and make the mirror authoritative
// — at that point the Sentry needs to construct sigreturn frames and
// emulate rt_sigreturn, which is a real engineering project.
//
// Phase 3c commit 1 (ADR 002) splits the state across ThreadGroup and
// ThreadState. SignalState is now a shim that embeds one of each and
// routes every public method to the single main thread. Existing
// call sites keep working unchanged; multi-thread routing lands in
// commit 3 after TRACECLONE wires in commit 2.

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// nSig is the number of signals Linux actually uses (1..64). Signal 0
// is not a real signal (it's used by kill(pid, 0) for existence checks),
// so we size by 65 and ignore index 0.
const nSig = 65

// sigsetWords is the wire format of sigset_t. On Linux sigset_t is a
// fixed-size bitmap; the kernel-side struct kernel_sigaction uses 8
// bytes (one uint64) for 64 signals. Userspace struct sigaction uses
// 16 bytes on most arches because glibc's sigset_t is padded, but the
// kernel variant (what rt_sigaction actually expects from the syscall)
// is 8 bytes. We store the canonical 8-byte form.
type sigset uint64

func (s sigset) has(signum int) bool {
	if signum < 1 || signum >= nSig {
		return false
	}
	return s&(1<<uint(signum-1)) != 0
}

//nolint:unused // exercised by signals_test.go in a follow-up commit.
func (s sigset) add(signum int) sigset {
	if signum < 1 || signum >= nSig {
		return s
	}
	return s | (1 << uint(signum-1))
}

//nolint:unused // exercised by signals_test.go in a follow-up commit.
func (s sigset) del(signum int) sigset {
	if signum < 1 || signum >= nSig {
		return s
	}
	return s &^ (1 << uint(signum-1))
}

// SigAction mirrors the Sentry's record of a guest-installed signal
// handler. We keep the raw disposition pointer (SIG_DFL, SIG_IGN, or a
// handler address) plus flags and mask — that's enough for the Phase
// 3a routing decision. In Phase 3b we'd also need the restorer pointer
// for sigreturn frame construction.
type SigAction struct {
	// handler is the userspace address of the handler, or the magic
	// sentinels 0 (SIG_DFL) and 1 (SIG_IGN). We keep it as uint64 so
	// we can compare against the raw sa_handler field from the guest.
	handler uint64

	// flags is sa_flags from the struct (SA_RESTART, SA_SIGINFO, …).
	// Used for observability; the kernel is still the one that
	// interprets these because we passthrough in Phase 3a.
	flags uint64

	// mask is the signal mask applied while the handler runs.
	mask sigset

	// restorer is sa_restorer — the userspace trampoline libc
	// installs that calls rt_sigreturn. Recorded for Phase 3b.
	restorer uint64
}

// SIG_DFL / SIG_IGN sentinels as stored in SigAction.handler.
const (
	sigDFL = 0
	sigIGN = 1
)

// sa_flags bits the Sentry interprets. Values are the Linux ABI
// constants; x/sys/unix doesn't export them on linux/amd64 as of
// v0.28.0 so we pin them here. Bits we don't interpret (SA_RESTORER,
// SA_ONSTACK, SA_NOCLDSTOP, SA_NOCLDWAIT, SA_SIGINFO) are still stored
// verbatim on SigAction.flags — they're just not branched on here.
const (
	saNoDefer   = 0x40000000 // SA_NODEFER: don't auto-add signo to mask
	saResetHand = 0x80000000 // SA_RESETHAND: flip to SIG_DFL after deliver
	saRestart   = 0x10000000 // SA_RESTART: restart interrupted syscall
	saOnStack   = 0x08000000 // SA_ONSTACK: run handler on alternate stack
)

// ss_flags bits + lower bound for a plausible altstack size. MINSIGSTKSZ
// is 2048 on amd64 per <asm-generic/signal.h>; newer CPUs with larger
// XSAVE push this up (glibc started computing it dynamically), but the
// floor protects us from a guest that points sigaltstack at a 128-byte
// buffer.
const (
	ssOnStack   = 1
	ssDisable   = 2
	minSigStkSz = 2048
)

// StackT mirrors the Linux stack_t ABI (same layout on amd64 and
// arm64): sp (u64), flags (i32) + 4 bytes pad, size (u64) — 24 bytes
// total. Lives in signals.go so cross-arch code can reference it; the
// frame builder's amd64 uc.stack write pokes the same wire layout.
type StackT struct {
	SS_sp    uint64
	SS_flags int32
	_        int32
	SS_size  uint64
}

// sigactionLayout captures the per-architecture offsets within a
// serialized kernel_sigaction struct. amd64 includes sa_restorer;
// arm64 does not. The concrete layout is defined in regs_<arch>.go
// so the handler code can stay portable.
type sigactionLayout struct {
	handlerOff  int
	flagsOff    int
	restorerOff int
	maskOff     int
	hasRestorer bool
}

// SignalState is the per-Sentry mirror of the tracee's signal
// disposition table. As of ADR 002 commit 1 it is a shim over a
// ThreadGroup + a single main ThreadState; every public method is
// promoted from the embedded types so the existing API is unchanged.
//
// Field access through embedding is intentional: tests reach through
// `ss.mask`, `ss.generated`, etc. The embedded ThreadState and
// ThreadGroup promote those fields directly so signals_test.go
// continues to work unmodified.
//
// Maps to: gVisor's kernel.SignalHandlers + Task signal slice. The
// combined type exists purely because mini-sentry currently has a
// single tracee; commit 3 will split the API along TG/TS lines once
// there's more than one thread to route to.
type SignalState struct {
	*ThreadGroup
	*ThreadState
}

// NewSignalState returns a SignalState wrapping a fresh ThreadGroup
// with one implicit main ThreadState attached. All dispositions
// default to SIG_DFL with an empty mask, matching a freshly-forked
// process.
func NewSignalState() *SignalState {
	tg := newThreadGroup()
	tg.mu.Lock()
	ts := tg.addThreadLocked(0)
	tg.mu.Unlock()
	return &SignalState{ThreadGroup: tg, ThreadState: ts}
}

// String returns a short human-readable summary for debug logs.
func (a SigAction) String() string {
	switch a.handler {
	case sigDFL:
		return "SIG_DFL"
	case sigIGN:
		return "SIG_IGN"
	default:
		return fmt.Sprintf("handler=0x%x flags=0x%x mask=0x%x", a.handler, a.flags, uint64(a.mask))
	}
}

// signalName is a tiny table for the signals we care about most. It's
// only used in log lines — any signum not in the map is rendered as
// "sigN" so we still see it.
var signalNames = map[int]string{
	int(unix.SIGHUP):  "SIGHUP",
	int(unix.SIGINT):  "SIGINT",
	int(unix.SIGQUIT): "SIGQUIT",
	int(unix.SIGILL):  "SIGILL",
	int(unix.SIGTRAP): "SIGTRAP",
	int(unix.SIGABRT): "SIGABRT",
	int(unix.SIGBUS):  "SIGBUS",
	int(unix.SIGFPE):  "SIGFPE",
	int(unix.SIGKILL): "SIGKILL",
	int(unix.SIGUSR1): "SIGUSR1",
	int(unix.SIGSEGV): "SIGSEGV",
	int(unix.SIGUSR2): "SIGUSR2",
	int(unix.SIGPIPE): "SIGPIPE",
	int(unix.SIGALRM): "SIGALRM",
	int(unix.SIGTERM): "SIGTERM",
	int(unix.SIGCHLD): "SIGCHLD",
	int(unix.SIGCONT): "SIGCONT",
	int(unix.SIGSTOP): "SIGSTOP",
	int(unix.SIGURG):  "SIGURG",
}

func signalName(signum int) string {
	if n, ok := signalNames[signum]; ok {
		return n
	}
	return fmt.Sprintf("sig%d", signum)
}
