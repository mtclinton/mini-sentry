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

import (
	"fmt"
	"sync"

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
)

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
// disposition table. It lives on the Sentry (single-threaded tracee
// in mini-sentry today), protected by its own mutex so the platform
// wait loop — which runs on a different code path than HandleSyscall
// — can read it without taking s.mu.
//
// Maps to: gVisor's kernel.SignalHandlers (pkg/sentry/kernel/signal_handlers.go).
type SignalState struct {
	mu sync.Mutex

	// actions[signum] is the current disposition, or zero-value
	// (SIG_DFL) for signals the guest has never touched.
	actions [nSig]SigAction

	// mask is the signal mask — signals that are blocked from
	// delivery. Matches what the guest last set via rt_sigprocmask.
	mask sigset

	// pending is the FIFO of signals queued for Sentry-driven delivery.
	// Enqueue appends; DequeueUnblocked pops the first entry that isn't
	// currently masked. Unblockable signals (SIGKILL/SIGSTOP) bypass
	// the mask check in DequeueUnblocked.
	pending []pendingSignal

	// counters for observability.
	delivered map[int]int // signum → times actually forwarded to guest
	ignored   map[int]int // signum → times suppressed by SIG_IGN mirror
	generated map[int]int // signum → times guest sent a signal via kill/tkill
	installed map[int]int // signum → times a new handler was installed
}

// NewSignalState returns an empty SignalState. All dispositions default
// to SIG_DFL with an empty mask, matching a freshly-forked process.
func NewSignalState() *SignalState {
	return &SignalState{
		delivered: make(map[int]int),
		ignored:   make(map[int]int),
		generated: make(map[int]int),
		installed: make(map[int]int),
	}
}

// SetAction records a new disposition for signum and returns the
// previous one. Called from sysRtSigaction under the Sentry mutex —
// SignalState keeps its own mutex so the platform's concurrent reads
// in the wait loop don't need to take s.mu.
func (ss *SignalState) SetAction(signum int, act SigAction) SigAction {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if signum < 1 || signum >= nSig {
		return SigAction{}
	}
	old := ss.actions[signum]
	ss.actions[signum] = act
	ss.installed[signum]++
	return old
}

// GetAction returns the current disposition for signum. Safe for
// concurrent readers (platform wait loop).
func (ss *SignalState) GetAction(signum int) SigAction {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if signum < 1 || signum >= nSig {
		return SigAction{}
	}
	return ss.actions[signum]
}

// SetMask records a new signal mask. how is one of SIG_BLOCK,
// SIG_UNBLOCK, SIG_SETMASK (the rt_sigprocmask ABI). Returns the
// previous mask so the caller can write it back to *oldset.
func (ss *SignalState) SetMask(how int, set sigset) sigset {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	old := ss.mask
	switch how {
	case 0: // SIG_BLOCK
		ss.mask |= set
	case 1: // SIG_UNBLOCK
		ss.mask &^= set
	case 2: // SIG_SETMASK
		ss.mask = set
	}
	return old
}

// GetMask returns the current mask.
func (ss *SignalState) GetMask() sigset {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.mask
}

// IsBlocked reports whether signum is currently blocked by the mask.
// Used by the platform wait loop for routing decisions. SIGKILL and
// SIGSTOP are never blockable — we special-case them here because a
// misbehaving guest might still try to set the bit.
func (ss *SignalState) IsBlocked(signum int) bool {
	if signum == int(unix.SIGKILL) || signum == int(unix.SIGSTOP) {
		return false
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.mask.has(signum)
}

// CountGenerated bumps the counter for a signal the guest generated
// (via kill / tkill / tgkill). Purely observational.
func (ss *SignalState) CountGenerated(signum int) {
	ss.mu.Lock()
	ss.generated[signum]++
	ss.mu.Unlock()
}

// countDelivered / countIgnored are called by the platform wait loop
// to keep the observability counters honest. Separate methods so the
// hot path doesn't take the mutex through a bigger API.
func (ss *SignalState) countDelivered(signum int) {
	ss.mu.Lock()
	ss.delivered[signum]++
	ss.mu.Unlock()
}

func (ss *SignalState) countIgnored(signum int) {
	ss.mu.Lock()
	ss.ignored[signum]++
	ss.mu.Unlock()
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
