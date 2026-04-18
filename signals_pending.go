//go:build linux

package main

// signals_pending.go — the "queue on generation, deliver on resume"
// half of the Phase 3b signal state machine.
//
// Before 3b commit 3, self-targeted kill/tkill/tgkill went out as a
// real host kill(2) to the tracee's PID and the kernel's signal
// delivery machinery did the rest. The Sentry only observed the
// resulting wait4 signal-stop and decided whether to forward.
//
// Commit 3 moves delivery into the Sentry. Both self-generated
// signals (sendSelfSignal) and external signals (wait4 signal-stop)
// Enqueue a pendingSignal onto the thread's queue; the platform loop
// drains unblocked entries right before each ptraceSysemu(0) call.
// See ADR 001 §3 — the "queue on generation, check mask on delivery"
// invariant lives here.
//
// Phase 3c commit 1 (ADR 002) rehomed these methods from SignalState
// onto ThreadState: sigaltstack, pending queue, and mask are all
// per-thread in Linux, so the queue belongs next to the thread, not
// next to the shared disposition table.

import "golang.org/x/sys/unix"

// sigInfoBytes is the wire size of siginfo_t on both amd64 and arm64
// (128 bytes). The Sentry stores queued signals as opaque byte
// buffers so this file stays architecture-neutral; arch-specific
// delivery code (deliver_amd64.go) casts the buffer into its Siginfo
// struct using the kernel offsets.
const sigInfoBytes = 128

// pendingSignal is a queued-but-not-yet-delivered signal.
type pendingSignal struct {
	signo int
	info  [sigInfoBytes]byte
}

// Enqueue appends a signal to this thread's pending queue. info is
// the 128-byte wire-format siginfo_t the delivery path will embed
// into the rt_sigframe; callers that don't have a kernel-captured
// siginfo may pass a zero buffer (SI_USER-shaped siginfo is accurate
// enough for self-kill).
func (ts *ThreadState) Enqueue(signo int, info [sigInfoBytes]byte) {
	if signo < 1 || signo >= nSig {
		return
	}
	ts.group.mu.Lock()
	defer ts.group.mu.Unlock()
	ts.pending = append(ts.pending, pendingSignal{signo: signo, info: info})
}

// DequeueUnblocked pops and returns the first pending signal that is
// NOT currently blocked by this thread's mask. SIGKILL and SIGSTOP
// are unblockable and always dequeue if present. ok=false means the
// queue is empty or every entry is blocked; callers that need to
// distinguish use PendingCount.
//
// Precedence: thread-directed entries (ts.pending) outrank group-
// directed entries (tg.groupPending). gVisor makes the same choice in
// Task.dequeueSignalLocked (task_signals.go:~490) — targeted signals
// win over group-directed ones within the same mask gate.
func (ts *ThreadState) DequeueUnblocked() (pendingSignal, bool) {
	ts.group.mu.Lock()
	defer ts.group.mu.Unlock()
	if p, ok := dequeueUnblockedLocked(&ts.pending, ts.mask); ok {
		return p, true
	}
	return dequeueUnblockedLocked(&ts.group.groupPending, ts.mask)
}

// dequeueUnblockedLocked pops the first entry in q that ts's mask
// doesn't block. Shared between the per-thread and group queue
// scans. Caller must hold tg.mu.
func dequeueUnblockedLocked(q *[]pendingSignal, mask sigset) (pendingSignal, bool) {
	for i, p := range *q {
		if p.signo == int(unix.SIGKILL) || p.signo == int(unix.SIGSTOP) || !mask.has(p.signo) {
			entry := p
			*q = append((*q)[:i], (*q)[i+1:]...)
			return entry, true
		}
	}
	return pendingSignal{}, false
}

// PendingCount returns this thread's queue length. Exists for tests
// and for a one-line log at end of run.
func (ts *ThreadState) PendingCount() int {
	ts.group.mu.Lock()
	defer ts.group.mu.Unlock()
	return len(ts.pending)
}

// GroupPendingCount returns the group-directed queue length. Used by
// tests and the exit banner; a non-zero value at teardown means a
// group-directed signal was queued but never had an eligible thread
// to receive it (every thread blocked it or the group emptied first).
func (tg *ThreadGroup) GroupPendingCount() int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return len(tg.groupPending)
}

// EnqueueGroup appends a signal to the group-directed queue. Target
// of kill(tgid, sig) and any other "send to the process" path. The
// drain picks a receiver by walking tg.threads in slice order; see
// findSignalReceiverLocked.
func (tg *ThreadGroup) EnqueueGroup(signo int, info [sigInfoBytes]byte) {
	if signo < 1 || signo >= nSig {
		return
	}
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.groupPending = append(tg.groupPending, pendingSignal{signo: signo, info: info})
}

// canReceiveSignalLocked reports whether ts is eligible to receive
// signo right now. Mirrors gVisor's Task.canReceiveSignalLocked
// (task_signals.go:524): SIGKILL and SIGSTOP bypass the mask; every
// other signal is gated on the thread's per-task signal mask.
// Caller must hold tg.mu.
func (tg *ThreadGroup) canReceiveSignalLocked(ts *ThreadState, signo int) bool {
	if signo == int(unix.SIGKILL) || signo == int(unix.SIGSTOP) {
		return true
	}
	return !ts.mask.has(signo)
}

// findSignalReceiverLocked picks the thread that should take a
// group-directed signo. Walks tg.threads in attach order — the same
// deterministic traversal as gVisor's findSignalReceiverLocked
// (task_signals.go:550), minus the "prefer a thread already running"
// hint (we always pick the first eligible thread because mini-sentry
// has no notion of runnable state). Returns nil if every thread is
// currently blocking signo — the signal stays on groupPending until
// a thread unblocks it via rt_sigprocmask.
// Caller must hold tg.mu.
func (tg *ThreadGroup) findSignalReceiverLocked(signo int) *ThreadState {
	for _, ts := range tg.threads {
		if tg.canReceiveSignalLocked(ts, signo) {
			return ts
		}
	}
	return nil
}
