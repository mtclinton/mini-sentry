//go:build linux

package main

// signals_threadgroup.go — Phase 3c commit 1: the split between
// group-wide and per-thread signal state that ADR 002 calls for.
//
// Maps to: gVisor's kernel.SignalHandlers (per-ThreadGroup, at
// pkg/sentry/kernel/signal_handlers.go) plus the per-Task slice on
// pkg/sentry/kernel/task.go (signalMask, signalStack, pendingSignals).
// gVisor splits the state the same way we do here: the sigaction
// table is shared across every thread in the group (a sigaction from
// thread A is observable by thread B) while mask, pending queue, and
// alternate signal stack are per-thread.
//
// Commit 1 only *introduces* the types and populates one implicit
// main thread. Every existing method routes through that single
// thread so SignalState's public API — and every existing test — is
// unchanged. Routing (choosing which ThreadState a generated signal
// goes to) lands in commit 3 after commit 2 wires PTRACE_O_TRACECLONE.

import (
	"sync"

	"golang.org/x/sys/unix"
)

// ThreadGroup is the per-process shared signal state. Every
// ThreadState in .threads shares the same sigaction table and
// observability counters.
type ThreadGroup struct {
	// mu guards every mutable field on ThreadGroup and on every
	// ThreadState attached to it. A single lock is sufficient for
	// Phase 3c — gVisor uses a per-TG signalMu for the same job and
	// we can follow suit later if contention shows up.
	mu sync.Mutex

	// actions is the disposition table. A sigaction call from any
	// thread writes here once and every thread observes the update.
	actions [nSig]SigAction

	// threads is the ordered list of live threads in the group.
	// Commit 1 always holds exactly one entry (the main thread);
	// commit 2 appends on PTRACE_EVENT_CLONE and commit 3 walks
	// this slice in attach order for deterministic routing.
	threads []*ThreadState

	// groupPending is the queue of group-directed signals waiting on a
	// receiver. A signal sent via kill(tgid, sig) lands here; the
	// drain path walks tg.threads in slice order and the first thread
	// that isn't blocking signo dequeues it. Matches gVisor's
	// ThreadGroup.pendingSignals (thread_group.go:74).
	groupPending []pendingSignal

	// Observability counters — group-wide so a single kill(pid, sig)
	// routed to any thread still bumps the same `delivered` counter
	// the tests read. generated/delivered/ignored/installed
	// correspond one-for-one with what SignalState used to hold.
	delivered map[int]int
	ignored   map[int]int
	generated map[int]int
	installed map[int]int
}

// newThreadGroup returns an empty group with initialized counter
// maps. Attach a main thread with addThreadLocked before using.
func newThreadGroup() *ThreadGroup {
	return &ThreadGroup{
		delivered: make(map[int]int),
		ignored:   make(map[int]int),
		generated: make(map[int]int),
		installed: make(map[int]int),
	}
}

// addThreadLocked constructs a ThreadState for tid, links it back to
// this group, and appends it to .threads. Caller must hold tg.mu.
func (tg *ThreadGroup) addThreadLocked(tid int) *ThreadState {
	ts := &ThreadState{group: tg, tid: tid}
	tg.threads = append(tg.threads, ts)
	return ts
}

// AttachThread registers a ThreadState for tid on this group and
// returns it. If tid is already registered, the existing ThreadState
// is returned unchanged — ptrace can report EVENT_CLONE and the
// child's initial SIGSTOP in either order, and callers handle both
// by going through AttachThread, so idempotence is required.
func (tg *ThreadGroup) AttachThread(tid int) *ThreadState {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	for _, ts := range tg.threads {
		if ts.tid == tid {
			return ts
		}
	}
	return tg.addThreadLocked(tid)
}

// DetachThread removes the ThreadState with the given tid from this
// group. No-op if tid isn't registered (covers double-detach from
// e.g. EVENT_EXIT followed by the final WIFEXITED reap). After
// detach, routing (commit 3) will not pick this tid.
func (tg *ThreadGroup) DetachThread(tid int) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	for i, ts := range tg.threads {
		if ts.tid == tid {
			tg.threads = append(tg.threads[:i], tg.threads[i+1:]...)
			return
		}
	}
}

// FindThread returns the ThreadState for tid, or nil if not
// registered. Commit 2 uses this to route per-thread state updates
// (mask, altstack) to the right thread when handlers fire.
func (tg *ThreadGroup) FindThread(tid int) *ThreadState {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	for _, ts := range tg.threads {
		if ts.tid == tid {
			return ts
		}
	}
	return nil
}

// ThreadCount returns the number of live threads in the group. For
// tests and for the exit-banner summary.
func (tg *ThreadGroup) ThreadCount() int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return len(tg.threads)
}

// SetMainTid rewrites the tid of the implicit main ThreadState that
// NewSignalState created with tid=0. PtracePlatform.Run calls this
// as soon as it knows the tracee pid, so the thread registered at
// NewSignalState time ends up keyed correctly for routing.
func (ss *SignalState) SetMainTid(tid int) {
	ss.ThreadGroup.mu.Lock()
	defer ss.ThreadGroup.mu.Unlock()
	if ss.ThreadState != nil {
		ss.ThreadState.tid = tid
	}
}

// ThreadState is the per-thread signal state. Points back to its
// ThreadGroup for the shared mutex and disposition table.
type ThreadState struct {
	// group is the enclosing ThreadGroup. Non-nil for the lifetime
	// of the thread. Commit 3 removes a ThreadState from
	// group.threads on PTRACE_EVENT_EXIT.
	group *ThreadGroup

	// tid is the host thread id this ThreadState stands in for.
	// Stable for the thread's lifetime. Commit 1 keeps this at 0
	// because we don't attach to a real tracee in unit tests.
	tid int

	// mask is the per-thread signal mask — signals currently
	// blocked from delivery to this thread. rt_sigprocmask is a
	// per-thread syscall; each Task in gVisor has its own
	// signalMask for exactly this reason.
	mask sigset

	// pending is this thread's FIFO of queued signals. Entries land
	// here from self-tkill and (commit 3) from the routing pass of
	// a group-directed signal.
	pending []pendingSignal

	// altStack is the per-thread sigaltstack mirror. sigaltstack(2)
	// is per-thread in the kernel — gVisor stores it on Task
	// (signalStack), and we match that.
	altStack StackT
}

// SetAction installs a disposition for signum and bumps the installed
// counter. Group-wide: dispositions are shared across the whole
// thread group.
func (tg *ThreadGroup) SetAction(signum int, act SigAction) SigAction {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	if signum < 1 || signum >= nSig {
		return SigAction{}
	}
	old := tg.actions[signum]
	tg.actions[signum] = act
	tg.installed[signum]++
	return old
}

// GetAction returns the current disposition for signum.
func (tg *ThreadGroup) GetAction(signum int) SigAction {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	if signum < 1 || signum >= nSig {
		return SigAction{}
	}
	return tg.actions[signum]
}

// CountGenerated bumps the group-wide generated counter.
func (tg *ThreadGroup) CountGenerated(signum int) {
	tg.mu.Lock()
	tg.generated[signum]++
	tg.mu.Unlock()
}

// countDelivered bumps the group-wide delivered counter. Lowercased
// because it is only called from the platform wait loop.
func (tg *ThreadGroup) countDelivered(signum int) {
	tg.mu.Lock()
	tg.delivered[signum]++
	tg.mu.Unlock()
}

// countIgnored bumps the group-wide ignored counter.
func (tg *ThreadGroup) countIgnored(signum int) {
	tg.mu.Lock()
	tg.ignored[signum]++
	tg.mu.Unlock()
}

// SetMask updates this thread's signal mask per the rt_sigprocmask
// ABI. how is one of SIG_BLOCK (0), SIG_UNBLOCK (1), SIG_SETMASK (2).
// Returns the previous mask so the caller can write it back to
// *oldset.
func (ts *ThreadState) SetMask(how int, set sigset) sigset {
	ts.group.mu.Lock()
	defer ts.group.mu.Unlock()
	old := ts.mask
	switch how {
	case 0: // SIG_BLOCK
		ts.mask |= set
	case 1: // SIG_UNBLOCK
		ts.mask &^= set
	case 2: // SIG_SETMASK
		ts.mask = set
	}
	return old
}

// GetMask returns this thread's current mask.
func (ts *ThreadState) GetMask() sigset {
	ts.group.mu.Lock()
	defer ts.group.mu.Unlock()
	return ts.mask
}

// SetAltStack records a new alternate signal stack and returns the
// previous one. Per-thread.
func (ts *ThreadState) SetAltStack(as StackT) StackT {
	ts.group.mu.Lock()
	defer ts.group.mu.Unlock()
	old := ts.altStack
	ts.altStack = as
	return old
}

// GetAltStack returns the mirrored altstack.
func (ts *ThreadState) GetAltStack() StackT {
	ts.group.mu.Lock()
	defer ts.group.mu.Unlock()
	return ts.altStack
}

// AltStackUsable reports whether the mirrored altstack is installed,
// enabled, and big enough to park an rt_sigframe on. Same gates as
// the old SignalState method — just rehomed onto ThreadState since
// sigaltstack is per-thread.
func (ts *ThreadState) AltStackUsable() bool {
	as := ts.GetAltStack()
	if as.SS_flags&ssDisable != 0 {
		return false
	}
	if as.SS_sp == 0 || as.SS_size < minSigStkSz {
		return false
	}
	return true
}

// IsBlocked reports whether signum is currently blocked by this
// thread's mask. SIGKILL and SIGSTOP are never blockable.
func (ts *ThreadState) IsBlocked(signum int) bool {
	if signum == int(unix.SIGKILL) || signum == int(unix.SIGSTOP) {
		return false
	}
	ts.group.mu.Lock()
	defer ts.group.mu.Unlock()
	return ts.mask.has(signum)
}
