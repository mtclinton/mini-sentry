//go:build linux

package main

// signals_routing_test.go — ADR 002 commit 3: tests for the
// group-vs-thread routing split. All tests drive ThreadGroup /
// ThreadState directly so a regression in routing shows up even if a
// higher-level shim papers over it.

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestGroupPendingDrainPicksEligibleThread — a group-directed signal
// lands in groupPending; the thread that the drain runs on dequeues
// it if it isn't blocking signo. gVisor mirrors this in
// findSignalReceiverLocked (task_signals.go:550) — the receiver is
// chosen at dequeue time, not at send time.
func TestGroupPendingDrainPicksEligibleThread(t *testing.T) {
	tg := newThreadGroup()
	ts1 := tg.AttachThread(10)
	ts2 := tg.AttachThread(11)

	tg.EnqueueGroup(int(unix.SIGUSR1), [sigInfoBytes]byte{})
	if got := tg.GroupPendingCount(); got != 1 {
		t.Fatalf("GroupPendingCount after EnqueueGroup = %d, want 1", got)
	}

	// ts2 drains first; groupPending should empty. ts1 sees nothing.
	if got, ok := ts2.DequeueUnblocked(); !ok || got.signo != int(unix.SIGUSR1) {
		t.Fatalf("ts2 drain: got=(%+v, %v), want SIGUSR1", got, ok)
	}
	if got := tg.GroupPendingCount(); got != 0 {
		t.Fatalf("GroupPendingCount after drain = %d, want 0", got)
	}
	if _, ok := ts1.DequeueUnblocked(); ok {
		t.Fatal("ts1 saw an already-drained group signal")
	}
}

// TestGroupPendingBlockedByMask — if the draining thread is blocking
// signo, the entry stays on groupPending. Another thread that doesn't
// block it drains cleanly. Matches canReceiveSignalLocked's mask gate.
func TestGroupPendingBlockedByMask(t *testing.T) {
	tg := newThreadGroup()
	ts1 := tg.AttachThread(10)
	ts2 := tg.AttachThread(11)

	ts1.SetMask(2, sigset(0).add(int(unix.SIGUSR1))) // SIG_SETMASK on ts1
	tg.EnqueueGroup(int(unix.SIGUSR1), [sigInfoBytes]byte{})

	// ts1 blocks it — drain is a no-op, signal stays queued.
	if _, ok := ts1.DequeueUnblocked(); ok {
		t.Fatal("ts1 drained a signal it blocks")
	}
	if got := tg.GroupPendingCount(); got != 1 {
		t.Fatalf("GroupPendingCount after blocked drain = %d, want 1", got)
	}

	// ts2 doesn't block it — drains.
	if got, ok := ts2.DequeueUnblocked(); !ok || got.signo != int(unix.SIGUSR1) {
		t.Fatalf("ts2 drain: got=(%+v, %v), want SIGUSR1", got, ok)
	}
	if got := tg.GroupPendingCount(); got != 0 {
		t.Fatalf("GroupPendingCount after ts2 drain = %d, want 0", got)
	}
}

// TestTargetedBeatsGroup — a signal on the thread's own queue dequeues
// before a group-directed entry, even if the group entry was queued
// first. Precedence matches gVisor's dequeueSignalLocked.
func TestTargetedBeatsGroup(t *testing.T) {
	tg := newThreadGroup()
	ts := tg.AttachThread(10)

	tg.EnqueueGroup(int(unix.SIGUSR2), [sigInfoBytes]byte{}) // group: older
	ts.Enqueue(int(unix.SIGUSR1), [sigInfoBytes]byte{})      // thread: newer

	got, ok := ts.DequeueUnblocked()
	if !ok || got.signo != int(unix.SIGUSR1) {
		t.Fatalf("first drain: got=(%+v, %v), want SIGUSR1 (thread beats group)", got, ok)
	}
	got, ok = ts.DequeueUnblocked()
	if !ok || got.signo != int(unix.SIGUSR2) {
		t.Fatalf("second drain: got=(%+v, %v), want SIGUSR2", got, ok)
	}
}

// TestGroupKillUnblockableBypassesMask — SIGKILL queued onto the group
// dequeues on a thread that blocks SIGKILL in its mask. The mask
// literally can't block SIGKILL but we pin the behavior so a bug in
// canReceiveSignalLocked can't strand a terminate-kill.
func TestGroupKillUnblockableBypassesMask(t *testing.T) {
	tg := newThreadGroup()
	ts := tg.AttachThread(10)
	ts.SetMask(2, ^sigset(0)) // block everything we can

	tg.EnqueueGroup(int(unix.SIGKILL), [sigInfoBytes]byte{})
	got, ok := ts.DequeueUnblocked()
	if !ok || got.signo != int(unix.SIGKILL) {
		t.Fatalf("SIGKILL through full-mask: got=(%+v, %v)", got, ok)
	}
}

// TestFindSignalReceiverWalksInOrder — the deterministic slice order is
// the whole reason we use a slice instead of a map. Later threads
// should never be picked before earlier ones if both are eligible.
func TestFindSignalReceiverWalksInOrder(t *testing.T) {
	tg := newThreadGroup()
	ts1 := tg.AttachThread(10)
	_ = tg.AttachThread(11)
	_ = tg.AttachThread(12)

	tg.mu.Lock()
	defer tg.mu.Unlock()
	if got := tg.findSignalReceiverLocked(int(unix.SIGUSR1)); got != ts1 {
		t.Fatalf("receiver for SIGUSR1 = %p, want ts1=%p", got, ts1)
	}
}

// TestFindSignalReceiverSkipsBlocked — first thread blocks signo, the
// second doesn't; the pick jumps over ts1 to ts2.
func TestFindSignalReceiverSkipsBlocked(t *testing.T) {
	tg := newThreadGroup()
	ts1 := tg.AttachThread(10)
	ts2 := tg.AttachThread(11)

	ts1.SetMask(2, sigset(0).add(int(unix.SIGUSR1)))

	tg.mu.Lock()
	defer tg.mu.Unlock()
	if got := tg.findSignalReceiverLocked(int(unix.SIGUSR1)); got != ts2 {
		t.Fatalf("receiver skipping blocked ts1: got=%p, want ts2=%p", got, ts2)
	}
}

// TestFindSignalReceiverAllBlocked — every thread blocks signo, the
// result is nil. The group queue holds the entry until some thread
// unblocks via rt_sigprocmask.
func TestFindSignalReceiverAllBlocked(t *testing.T) {
	tg := newThreadGroup()
	ts1 := tg.AttachThread(10)
	ts2 := tg.AttachThread(11)

	blocked := sigset(0).add(int(unix.SIGUSR1))
	ts1.SetMask(2, blocked)
	ts2.SetMask(2, blocked)

	tg.mu.Lock()
	defer tg.mu.Unlock()
	if got := tg.findSignalReceiverLocked(int(unix.SIGUSR1)); got != nil {
		t.Fatalf("receiver with all blocked = %p, want nil", got)
	}
}

// TestRoutingSurvivesDetach — a thread that leaves the group must no
// longer receive group signals. After detach ts1, a group-directed
// signo is picked up by the remaining ts2.
func TestRoutingSurvivesDetach(t *testing.T) {
	tg := newThreadGroup()
	_ = tg.AttachThread(10)
	ts2 := tg.AttachThread(11)

	tg.DetachThread(10)

	tg.EnqueueGroup(int(unix.SIGUSR1), [sigInfoBytes]byte{})
	got, ok := ts2.DequeueUnblocked()
	if !ok || got.signo != int(unix.SIGUSR1) {
		t.Fatalf("post-detach drain: got=(%+v, %v), want SIGUSR1", got, ok)
	}
}

// TestPerThreadQueueIsolated — a thread-directed Enqueue onto ts1
// must never show up on ts2's DequeueUnblocked.
func TestPerThreadQueueIsolated(t *testing.T) {
	tg := newThreadGroup()
	ts1 := tg.AttachThread(10)
	ts2 := tg.AttachThread(11)

	ts1.Enqueue(int(unix.SIGUSR1), [sigInfoBytes]byte{})
	if _, ok := ts2.DequeueUnblocked(); ok {
		t.Fatal("ts2 drained a signal enqueued onto ts1")
	}
	got, ok := ts1.DequeueUnblocked()
	if !ok || got.signo != int(unix.SIGUSR1) {
		t.Fatalf("ts1 drain: got=(%+v, %v), want SIGUSR1", got, ok)
	}
}
