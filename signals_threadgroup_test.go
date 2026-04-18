//go:build linux

package main

// signals_threadgroup_test.go — unit tests for the ThreadGroup /
// ThreadState split introduced in ADR 002 commit 1.
//
// These tests exercise the types directly (not via the SignalState
// shim) so a regression in the new scaffolding shows up even if the
// shim happens to obscure it. Pure Go, no tracee.

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestThreadGroupAddThread checks that newThreadGroup yields an
// empty group and addThreadLocked produces a ThreadState wired back
// to the group.
func TestThreadGroupAddThread(t *testing.T) {
	tg := newThreadGroup()
	if len(tg.threads) != 0 {
		t.Fatalf("fresh ThreadGroup has %d threads, want 0", len(tg.threads))
	}

	tg.mu.Lock()
	ts := tg.addThreadLocked(42)
	tg.mu.Unlock()

	if ts.group != tg {
		t.Fatalf("ts.group = %p, want %p", ts.group, tg)
	}
	if ts.tid != 42 {
		t.Fatalf("ts.tid = %d, want 42", ts.tid)
	}
	if len(tg.threads) != 1 || tg.threads[0] != ts {
		t.Fatalf("tg.threads = %v, want [ts]", tg.threads)
	}
}

// TestThreadGroupActionsAreShared confirms the sigaction table is
// group-wide: a SetAction from one thread is visible via GetAction
// from a second thread attached to the same group. This is the
// invariant ADR 002 §1 cites from gVisor.
func TestThreadGroupActionsAreShared(t *testing.T) {
	tg := newThreadGroup()
	tg.mu.Lock()
	ts1 := tg.addThreadLocked(10)
	ts2 := tg.addThreadLocked(11)
	tg.mu.Unlock()
	_ = ts1
	_ = ts2

	// Install a non-default disposition; reading back from the group
	// should see it regardless of which thread initiated.
	act := SigAction{handler: 0xcafe, flags: saRestart}
	if prev := tg.SetAction(int(unix.SIGUSR1), act); prev.handler != sigDFL {
		t.Fatalf("prev handler = 0x%x, want SIG_DFL", prev.handler)
	}
	if got := tg.GetAction(int(unix.SIGUSR1)); got != act {
		t.Fatalf("GetAction(SIGUSR1) = %+v, want %+v", got, act)
	}
}

// TestThreadStateMaskIsPerThread confirms SetMask on one thread does
// NOT affect the mask on a sibling thread. Mask is per-Task in
// gVisor (task.go:157); this pins that invariant for us.
func TestThreadStateMaskIsPerThread(t *testing.T) {
	tg := newThreadGroup()
	tg.mu.Lock()
	ts1 := tg.addThreadLocked(10)
	ts2 := tg.addThreadLocked(11)
	tg.mu.Unlock()

	ts1.SetMask(2, sigset(0).add(int(unix.SIGUSR1))) // SIG_SETMASK on ts1 only

	if !ts1.IsBlocked(int(unix.SIGUSR1)) {
		t.Fatal("ts1 should see SIGUSR1 blocked after SetMask")
	}
	if ts2.IsBlocked(int(unix.SIGUSR1)) {
		t.Fatal("ts2 should NOT see SIGUSR1 blocked — mask is per-thread")
	}
}

// TestThreadStateAltStackIsPerThread — sigaltstack is per-task in
// Linux (and in gVisor). Independent ThreadStates must keep
// independent altstacks.
func TestThreadStateAltStackIsPerThread(t *testing.T) {
	tg := newThreadGroup()
	tg.mu.Lock()
	ts1 := tg.addThreadLocked(10)
	ts2 := tg.addThreadLocked(11)
	tg.mu.Unlock()

	as1 := StackT{SS_sp: 0x7fff_0000_1000, SS_size: 8192}
	as2 := StackT{SS_sp: 0x7fff_0000_2000, SS_size: 16384}

	ts1.SetAltStack(as1)
	ts2.SetAltStack(as2)

	if got := ts1.GetAltStack(); got != as1 {
		t.Fatalf("ts1 altstack = %+v, want %+v", got, as1)
	}
	if got := ts2.GetAltStack(); got != as2 {
		t.Fatalf("ts2 altstack = %+v, want %+v", got, as2)
	}
}

// TestThreadStatePendingIsPerThread — the pending queue lives on
// ThreadState. A signal enqueued onto one thread must not show up
// on another thread's queue.
func TestThreadStatePendingIsPerThread(t *testing.T) {
	tg := newThreadGroup()
	tg.mu.Lock()
	ts1 := tg.addThreadLocked(10)
	ts2 := tg.addThreadLocked(11)
	tg.mu.Unlock()

	ts1.Enqueue(int(unix.SIGUSR1), [sigInfoBytes]byte{})

	if got := ts1.PendingCount(); got != 1 {
		t.Fatalf("ts1 PendingCount = %d, want 1", got)
	}
	if got := ts2.PendingCount(); got != 0 {
		t.Fatalf("ts2 PendingCount = %d, want 0 (queue is per-thread)", got)
	}
}

// TestThreadGroupCountersAreShared — observability counters live on
// the group. Both threads hitting CountGenerated bump the same
// counter, which is what the exit-banner stats depend on.
func TestThreadGroupCountersAreShared(t *testing.T) {
	tg := newThreadGroup()
	tg.mu.Lock()
	_ = tg.addThreadLocked(10)
	_ = tg.addThreadLocked(11)
	tg.mu.Unlock()

	tg.CountGenerated(int(unix.SIGINT))
	tg.CountGenerated(int(unix.SIGINT))
	tg.countDelivered(int(unix.SIGINT))

	if got := tg.generated[int(unix.SIGINT)]; got != 2 {
		t.Fatalf("tg.generated[SIGINT] = %d, want 2", got)
	}
	if got := tg.delivered[int(unix.SIGINT)]; got != 1 {
		t.Fatalf("tg.delivered[SIGINT] = %d, want 1", got)
	}
}

// TestSignalStateShim confirms the SignalState shim correctly
// promotes fields and methods from both embedded types, and that
// both legs point at the same underlying state (i.e. modifications
// via the shim are visible via the embedded types directly).
func TestSignalStateShim(t *testing.T) {
	ss := NewSignalState()

	if ss.ThreadGroup == nil || ss.ThreadState == nil {
		t.Fatal("SignalState should embed non-nil TG and TS")
	}
	if ss.ThreadState.group != ss.ThreadGroup {
		t.Fatal("ss.ThreadState.group should point at ss.ThreadGroup")
	}
	if len(ss.ThreadGroup.threads) != 1 || ss.ThreadGroup.threads[0] != ss.ThreadState {
		t.Fatal("ss.ThreadGroup.threads should contain exactly ss.ThreadState")
	}

	// Field promotion round-trip: write ss.mask, read ss.ThreadState.mask.
	ss.mask = sigset(0).add(int(unix.SIGUSR1))
	if !ss.ThreadState.mask.has(int(unix.SIGUSR1)) {
		t.Fatal("ss.mask write did not reach ss.ThreadState.mask")
	}

	// Same for group-owned state: ss.generated[N] uses the group map.
	ss.CountGenerated(int(unix.SIGUSR2))
	if ss.ThreadGroup.generated[int(unix.SIGUSR2)] != 1 {
		t.Fatal("ss.CountGenerated did not update ss.ThreadGroup.generated")
	}
}
