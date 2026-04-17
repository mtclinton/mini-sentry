//go:build linux

package main

// signals_pending_test.go — tests for the Phase 3b pending queue.
//
// These tests never touch a tracee. Enqueue/DequeueUnblocked/
// PendingCount are pure Go over SignalState; if the mask check or the
// FIFO ordering regresses, these fire before the platform loop gets
// near a real signal.

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestPendingEnqueueCount(t *testing.T) {
	ss := NewSignalState()
	if got := ss.PendingCount(); got != 0 {
		t.Fatalf("fresh PendingCount = %d, want 0", got)
	}
	ss.Enqueue(int(unix.SIGUSR1), [sigInfoBytes]byte{})
	ss.Enqueue(int(unix.SIGUSR2), [sigInfoBytes]byte{})
	if got := ss.PendingCount(); got != 2 {
		t.Fatalf("PendingCount after 2 Enqueues = %d, want 2", got)
	}
}

// TestPendingEnqueueOutOfRange locks the Enqueue guard — 0 isn't a
// real signal and anything ≥nSig is off the bitmap. Either one
// silently dropping is fine; what isn't fine is a panic or a queue
// entry the drain can never handle.
func TestPendingEnqueueOutOfRange(t *testing.T) {
	ss := NewSignalState()
	ss.Enqueue(0, [sigInfoBytes]byte{})
	ss.Enqueue(nSig, [sigInfoBytes]byte{})
	ss.Enqueue(-1, [sigInfoBytes]byte{})
	ss.Enqueue(999, [sigInfoBytes]byte{})
	if got := ss.PendingCount(); got != 0 {
		t.Fatalf("PendingCount after out-of-range Enqueues = %d, want 0", got)
	}
}

func TestPendingDequeueFIFO(t *testing.T) {
	ss := NewSignalState()
	ss.Enqueue(int(unix.SIGUSR1), [sigInfoBytes]byte{})
	ss.Enqueue(int(unix.SIGUSR2), [sigInfoBytes]byte{})
	ss.Enqueue(int(unix.SIGTERM), [sigInfoBytes]byte{})

	want := []int{int(unix.SIGUSR1), int(unix.SIGUSR2), int(unix.SIGTERM)}
	for i, w := range want {
		got, ok := ss.DequeueUnblocked()
		if !ok {
			t.Fatalf("step %d: DequeueUnblocked ok=false", i)
		}
		if got.signo != w {
			t.Fatalf("step %d: signo = %d, want %d", i, got.signo, w)
		}
	}
	if _, ok := ss.DequeueUnblocked(); ok {
		t.Fatal("empty queue returned ok=true")
	}
	if got := ss.PendingCount(); got != 0 {
		t.Fatalf("PendingCount after full drain = %d, want 0", got)
	}
}

// TestPendingDequeueEmpty documents the "no panic, ok=false" contract
// the drain loop depends on — it's called every iteration of
// interceptLoop, so an empty queue must be the zero-cost path.
func TestPendingDequeueEmpty(t *testing.T) {
	ss := NewSignalState()
	if got, ok := ss.DequeueUnblocked(); ok || got.signo != 0 {
		t.Fatalf("empty DequeueUnblocked = (%+v, %v), want ({}, false)", got, ok)
	}
}

func TestPendingDequeueSkipsBlocked(t *testing.T) {
	ss := NewSignalState()
	ss.mask = sigset(0).add(int(unix.SIGUSR1))
	ss.Enqueue(int(unix.SIGUSR1), [sigInfoBytes]byte{})
	ss.Enqueue(int(unix.SIGUSR2), [sigInfoBytes]byte{})

	// Blocked SIGUSR1 is in front of the queue but must be skipped;
	// SIGUSR2 dequeues first.
	got, ok := ss.DequeueUnblocked()
	if !ok || got.signo != int(unix.SIGUSR2) {
		t.Fatalf("first drain: got=(%+v, %v), want SIGUSR2", got, ok)
	}
	// SIGUSR1 stays pending because it's blocked.
	if _, ok := ss.DequeueUnblocked(); ok {
		t.Fatal("blocked SIGUSR1 was dequeued anyway")
	}
	if got := ss.PendingCount(); got != 1 {
		t.Fatalf("PendingCount with one blocked entry = %d, want 1", got)
	}

	// Unblock SIGUSR1 and it drains.
	ss.mask = 0
	got, ok = ss.DequeueUnblocked()
	if !ok || got.signo != int(unix.SIGUSR1) {
		t.Fatalf("after unblock: got=(%+v, %v), want SIGUSR1", got, ok)
	}
}

// TestPendingKillStopUnblockable covers the two signals POSIX forbids
// from ever being blocked. Even a fully-masked tracee must see them.
func TestPendingKillStopUnblockable(t *testing.T) {
	for _, sig := range []int{int(unix.SIGKILL), int(unix.SIGSTOP)} {
		ss := NewSignalState()
		ss.mask = ^sigset(0) // block everything possible
		ss.Enqueue(sig, [sigInfoBytes]byte{})
		got, ok := ss.DequeueUnblocked()
		if !ok || got.signo != sig {
			t.Fatalf("signo=%d blocked by ^mask: got=(%+v, %v)", sig, got, ok)
		}
	}
}

// TestPendingInfoPreserved makes sure the 128-byte siginfo buffer
// round-trips through the queue unchanged — deliverOne reads si_pid/
// si_uid out of it, so any corruption would misattribute the signal
// origin to the handler.
func TestPendingInfoPreserved(t *testing.T) {
	ss := NewSignalState()
	var info [sigInfoBytes]byte
	info[0] = 0x11
	info[16] = 0x22
	info[120] = 0x33
	ss.Enqueue(int(unix.SIGUSR1), info)

	got, ok := ss.DequeueUnblocked()
	if !ok {
		t.Fatal("DequeueUnblocked ok=false")
	}
	if got.info != info {
		t.Fatalf("info round-trip mismatch:\n got=%x\nwant=%x", got.info, info)
	}
}
