//go:build linux

package main

// signals_test.go — pure-logic tests for the signal mirror.
//
// These tests never touch a tracee. They exercise SignalState and the
// sigset bitmap helpers via their public Go API. If a regression ever
// breaks masking or the IS_BLOCKED decision the platform loop makes,
// these should fail before any guest program has to raise a signal.

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSigsetAddHasDel(t *testing.T) {
	cases := []struct {
		name string
		op   func(sigset) sigset
		sig  int
		has  bool
	}{
		{"add SIGINT", func(s sigset) sigset { return s.add(int(unix.SIGINT)) }, int(unix.SIGINT), true},
		{"add SIGTERM leaves SIGINT unset", func(s sigset) sigset { return s.add(int(unix.SIGTERM)) }, int(unix.SIGINT), false},
		{"add SIGTERM sets SIGTERM", func(s sigset) sigset { return s.add(int(unix.SIGTERM)) }, int(unix.SIGTERM), true},
		{"add 0 is a no-op (signal 0 isn't real)", func(s sigset) sigset { return s.add(0) }, 0, false},
		{"add 65 is a no-op (out of range)", func(s sigset) sigset { return s.add(65) }, 65, false},
		{"add 64 sets signal 64", func(s sigset) sigset { return s.add(64) }, 64, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.op(sigset(0))
			if got.has(tc.sig) != tc.has {
				t.Fatalf("has(%d) = %v, want %v (set=0x%x)", tc.sig, got.has(tc.sig), tc.has, uint64(got))
			}
		})
	}
}

// TestSigsetDelIsInverse verifies del undoes add for valid signums.
// Runs through all 64 signals so a single off-by-one shows up.
func TestSigsetDelIsInverse(t *testing.T) {
	for sig := 1; sig <= 64; sig++ {
		s := sigset(0).add(sig)
		if !s.has(sig) {
			t.Fatalf("after add(%d): has=false", sig)
		}
		s = s.del(sig)
		if s.has(sig) {
			t.Fatalf("after del(%d): has=true (set=0x%x)", sig, uint64(s))
		}
		if s != 0 {
			t.Fatalf("after add+del %d: set=0x%x, want 0", sig, uint64(s))
		}
	}
}

func TestSignalStateSetGetAction(t *testing.T) {
	ss := NewSignalState()

	// Brand-new signum returns a zero SigAction (SIG_DFL).
	got := ss.GetAction(int(unix.SIGUSR1))
	if got.handler != sigDFL {
		t.Fatalf("default SIGUSR1 handler = 0x%x, want SIG_DFL (0)", got.handler)
	}

	// SetAction returns the previous disposition.
	newAct := SigAction{handler: 0xcafe, flags: 0x1, mask: 0x2}
	prev := ss.SetAction(int(unix.SIGUSR1), newAct)
	if prev.handler != sigDFL {
		t.Fatalf("prev handler = 0x%x, want SIG_DFL", prev.handler)
	}
	if got := ss.GetAction(int(unix.SIGUSR1)); got != newAct {
		t.Fatalf("after set, got %+v, want %+v", got, newAct)
	}

	// Second SetAction returns the one we just stored.
	newer := SigAction{handler: sigIGN}
	prev = ss.SetAction(int(unix.SIGUSR1), newer)
	if prev != newAct {
		t.Fatalf("second set returned %+v, want %+v", prev, newAct)
	}

	// Out-of-range signum is a no-op; returns zero value.
	prev = ss.SetAction(100, SigAction{handler: 0xdead})
	if prev != (SigAction{}) {
		t.Fatalf("out-of-range SetAction returned %+v, want zero", prev)
	}
	if got := ss.GetAction(100); got != (SigAction{}) {
		t.Fatalf("out-of-range GetAction returned %+v, want zero", got)
	}
}

func TestSignalStateIsBlocked(t *testing.T) {
	cases := []struct {
		name    string
		mask    sigset
		sig     int
		blocked bool
	}{
		{"empty mask SIGINT", 0, int(unix.SIGINT), false},
		{"INT-only mask, SIGINT", sigset(0).add(int(unix.SIGINT)), int(unix.SIGINT), true},
		{"INT-only mask, SIGUSR1", sigset(0).add(int(unix.SIGINT)), int(unix.SIGUSR1), false},
		{"SIGKILL can never be blocked", ^sigset(0), int(unix.SIGKILL), false},
		{"SIGSTOP can never be blocked", ^sigset(0), int(unix.SIGSTOP), false},
		{"SIGTERM is blockable", ^sigset(0), int(unix.SIGTERM), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss := NewSignalState()
			ss.mask = tc.mask
			if got := ss.IsBlocked(tc.sig); got != tc.blocked {
				t.Fatalf("IsBlocked(%d) with mask=0x%x = %v, want %v",
					tc.sig, uint64(tc.mask), got, tc.blocked)
			}
		})
	}
}

func TestSignalNameFallback(t *testing.T) {
	cases := []struct {
		sig  int
		want string
	}{
		{int(unix.SIGINT), "SIGINT"},
		{int(unix.SIGURG), "SIGURG"},
		{int(unix.SIGKILL), "SIGKILL"},
		// Realtime signals and anything else fall through to "sigN".
		{34, "sig34"},
		{64, "sig64"},
		{-1, "sig-1"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := signalName(tc.sig); got != tc.want {
				t.Fatalf("signalName(%d) = %q, want %q", tc.sig, got, tc.want)
			}
		})
	}
}

// TestSigActionString locks the human-readable forms the signal-stop
// log line uses. If these drift, observers grepping logs get surprised.
func TestSigActionString(t *testing.T) {
	cases := []struct {
		name string
		act  SigAction
		want string
	}{
		{"SIG_DFL", SigAction{handler: sigDFL}, "SIG_DFL"},
		{"SIG_IGN", SigAction{handler: sigIGN}, "SIG_IGN"},
		{
			"handler",
			SigAction{handler: 0x7fffdead_beef, flags: 0x04, mask: 0x100},
			"handler=0x7fffdeadbeef flags=0x4 mask=0x100",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.act.String(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSignalStateCounters makes sure the observability counters bump
// correctly so the exit-banner stats don't silently stop counting.
func TestSignalStateCounters(t *testing.T) {
	ss := NewSignalState()
	ss.CountGenerated(int(unix.SIGURG))
	ss.CountGenerated(int(unix.SIGURG))
	ss.CountGenerated(int(unix.SIGINT))
	ss.countDelivered(int(unix.SIGURG))
	ss.countIgnored(int(unix.SIGTERM))

	if ss.generated[int(unix.SIGURG)] != 2 {
		t.Fatalf("generated[SIGURG] = %d, want 2", ss.generated[int(unix.SIGURG)])
	}
	if ss.generated[int(unix.SIGINT)] != 1 {
		t.Fatalf("generated[SIGINT] = %d, want 1", ss.generated[int(unix.SIGINT)])
	}
	if ss.delivered[int(unix.SIGURG)] != 1 {
		t.Fatalf("delivered[SIGURG] = %d, want 1", ss.delivered[int(unix.SIGURG)])
	}
	if ss.ignored[int(unix.SIGTERM)] != 1 {
		t.Fatalf("ignored[SIGTERM] = %d, want 1", ss.ignored[int(unix.SIGTERM)])
	}
	// SetAction bumps `installed`.
	ss.SetAction(int(unix.SIGINT), SigAction{handler: 0xbeef})
	if ss.installed[int(unix.SIGINT)] != 1 {
		t.Fatalf("installed[SIGINT] = %d, want 1", ss.installed[int(unix.SIGINT)])
	}
}
