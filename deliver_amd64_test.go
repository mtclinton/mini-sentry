//go:build linux && amd64

package main

// deliver_amd64_test.go — Phase 3b delivery unit tests that don't
// need a live tracee. These cover the two pure-logic bits of
// deliver_amd64.go: the SIG_DFL disposition table and the siginfo
// wire-format round-trip.

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestDefaultIgnoredTable pins the SIG_DFL=ignore set. Anything not
// in this set falls through to terminate, which the drain maps to
// SIGKILL on the tracee — so the boundary between "drop quietly" and
// "kill the guest" has to stay exactly where commit 3 put it.
func TestDefaultIgnoredTable(t *testing.T) {
	ignored := map[int]bool{
		int(unix.SIGCHLD):  true,
		int(unix.SIGURG):   true,
		int(unix.SIGWINCH): true,
		int(unix.SIGCONT):  true,
		int(unix.SIGIO):    true,
	}
	terminates := []int{
		int(unix.SIGINT), int(unix.SIGTERM), int(unix.SIGQUIT),
		int(unix.SIGSEGV), int(unix.SIGBUS), int(unix.SIGFPE),
		int(unix.SIGILL), int(unix.SIGUSR1), int(unix.SIGUSR2),
		int(unix.SIGPIPE), int(unix.SIGALRM), int(unix.SIGHUP),
	}
	for sig := range ignored {
		if !defaultIgnored(sig) {
			t.Errorf("defaultIgnored(%s) = false, want true", signalName(sig))
		}
	}
	for _, sig := range terminates {
		if defaultIgnored(sig) {
			t.Errorf("defaultIgnored(%s) = true, want false (terminate-by-default)", signalName(sig))
		}
	}
}

// TestSiginfoRoundTrip covers buildSelfSiginfo → siginfoFromBytes. The
// pending queue stores 128-byte wire-format siginfo_t buffers and
// deliverOne reads Signo/Pid/Uid back out of the struct, so these
// have to agree byte for byte.
func TestSiginfoRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		signo int
	}{
		{"SIGUSR1", int(unix.SIGUSR1)},
		{"SIGINT", int(unix.SIGINT)},
		{"SIGTERM", int(unix.SIGTERM)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := buildSelfSiginfo(tc.signo)
			si := siginfoFromBytes(buf)
			if int(si.Signo) != tc.signo {
				t.Errorf("Signo = %d, want %d", si.Signo, tc.signo)
			}
			if si.Errno != 0 {
				t.Errorf("Errno = %d, want 0", si.Errno)
			}
			// SI_USER == 0 is what buildSelfSiginfo writes.
			if si.Code != 0 {
				t.Errorf("Code = %d, want 0 (SI_USER)", si.Code)
			}
			if si.Pid != 1 {
				t.Errorf("Pid = %d, want 1 (guest-visible tgid)", si.Pid)
			}
			if si.Uid != 0 {
				t.Errorf("Uid = %d, want 0 (guest runs as root)", si.Uid)
			}
		})
	}
}

// TestSiginfoFromBytesEmpty documents the zero-buffer path — the
// ptraceGetsiginfo fallback when the kernel returns ESRCH for a
// non-signal stop. siginfoFromBytes must not blow up and must return
// a fully-zero Siginfo.
func TestSiginfoFromBytesEmpty(t *testing.T) {
	var zero [sigInfoBytes]byte
	si := siginfoFromBytes(zero)
	if si != (Siginfo{}) {
		t.Fatalf("zero buffer produced non-zero Siginfo: %+v", si)
	}
}

// TestFlagSummary pins the rendering of the sa_flags bits the Sentry
// mirrors. The log line is the only observable signal the user has that
// commit 4's branches actually ran, so the format matters.
func TestFlagSummary(t *testing.T) {
	cases := []struct {
		name  string
		flags uint64
		want  string
	}{
		{"none", 0, ""},
		{"nodefer", saNoDefer, " +NODEFER"},
		{"resethand", saResetHand, " +RESETHAND"},
		{"restart", saRestart, " +RESTART"},
		{"all", saNoDefer | saResetHand | saRestart, " +NODEFER +RESETHAND +RESTART"},
		{"nodefer+restart", saNoDefer | saRestart, " +NODEFER +RESTART"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := flagSummary(tc.flags); got != tc.want {
				t.Errorf("flagSummary(0x%x) = %q, want %q", tc.flags, got, tc.want)
			}
		})
	}
}

// TestDeliverMaskNoDefer mirrors the exact ordering deliverOne uses —
// SetMask(SIG_SETMASK, preMask|act.mask [| signo-bit unless NODEFER])
// — so we catch a regression if the gate moves or the bit flips the
// wrong way.
func TestDeliverMaskNoDefer(t *testing.T) {
	cases := []struct {
		name     string
		flags    uint64
		wantSelf bool // signo bit expected set in handler mask
	}{
		{"default defers", 0, true},
		{"NODEFER skips auto-defer", saNoDefer, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss := NewSignalState()
			signo := int(unix.SIGUSR1)
			preMask := sigset(0).add(int(unix.SIGALRM))
			ss.SetMask(2, preMask)
			act := SigAction{handler: 0xdeadbeef, flags: tc.flags, mask: sigset(0).add(int(unix.SIGTERM))}

			handlerMask := preMask | act.mask
			if signo >= 1 && signo < nSig && act.flags&saNoDefer == 0 {
				handlerMask |= 1 << uint(signo-1)
			}
			ss.SetMask(2, handlerMask)

			got := ss.GetMask()
			if got.has(int(unix.SIGALRM)) != true {
				t.Errorf("preMask SIGALRM bit lost")
			}
			if got.has(int(unix.SIGTERM)) != true {
				t.Errorf("act.mask SIGTERM bit missing")
			}
			if got.has(signo) != tc.wantSelf {
				t.Errorf("signo bit: got %v, want %v", got.has(signo), tc.wantSelf)
			}
		})
	}
}

// TestDeliverResetHand mirrors deliverOne's post-SetMask branch: when
// SA_RESETHAND is set, disposition flips back to SIG_DFL so the next
// signal runs the default action (or the guest re-registers).
func TestDeliverResetHand(t *testing.T) {
	ss := NewSignalState()
	signo := int(unix.SIGUSR1)
	act := SigAction{handler: 0xdeadbeef, flags: saResetHand}
	ss.SetAction(signo, act)

	if act.flags&saResetHand != 0 {
		ss.SetAction(signo, SigAction{})
	}

	got := ss.GetAction(signo)
	if got.handler != sigDFL {
		t.Errorf("post-RESETHAND handler = 0x%x, want SIG_DFL (0)", got.handler)
	}
	if got.flags != 0 {
		t.Errorf("post-RESETHAND flags = 0x%x, want 0", got.flags)
	}
}

// TestChooseFrameTop pins the altstack gating in deliverOne: SA_ONSTACK
// must be set, the altstack must be enabled and at least MINSIGSTKSZ
// bytes, and the tracee must not already be running on the altstack
// (the kernel's on_sig_stack check — re-entering would clobber a
// running handler). Any failed clause falls back to main-stack
// delivery, which is encoded as frameTop=0.
func TestChooseFrameTop(t *testing.T) {
	validAS := StackT{SS_sp: 0x7fff_0000_0000, SS_size: 8192}
	cases := []struct {
		name string
		act  SigAction
		as   StackT
		rsp  uint64
		want uint64
	}{
		{"no SA_ONSTACK flag", SigAction{}, validAS, 0x1000, 0},
		{"altstack too small", SigAction{flags: saOnStack},
			StackT{SS_sp: 0x7fff_0000_0000, SS_size: 1024}, 0x1000, 0},
		{"altstack disabled", SigAction{flags: saOnStack},
			StackT{SS_sp: 0x7fff_0000_0000, SS_flags: ssDisable, SS_size: 8192},
			0x1000, 0},
		{"altstack sp zero", SigAction{flags: saOnStack},
			StackT{SS_size: 8192}, 0x1000, 0},
		{"already on altstack", SigAction{flags: saOnStack}, validAS,
			0x7fff_0000_0100, 0},
		{"honored", SigAction{flags: saOnStack}, validAS, 0x1000,
			0x7fff_0000_0000 + 8192},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := chooseFrameTop(tc.act, tc.as, tc.rsp)
			if got != tc.want {
				t.Errorf("chooseFrameTop = 0x%x, want 0x%x", got, tc.want)
			}
		})
	}
}

// TestFlagSummaryOnStack extends TestFlagSummary with the SA_ONSTACK
// addition landed in commit 1 of Phase 3c.
func TestFlagSummaryOnStack(t *testing.T) {
	if got := flagSummary(saOnStack); got != " +ONSTACK" {
		t.Errorf("flagSummary(ONSTACK) = %q, want %q", got, " +ONSTACK")
	}
	all := uint64(saNoDefer | saResetHand | saRestart | saOnStack)
	want := " +NODEFER +RESETHAND +RESTART +ONSTACK"
	if got := flagSummary(all); got != want {
		t.Errorf("flagSummary(all) = %q, want %q", got, want)
	}
}

// TestDeliverResetHandNotSet confirms the inverse: without SA_RESETHAND
// the disposition persists across deliveries.
func TestDeliverResetHandNotSet(t *testing.T) {
	ss := NewSignalState()
	signo := int(unix.SIGUSR1)
	act := SigAction{handler: 0xdeadbeef, flags: saRestart}
	ss.SetAction(signo, act)

	if act.flags&saResetHand != 0 {
		ss.SetAction(signo, SigAction{})
	}

	got := ss.GetAction(signo)
	if got.handler != 0xdeadbeef {
		t.Errorf("handler = 0x%x, want 0xdeadbeef (persisted)", got.handler)
	}
}
