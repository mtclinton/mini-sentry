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
