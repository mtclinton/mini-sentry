//go:build linux && amd64

package main

import (
	"testing"
	"unsafe"
)

// wantPtraceRegsSize is the expected size of unix.PtraceRegs on amd64.
// The kernel's struct user_regs_struct has 27 u64 fields (r15..gs),
// so 27 × 8 = 216 bytes.
const wantPtraceRegsSize = 216

// TestRtSigframeStructSizes pins the builder's mirror-struct sizes
// against the on-wire kernel layout.  Drift here would mean
// BuildRtSigframe writes garbage into the guest, but with only a
// byte-range mismatch against the oracle — make it loud at unit-test
// time instead.  These are complements to TestFrameOffsetsPinned,
// which pins offsets; this one pins the four struct sizes named in
// the kernel ABI contract.
func TestRtSigframeStructSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"RtSigframe", unsafe.Sizeof(RtSigframe{}), 1032},
		{"Ucontext", unsafe.Sizeof(Ucontext{}), 304},
		{"MContext", unsafe.Sizeof(MContext{}), 256},
		{"Siginfo", unsafe.Sizeof(Siginfo{}), 128},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("sizeof(%s) = %d, want %d", c.name, c.got, c.want)
		}
	}
}
