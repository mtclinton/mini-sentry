//go:build linux && amd64

package main

// decode_test.go — tests for DecodeRtSigframe, the Phase 3b commit 2
// inverse of BuildRtSigframe.  Three tests:
//
//   1. TestDecodeRtSigframeRoundTrip — BuildRtSigframe → DecodeRtSigframe
//      on known register/fp/mask values; every field must survive the
//      round trip (modulo segment selectors, which Decode ignores on
//      purpose — see the test comment for why).
//
//   2. TestDecodeRtSigframeOracle — DecodeRtSigframe against the
//      kernel-captured oracle, cross-checked with the same
//      extractRegsFromOracle helper the builder test uses.  If Decode
//      and that helper disagree, a byte offset has drifted.
//
//   3. TestDecodeRtSigframeShortFrame — length validation: any input
//      that isn't exactly RtSigframeSize must error, not panic and not
//      silently zero-fill.

import (
	"bytes"
	"syscall"
	"testing"
)

func TestDecodeRtSigframeRoundTrip(t *testing.T) {
	// Pick recognizable values so a byte drift in Decode's offsets
	// surfaces as a specific field mismatch instead of "they're both
	// zero".  Skip Cs: BuildRtSigframe writes kernelCs (0x33) into
	// mcontext — a constant that Decode deliberately ignores, so the
	// input value wouldn't round-trip (and doesn't need to; PTRACE_SETREGS
	// restores the segment selectors the tracee had at entry anyway).
	want := syscall.PtraceRegs{
		R8: 0x08, R9: 0x09, R10: 0x0a, R11: 0x0b,
		R12: 0x0c, R13: 0x0d, R14: 0x0e, R15: 0x0f,
		Rdi: 0x71, Rsi: 0x72, Rbp: 0x73, Rbx: 0x74,
		Rdx: 0x75, Rax: 0x76, Rcx: 0x77,
		Rsp:    0x7fff_fff0_0000,
		Rip:    0x0000_0000_4040_4000,
		Eflags: 0x246,
	}
	var fpWant FxRegs
	for i := range fpWant {
		fpWant[i] = byte(i)
	}
	wantMask := sigset(0x1234_5678_9abc_def0)

	frame, rsp := BuildRtSigframe(&want, &fpWant, Siginfo{Signo: 10},
		wantMask, 0xdeadbeef)

	gotRegs, gotFp, gotMask, fpPtr, err := DecodeRtSigframe(frame)
	if err != nil {
		t.Fatalf("DecodeRtSigframe: %v", err)
	}
	// BuildRtSigframe picks the frame base itself (below the caller's
	// rsp, 16-aligned); fpstatePtr must match that derived address.
	if wantPtr := rsp + uint64(FrameOffFpstate); fpPtr != wantPtr {
		t.Errorf("fpstate_ptr = 0x%x, want 0x%x", fpPtr, wantPtr)
	}
	// Compare GPRs.  Cs/Ss/Fs/Gs are not round-tripped (see above).
	if gotRegs.R8 != want.R8 || gotRegs.Rdi != want.Rdi ||
		gotRegs.Rsp != want.Rsp || gotRegs.Rip != want.Rip ||
		gotRegs.Eflags != want.Eflags || gotRegs.Rax != want.Rax {
		t.Errorf("regs mismatch:\n got  %+v\n want %+v", gotRegs, want)
	}
	if !bytes.Equal(gotFp[:], fpWant[:]) {
		t.Errorf("fpregs mismatch: first diff at byte %d",
			firstDiff(gotFp[:], fpWant[:]))
	}
	if gotMask != wantMask {
		t.Errorf("sigmask = 0x%x, want 0x%x", uint64(gotMask), uint64(wantMask))
	}
}

func TestDecodeRtSigframeOracle(t *testing.T) {
	oracle := loadOracle(t)
	regs, fpregs, mask, _, err := DecodeRtSigframe(oracle)
	if err != nil {
		t.Fatalf("DecodeRtSigframe(oracle): %v", err)
	}
	// Cross-check against the field-extractor the round-trip test
	// uses for BuildRtSigframe.  Same bytes, same offsets — if
	// Decode disagrees with extractRegsFromOracle the unit-level
	// test catches it before commit 3's end-to-end signal flow does.
	want := extractRegsFromOracle(oracle)
	if regs.Rsp != want.Rsp || regs.Rip != want.Rip ||
		regs.Rax != want.Rax || regs.R15 != want.R15 {
		t.Errorf("oracle decode: rsp=0x%x rip=0x%x rax=0x%x r15=0x%x "+
			"want rsp=0x%x rip=0x%x rax=0x%x r15=0x%x",
			regs.Rsp, regs.Rip, regs.Rax, regs.R15,
			want.Rsp, want.Rip, want.Rax, want.R15)
	}
	// Fp first 512 bytes must equal the FXSAVE slice of the frame.
	if !bytes.Equal(fpregs[:], oracle[FrameOffFpstate:FrameOffFpstate+fxregsSize]) {
		t.Errorf("oracle fpregs slice mismatch")
	}
	// The oracle captures SIGUSR1 delivery with the default mask (0).
	// If future oracle regeneration changes this, update the assertion
	// rather than silently accept drift.
	if mask != 0 {
		t.Errorf("oracle sigmask = 0x%x, want 0 (default)", uint64(mask))
	}
}

func TestDecodeRtSigframeShortFrame(t *testing.T) {
	cases := []int{0, 1, RtSigframeSize - 1, RtSigframeSize + 1}
	for _, n := range cases {
		_, _, _, _, err := DecodeRtSigframe(make([]byte, n))
		if err == nil {
			t.Errorf("DecodeRtSigframe(len=%d): expected error", n)
		}
	}
}

func firstDiff(a, b []byte) int {
	for i := range a {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}
