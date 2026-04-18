//go:build linux && amd64

package main

// frame_test.go — tests for the amd64 rt_sigframe builder.
//
// There are three tests:
//
//   1. TestBuildRtSigframeMatchesKernel — feeds the captured oracle's
//      own register/fp/siginfo state back through BuildRtSigframe
//      and diffs the result byte-for-byte with the oracle, masking
//      only the fields we *intentionally* diverge on:
//        - pretcode (caller-supplied restorer; oracle's is glibc's)
//        - uc.flags (oracle sets UC_FP_XSTATE; we don't — FXSAVE-only)
//        - uc.stack (oracle reflects glibc's startup alt-stack state;
//          we always write zeros for 3b)
//        - mcontext.fpstate_ptr (absolute address; differs per run)
//        - fpstate xsave_hdr tail (last 64 bytes; we leave zero,
//          kernel writes XSAVE header extension data)
//
//   2. TestFrameOffsetsPinned — pins the exported offset constants
//      against unsafe.Offsetof of the mirror struct fields.  Catches
//      drift between the constants the builder uses and the struct
//      layout cross_check_test.go validates.
//
//   3. TestBuildRtSigframeXmmPreservation — writes a known pattern
//      into the FxRegs at xmm0's FXSAVE slot, builds a frame, and
//      verifies the pattern round-trips through to frame byte offset
//      FrameOffFpstate + 160.  This is the regression test for
//      "Go SIGURG handler reads/writes xmm via ucontext" (ADR §2).

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

const oraclePath = "testdata/sigframe_amd64_sigusr1.hex"

func loadOracle(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Fatalf("read oracle %q: %v", oraclePath, err)
	}
	// File is a single line of lowercase hex + newline.
	raw = bytes.TrimSpace(raw)
	b, err := hex.DecodeString(string(raw))
	if err != nil {
		t.Fatalf("decode oracle hex: %v", err)
	}
	if len(b) != RtSigframeSize {
		t.Fatalf("oracle size = %d, want %d", len(b), RtSigframeSize)
	}
	return b
}

// Fields where our builder intentionally diverges from the kernel.
// Every byte in these ranges is excluded from the byte-exact diff.
var oracleMaskedRanges = []struct {
	off, size int
	why       string
}{
	{FrameOffPretcode, 8, "restorer is caller-supplied"},
	{FrameOffUcontext + UcOffFlags, 8, "uc.flags: kernel sets UC_FP_XSTATE, we don't"},
	{FrameOffUcontext + UcOffStack, 24, "uc.stack: glibc startup-dependent; 3b writes zeros"},
	{FrameOffFpstatePtr, 8, "mcontext.fpstate_ptr is an absolute address"},
	{FrameOffFpstate + fxregsSize, FpstateSize - fxregsSize,
		"xsave_hdr tail: we leave zero for FXRSTOR-only delivery"},
}

func diffMasked(t *testing.T, got, want []byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(want))
	}
	masked := make([]bool, len(got))
	for _, r := range oracleMaskedRanges {
		for i := r.off; i < r.off+r.size; i++ {
			masked[i] = true
		}
	}
	var diffs int
	for i := range got {
		if masked[i] {
			continue
		}
		if got[i] != want[i] {
			if diffs < 16 {
				t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, got[i], want[i])
			}
			diffs++
		}
	}
	if diffs != 0 {
		t.Fatalf("byte-exact diff failed: %d unmasked bytes differ", diffs)
	}
}

// extractRegsFromOracle reads the mcontext back out of the oracle into
// a syscall.PtraceRegs so the builder gets the same input the kernel
// had when it wrote the frame.
func extractRegsFromOracle(o []byte) *syscall.PtraceRegs {
	le := binary.LittleEndian
	mc := FrameOffUcontext + UcOffMContext
	return &syscall.PtraceRegs{
		R8:     le.Uint64(o[mc+0:]),
		R9:     le.Uint64(o[mc+8:]),
		R10:    le.Uint64(o[mc+16:]),
		R11:    le.Uint64(o[mc+24:]),
		R12:    le.Uint64(o[mc+32:]),
		R13:    le.Uint64(o[mc+40:]),
		R14:    le.Uint64(o[mc+48:]),
		R15:    le.Uint64(o[mc+56:]),
		Rdi:    le.Uint64(o[mc+McOffRdi+0:]),
		Rsi:    le.Uint64(o[mc+McOffRdi+8:]),
		Rbp:    le.Uint64(o[mc+McOffRdi+16:]),
		Rbx:    le.Uint64(o[mc+McOffRdi+24:]),
		Rdx:    le.Uint64(o[mc+McOffRdi+32:]),
		Rax:    le.Uint64(o[mc+McOffRdi+40:]),
		Rcx:    le.Uint64(o[mc+McOffRdi+48:]),
		Rsp:    le.Uint64(o[mc+McOffRsp:]),
		Rip:    le.Uint64(o[mc+McOffRip:]),
		Eflags: le.Uint64(o[mc+McOffEflags:]),
	}
}

func TestBuildRtSigframeMatchesKernel(t *testing.T) {
	oracle := loadOracle(t)
	regs := extractRegsFromOracle(oracle)

	// Copy the oracle's fpstate[0..512) out as the fake PTRACE_GETFPREGS
	// input.  We use the kernel-written bytes directly so that the
	// FXSAVE content (x87 state, MXCSR, xmm0..15) matches; we only
	// mask sw_reserved implicitly via the xsave_hdr-tail mask.
	var fpregs FxRegs
	copy(fpregs[:], oracle[FrameOffFpstate:FrameOffFpstate+fxregsSize])

	// Pull siginfo back out of the oracle into a Siginfo we can feed
	// back in.  Only the named fields; Rest is part of the masked
	// byte-range implicitly (it's zeros on both sides for SI_TKILL).
	le := binary.LittleEndian
	si := FrameOffSiginfo
	info := Siginfo{
		Signo: int32(le.Uint32(oracle[si+0:])),
		Errno: int32(le.Uint32(oracle[si+4:])),
		Code:  int32(le.Uint32(oracle[si+8:])),
		Pid:   int32(le.Uint32(oracle[si+16:])),
		Uid:   le.Uint32(oracle[si+20:]),
	}

	// Sigmask from the oracle.
	mask := sigset(le.Uint64(oracle[FrameOffUcontext+UcOffSigmask:]))

	// Restorer is masked — any value works.  Use 0xdeadbeef for clarity.
	frame, _ := BuildRtSigframe(regs, &fpregs, info, mask, 0xdeadbeef, StackT{}, 0)

	diffMasked(t, frame, oracle)
}

func TestFrameOffsetsPinned(t *testing.T) {
	// Struct-offset ground truth vs. the exported constants.
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Ucontext size", unsafe.Sizeof(Ucontext{}), UcontextSize},
		{"MContext size", unsafe.Sizeof(MContext{}), MContextSize},
		{"Siginfo size", unsafe.Sizeof(Siginfo{}), SiginfoSize},
		{"RtSigframe size", unsafe.Sizeof(RtSigframe{}), RtSigframeSize},

		{"Uc.MCtx offset", unsafe.Offsetof(Ucontext{}.MCtx), UcOffMContext},
		{"Uc.Sigmask offset", unsafe.Offsetof(Ucontext{}.Sigmask), UcOffSigmask},

		{"MC.Rsp offset", unsafe.Offsetof(MContext{}.Rsp), McOffRsp},
		{"MC.Rip offset", unsafe.Offsetof(MContext{}.Rip), McOffRip},
		{"MC.Eflags offset", unsafe.Offsetof(MContext{}.Eflags), McOffEflags},
		{"MC.Cs offset", unsafe.Offsetof(MContext{}.Cs), McOffCs},
		{"MC.Err offset", unsafe.Offsetof(MContext{}.Err), McOffErr},
		{"MC.FpstatePtr offset", unsafe.Offsetof(MContext{}.FpstatePtr), McOffFpstate},

		{"Frame.Info offset", unsafe.Offsetof(RtSigframe{}.Info), FrameOffSiginfo},
		{"Frame.Fpstate offset", unsafe.Offsetof(RtSigframe{}.Fpstate), FrameOffFpstate},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestBuildRtSigframeXmmPreservation(t *testing.T) {
	// xmm0 lives at FXSAVE offset 160 (right after 8 x87 st_space
	// slots × 16 bytes).  Go's SIGURG handler reads/writes xmm via
	// ucontext, so if the builder drops this byte range the runtime
	// will see garbage when a signal is delivered.
	const xmm0Off = 160
	var fpregs FxRegs
	pattern := []byte{
		0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	copy(fpregs[xmm0Off:], pattern)

	regs := &syscall.PtraceRegs{Rsp: 0x7fff_ff00_0000}
	frame, rsp := BuildRtSigframe(regs, &fpregs, Siginfo{Signo: 10}, 0, 0, StackT{}, 0)

	got := frame[FrameOffFpstate+xmm0Off : FrameOffFpstate+xmm0Off+16]
	if !bytes.Equal(got, pattern) {
		t.Fatalf("xmm0 slot lost or corrupted:\n got  %x\n want %x", got, pattern)
	}

	// Sanity-check the returned rsp: must be 16-aligned, live below
	// the caller's rsp, and leave at least RtSigframeSize of room.
	// These are the invariants commit 3 relies on when actually
	// placing the frame in guest memory.
	if rsp&0xf != 0 {
		t.Errorf("returned rsp = 0x%x, not 16-aligned", rsp)
	}
	if rsp >= regs.Rsp {
		t.Errorf("returned rsp = 0x%x, not below caller rsp = 0x%x", rsp, regs.Rsp)
	}
	if regs.Rsp-rsp < RtSigframeSize {
		t.Errorf("returned rsp = 0x%x, gap %d < %d", rsp, regs.Rsp-rsp, RtSigframeSize)
	}

	// The fpstate_ptr written into mcontext must equal rsp + FrameOffFpstate
	// so that rt_sigreturn finds fpstate inside the frame we just wrote.
	gotPtr := binary.LittleEndian.Uint64(frame[FrameOffFpstatePtr:])
	wantPtr := rsp + uint64(FrameOffFpstate)
	if gotPtr != wantPtr {
		t.Errorf("fpstate_ptr = 0x%x, want 0x%x (rsp + %d)",
			gotPtr, wantPtr, FrameOffFpstate)
	}
}
