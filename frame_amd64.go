//go:build linux && amd64

package main

// frame_amd64.go — kernel rt_sigframe layout for amd64 and builder.
//
// On signal delivery the kernel writes the frame onto the user stack
// low->high as:
//
//   pretcode(8) | ucontext(304) | siginfo(128) | pad(16) | fpstate(576)
//
// Total = 1032 bytes (pinned by cross_check_test.go).  The builder
// here is unused at this commit; commit 2 will call it from the
// rt_sigreturn handler and commit 3 from the signal-delivery path.
// Landing the frame first, with a byte-exact oracle, makes every
// subsequent commit testable against ground truth.
//
// Design notes (see docs/adr/001-phase3b-pure-state-signals.md):
//   * FP state is populated from PTRACE_GETFPREGS — the 512-byte
//     FXSAVE snapshot — not XSAVE.  We deliberately do NOT set
//     _UC_FP_XSTATE in uc.flags and leave fpstate.sw_reserved zero,
//     so rt_sigreturn restores via FXRSTOR only.  AVX / AVX-512 live
//     state is NOT preserved across a delivered signal (3c problem).
//   * Alt-stack (SA_ONSTACK) is out of scope for 3b; uc.stack is
//     zeroed.  Commit 3b's test binary does not install one.

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

// Size constants — pinned by cross_check_test.go.
const (
	RtSigframeSize = 1032
	UcontextSize   = 304
	MContextSize   = 256
	SiginfoSize    = 128
	FpstateSize    = 576 // FXSAVE(512) + XSAVE-header slop(64)
)

// Field offsets from the frame base (low -> high).
const (
	FrameOffPretcode = 0
	FrameOffUcontext = 8
	FrameOffSiginfo  = FrameOffUcontext + UcontextSize // 312
	// 16 bytes of alignment padding sit between siginfo and fpstate;
	// the kernel uses them to 64-align fpstate when the frame base is
	// also 64-aligned.  For now we just pin the offset — commit 3
	// will pick a frame_base that makes this address 64-aligned.
	FrameOffFpstate = 456
)

// Offsets within ucontext.
const (
	UcOffFlags    = 0
	UcOffLink     = 8
	UcOffStack    = 16
	UcOffMContext = 40
	UcOffSigmask  = UcOffMContext + MContextSize // 296
)

// Offsets within mcontext.
const (
	McOffR8       = 0  // r8..r15 live here as eight u64s
	McOffRdi      = 64 // rdi,rsi,rbp,rbx,rdx,rax,rcx follow as 7 u64s
	McOffRsp      = 120
	McOffRip      = 128
	McOffEflags   = 136
	McOffCs       = 144 // cs,gs,fs,ss — four u16s
	McOffErr      = 152 // err,trapno,oldmask,cr2 — four u64s
	McOffFpstate  = 184
	McOffReserved = 192 // [8]u64 reserved tail
)

// Frame offset of mcontext.FpstatePtr (the 8-byte self-reference that
// rt_sigreturn dereferences to find fpstate).  Handy for the test to
// mask the field during byte-exact comparison against the oracle.
const FrameOffFpstatePtr = FrameOffUcontext + UcOffMContext + McOffFpstate // 232

// Kernel segment selectors written into mcontext on signal delivery
// for a 64-bit userspace task.
const (
	kernelCs uint16 = 0x33
	kernelSs uint16 = 0x2b
)

// StackT mirrors kernel stack_t (sigaltstack).  8+4+4pad+8 = 24 bytes.
type StackT struct {
	SS_sp    uint64
	SS_flags int32
	_        int32
	SS_size  uint64
}

// MContext mirrors struct sigcontext / mcontext_t on amd64.  256 bytes.
type MContext struct {
	R8, R9, R10, R11, R12, R13, R14, R15 uint64
	Rdi, Rsi, Rbp, Rbx, Rdx, Rax, Rcx    uint64
	Rsp, Rip                             uint64
	Eflags                               uint64
	Cs, Gs, Fs, Ss                       uint16
	Err, Trapno, Oldmask, Cr2            uint64
	FpstatePtr                           uint64
	Reserved                             [8]uint64
}

// Ucontext mirrors the KERNEL shape of ucontext on amd64 (304 bytes).
// This is narrower than glibc's ucontext_t, which embeds a
// __fpregs_mem for handler convenience.  The kernel writes 304 bytes
// here; fpstate lives separately at higher addresses and is reached
// through MCtx.FpstatePtr.
type Ucontext struct {
	Flags   uint64
	Link    uint64
	Stack   StackT
	MCtx    MContext
	Sigmask uint64
}

// Siginfo mirrors kernel siginfo_t on amd64 (128 bytes).  We name
// only the common fields the builder fills from supplied input; the
// rest stays zero.  A full union for every si_code is unnecessary
// for 3b — signal delivery populates signo/errno/code/pid/uid.
type Siginfo struct {
	Signo int32
	Errno int32
	Code  int32
	_     int32
	Pid   int32
	Uid   uint32
	Rest  [104]byte
}

// RtSigframe mirrors the full 1032-byte on-stack layout written by
// the kernel on signal delivery.  Fpstate is a fixed buffer sized
// for FXSAVE plus XSAVE-header slop; the builder only populates the
// first 512 bytes (FXSAVE payload) and leaves the tail zero.
type RtSigframe struct {
	Pretcode uint64
	Uc       Ucontext
	Info     Siginfo
	_        [16]byte
	Fpstate  [FpstateSize]byte
}

// BuildRtSigframe serializes guest register state, fp state, siginfo,
// mask, and restorer pointer into a byte-exact 1032-byte rt_sigframe.
//
// Returned (frame, rsp): frame is the bytes to PTRACE_POKE into guest
// memory; rsp is the address at which the frame should be placed, so
// that mcontext.FpstatePtr (written inside the frame) points at the
// embedded fpstate slot.  The caller is responsible for the POKE and
// for setting the guest's rsp/rip before resuming into the handler.
func BuildRtSigframe(
	regs *syscall.PtraceRegs,
	fpregs *FxRegs,
	info Siginfo,
	mask sigset,
	restorer uint64,
) ([]byte, uint64) {
	// Pick rsp below the current top, rounded down to 16 (AMD64 Sys V
	// alignment).  64-byte alignment for fpstate is commit 3's job.
	newRsp := (regs.Rsp - uint64(RtSigframeSize)) &^ uint64(15)
	fpstateAddr := newRsp + uint64(FrameOffFpstate)

	buf := make([]byte, RtSigframeSize)
	le := binary.LittleEndian

	le.PutUint64(buf[FrameOffPretcode:], restorer)
	writeMContext(buf[FrameOffUcontext+UcOffMContext:], regs, fpstateAddr)
	le.PutUint64(buf[FrameOffUcontext+UcOffSigmask:], uint64(mask))
	// uc.flags=0, uc.link=0, uc.stack all-zero — see comments on
	// oracleMaskedRanges in frame_test.go for why we diverge.

	si := FrameOffSiginfo
	le.PutUint32(buf[si+0:], uint32(info.Signo))
	le.PutUint32(buf[si+4:], uint32(info.Errno))
	le.PutUint32(buf[si+8:], uint32(info.Code))
	le.PutUint32(buf[si+16:], uint32(info.Pid))
	le.PutUint32(buf[si+20:], info.Uid)

	// Copy the 512-byte FXSAVE snapshot into the start of the frame's
	// fpstate slot.  Leave the last 64 bytes zero: without the
	// FP_XSTATE_MAGIC1 cookie in sw_reserved the kernel's
	// rt_sigreturn path does FXRSTOR instead of XRSTOR.
	if fpregs != nil {
		copy(buf[FrameOffFpstate:FrameOffFpstate+fxregsSize], fpregs[:])
	}

	return buf, newRsp
}

// DecodeRtSigframe is the inverse of BuildRtSigframe: it parses the
// 1032-byte on-stack frame the kernel wrote (or the handler mutated)
// back into register, fp, and mask state that rt_sigreturn will
// restore.  The returned fpstatePtr is the absolute guest address the
// frame's mcontext claims fpstate lives at — callers validate this
// equals rsp + FrameOffFpstate to catch a malicious handler pointing
// fpstate at kernel or Sentry memory.  We do not dereference it.
func DecodeRtSigframe(frame []byte) (
	regs syscall.PtraceRegs, fpregs FxRegs, mask sigset,
	fpstatePtr uint64, err error,
) {
	if len(frame) != RtSigframeSize {
		err = fmt.Errorf("rt_sigframe length = %d, want %d", len(frame), RtSigframeSize)
		return
	}
	le := binary.LittleEndian
	fpstatePtr = readMContext(frame[FrameOffUcontext+UcOffMContext:], &regs)
	mask = sigset(le.Uint64(frame[FrameOffUcontext+UcOffSigmask:]))
	copy(fpregs[:], frame[FrameOffFpstate:FrameOffFpstate+fxregsSize])
	return
}

// writeMContext serializes a syscall.PtraceRegs into the 256-byte
// mcontext slot at mc.  fpstateAddr is the absolute guest-memory
// address rt_sigreturn will dereference to find fpstate.
func writeMContext(mc []byte, regs *syscall.PtraceRegs, fpstateAddr uint64) {
	le := binary.LittleEndian
	le.PutUint64(mc[0:], regs.R8)
	le.PutUint64(mc[8:], regs.R9)
	le.PutUint64(mc[16:], regs.R10)
	le.PutUint64(mc[24:], regs.R11)
	le.PutUint64(mc[32:], regs.R12)
	le.PutUint64(mc[40:], regs.R13)
	le.PutUint64(mc[48:], regs.R14)
	le.PutUint64(mc[56:], regs.R15)
	le.PutUint64(mc[McOffRdi+0:], regs.Rdi)
	le.PutUint64(mc[McOffRdi+8:], regs.Rsi)
	le.PutUint64(mc[McOffRdi+16:], regs.Rbp)
	le.PutUint64(mc[McOffRdi+24:], regs.Rbx)
	le.PutUint64(mc[McOffRdi+32:], regs.Rdx)
	le.PutUint64(mc[McOffRdi+40:], regs.Rax)
	le.PutUint64(mc[McOffRdi+48:], regs.Rcx)
	le.PutUint64(mc[McOffRsp:], regs.Rsp)
	le.PutUint64(mc[McOffRip:], regs.Rip)
	le.PutUint64(mc[McOffEflags:], regs.Eflags)
	le.PutUint16(mc[McOffCs+0:], kernelCs)
	le.PutUint16(mc[McOffCs+6:], kernelSs) // gs,fs stay 0; ss at Cs+6
	le.PutUint64(mc[McOffFpstate:], fpstateAddr)
	// err/trapno/oldmask/cr2 and reserved[8] stay 0.
}

// readMContext is the inverse of writeMContext: it deserializes the
// 256-byte mcontext slot at mc into regs and returns the absolute
// fpstate address the frame pointed at.  cs/gs/fs/ss selectors and
// the err/trapno/oldmask/cr2 tail are ignored — restoring them isn't
// PTRACE_SETREGS's job (segment regs need ARCH_SET_{FS,GS}; trap-info
// is kernel-only) and a malicious handler can't weaponize leaving
// them at their pre-signal values.
func readMContext(mc []byte, regs *syscall.PtraceRegs) uint64 {
	le := binary.LittleEndian
	regs.R8 = le.Uint64(mc[0:])
	regs.R9 = le.Uint64(mc[8:])
	regs.R10 = le.Uint64(mc[16:])
	regs.R11 = le.Uint64(mc[24:])
	regs.R12 = le.Uint64(mc[32:])
	regs.R13 = le.Uint64(mc[40:])
	regs.R14 = le.Uint64(mc[48:])
	regs.R15 = le.Uint64(mc[56:])
	regs.Rdi = le.Uint64(mc[McOffRdi+0:])
	regs.Rsi = le.Uint64(mc[McOffRdi+8:])
	regs.Rbp = le.Uint64(mc[McOffRdi+16:])
	regs.Rbx = le.Uint64(mc[McOffRdi+24:])
	regs.Rdx = le.Uint64(mc[McOffRdi+32:])
	regs.Rax = le.Uint64(mc[McOffRdi+40:])
	regs.Rcx = le.Uint64(mc[McOffRdi+48:])
	regs.Rsp = le.Uint64(mc[McOffRsp:])
	regs.Rip = le.Uint64(mc[McOffRip:])
	regs.Eflags = le.Uint64(mc[McOffEflags:])
	return le.Uint64(mc[McOffFpstate:])
}
