//go:build linux && amd64

package main

// handlers_signals_amd64.go — amd64 rt_sigreturn emulation.
//
// Phase 3b, commit 2.  When the guest's signal handler returns via
// __restore_rt (the 3-byte stub glibc / the Go runtime install as
// sa_restorer), it issues an rt_sigreturn syscall.  The classical
// ABI contract: the kernel reads the rt_sigframe the caller left
// on the user stack, restores the full user register file and fp
// state, and resumes at the saved rip.
//
// In mini-sentry phase 3b, *we* are the kernel for this path.  The
// handler here is the inverse of commit 1's BuildRtSigframe:
//
//   1. PTRACE_GETREGS to recover rsp.  After the handler's `ret`
//      popped pretcode, rsp points at &ucontext; the frame base
//      (where BuildRtSigframe's offsets anchor) is rsp - 8.
//   2. process_vm_readv the 1032-byte frame out of guest memory.
//   3. DecodeRtSigframe → (regs, fpregs, mask, fpstatePtr).
//   4. Validate fpstatePtr self-consistency.  A mismatch is logged
//      but non-fatal — a handler that deliberately rewrote the
//      pointer is doing something exotic (e.g., userspace xstate
//      rehydration), and we still only restore FXSAVE.
//   5. PTRACE_SETREGS + PTRACE_SETFPREGS on the tracee.
//   6. SIG_SETMASK via the sigset the frame carried.
//   7. requestKeepRegs so the platform loop doesn't stuff rax.

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// sysRtSigreturn restores guest state from the rt_sigframe parked on
// the user stack.  Only registered on amd64 (sentry_amd64.go); other
// arches keep the passthrough entry from buildSyscallTable.
func (s *Sentry) sysRtSigreturn(_, pid int, _ SyscallArgs) uint64 {
	// Under seccomp there is no ptrace relationship — GETREGS fails
	// and we can't restore state from userspace.  Fall back to the
	// pre-3b passthrough.
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		sigLogf("GETREGS failed (%v), passthrough", err)
		s.requestPassthrough(nil)
		return 0
	}
	// After `ret` in __restore_rt the pretcode slot is popped, so
	// rsp sits at frame_base + 8.  The commit-1 oracle anchors on
	// frame_base itself, which is rsp - 8.
	frameBase := regs.Rsp - 8
	frame := readFromChild(pid, frameBase, RtSigframeSize)
	if len(frame) != RtSigframeSize {
		sigLogf("short frame@0x%x: got %d want %d", frameBase, len(frame), RtSigframeSize)
		return errno(unix.EFAULT)
	}
	newRegs, fpregs, mask, fpstatePtr, err := DecodeRtSigframe(frame)
	if err != nil {
		sigLogf("decode: %v", err)
		return errno(unix.EFAULT)
	}
	// Fpstate self-consistency: a malicious handler could point
	// fpstate_ptr elsewhere.  We only ever restore the FXSAVE bytes
	// we already read, so mismatches are noise, not an exploit.
	if wantFp := frameBase + uint64(FrameOffFpstate); fpstatePtr != wantFp {
		sigLogf("fpstate_ptr=0x%x want=0x%x (frame@0x%x)", fpstatePtr, wantFp, frameBase)
	}
	// Merge restored fields into the live regs we GETREGS'd on entry.
	// writeMContext only persists GPRs + RIP + RSP + Eflags + kernel
	// Cs/Ss constants; segment registers and FS_base / GS_base stay
	// zero in newRegs. PTRACE_SETREGS with CS=0 is rejected by the
	// kernel as non-canonical (EIO), so we keep Cs/Ss/Fs_base/Gs_base
	// and the Ds/Es/Fs/Gs selectors from the pre-sigreturn state — the
	// handler couldn't have changed them anyway (no segment-writing
	// instructions survive into userspace on x86_64).
	regs.R15 = newRegs.R15
	regs.R14 = newRegs.R14
	regs.R13 = newRegs.R13
	regs.R12 = newRegs.R12
	regs.Rbp = newRegs.Rbp
	regs.Rbx = newRegs.Rbx
	regs.R11 = newRegs.R11
	regs.R10 = newRegs.R10
	regs.R9 = newRegs.R9
	regs.R8 = newRegs.R8
	regs.Rax = newRegs.Rax
	regs.Rcx = newRegs.Rcx
	regs.Rdx = newRegs.Rdx
	regs.Rsi = newRegs.Rsi
	regs.Rdi = newRegs.Rdi
	regs.Rip = newRegs.Rip
	regs.Rsp = newRegs.Rsp
	regs.Eflags = newRegs.Eflags
	// Orig_rax: the kernel keys syscall-exit bookkeeping off this;
	// stomping it with the mcontext's zero would confuse ptrace's
	// next-syscall tracking. Leave it as GETREGS read it.
	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		sigLogf("SETREGS: %v", err)
		return errno(unix.EFAULT)
	}
	if err := SetFpregs(pid, &fpregs); err != nil {
		// GPRs already restored; fp is stale.  Keep going rather
		// than half-restore via ActionReturn.
		sigLogf("SETFPREGS: %v", err)
	}
	s.callerThread(pid).SetMask(2, mask) // SIG_SETMASK: sigreturn replaces wholesale
	s.requestKeepRegs()
	return 0
}

func sigLogf(format string, args ...any) {
	_, _ = fmt.Fprintf(logWriter(), "  [sentry] rt_sigreturn: "+format+"\n", args...)
}
