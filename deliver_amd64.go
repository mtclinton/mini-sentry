//go:build linux && amd64

package main

// deliver_amd64.go — Sentry-driven signal delivery on amd64.
//
// This is the "inverse" of handlers_signals_amd64.go's sysRtSigreturn:
// we BUILD an rt_sigframe from scratch, write it onto the tracee's
// stack, and redirect RIP into the handler. rt_sigreturn later undoes
// our work to restore pre-signal state.
//
// Phase 3b commit 3 (ADR 001 §3) integrates this with the platform
// loop: every ptraceSysemu(pid, 0) call is preceded by a
// deliverPending(pid) drain. Pending signals land on the queue via
// two paths — sendSelfSignal (Sentry-generated) and the wait4
// signal-stop branch in interceptLoop (host-delivered). Both enqueue
// 128-byte siginfo buffers; this file is where the buffers become
// real signals.

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// deliveryResult tells the caller (interceptLoop) what the drain did,
// so the resume after a drain knows whether to forward a signal to the
// kernel or resume with 0. Phase 3b's drain is at most one custom
// handler per call — two stacked frames would share registers we
// saved only once — so at most one of {delivered, terminate} is true
// per deliverPending run.
type deliveryResult struct {
	// terminate, if nonzero, means the drain hit a SIG_DFL-terminate
	// signal and the caller should kill the tracee. We don't do the
	// kill here because the caller also owns the wait4 loop.
	terminate int
}

// deliverPending drains unblocked entries from the Sentry's pending
// queue. SIG_IGN and SIG_DFL-ignored signals are dropped quietly;
// SIG_DFL-terminate signals return via result.terminate so the caller
// can act; custom handlers cause exactly one frame to be built
// (further pending signals stay queued until the handler's
// rt_sigreturn triggers the next drain). Safe to call when the queue
// is empty — returns zero result.
func (p *PtracePlatform) deliverPending(pid int) (deliveryResult, error) {
	for {
		sig, ok := p.sentry.signals.DequeueUnblocked()
		if !ok {
			return deliveryResult{}, nil
		}
		act := p.sentry.signals.GetAction(sig.signo)
		switch act.handler {
		case sigIGN:
			p.sentry.signals.countIgnored(sig.signo)
			continue
		case sigDFL:
			if defaultIgnored(sig.signo) {
				p.sentry.signals.countIgnored(sig.signo)
				continue
			}
			return deliveryResult{terminate: sig.signo}, nil
		default:
			if err := p.deliverOne(pid, sig, act); err != nil {
				return deliveryResult{}, err
			}
			p.sentry.signals.countDelivered(sig.signo)
			return deliveryResult{}, nil
		}
	}
}

// deliverOne builds a single rt_sigframe on the tracee's stack and
// redirects RIP to the handler. On return the tracee is set up so
// that the next ptraceSysemu(pid, 0) enters the handler with:
//
//	rdi = signo
//	rsi = &siginfo  (inside frame)
//	rdx = &ucontext (inside frame)
//	rsp = frame base
//	rip = act.handler
//
// Mask update matches POSIX: current | sa_mask, plus signo itself
// (automatic one-shot defer). SA_NODEFER is commit 4's job.
func (p *PtracePlatform) deliverOne(pid int, sig pendingSignal, act SigAction) error {
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return fmt.Errorf("deliverOne GETREGS: %w", err)
	}
	fpregs, err := GetFpregs(pid)
	if err != nil {
		return fmt.Errorf("deliverOne GETFPREGS: %w", err)
	}
	info := siginfoFromBytes(sig.info)
	preMask := p.sentry.signals.GetMask()
	frameRegs := syscallRegsFromUnix(&regs)
	frame, newRsp := BuildRtSigframe(&frameRegs, &fpregs, info, preMask, act.restorer)
	writeToChild(pid, newRsp, frame)

	regs.Rsp = newRsp
	regs.Rip = act.handler
	regs.Rdi = uint64(sig.signo)
	regs.Rsi = newRsp + uint64(FrameOffSiginfo)
	regs.Rdx = newRsp + uint64(FrameOffUcontext)
	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		return fmt.Errorf("deliverOne SETREGS: %w", err)
	}
	handlerMask := preMask | act.mask
	if sig.signo >= 1 && sig.signo < nSig {
		handlerMask |= 1 << uint(sig.signo-1)
	}
	p.sentry.signals.SetMask(2, handlerMask) // SIG_SETMASK
	_, _ = fmt.Fprintf(logWriter(),
		"  [sentry] deliver %s → handler=0x%x rsp=0x%x (preMask=0x%x)\n",
		signalName(sig.signo), act.handler, newRsp, uint64(preMask))
	return nil
}

// siginfoFromBytes deserializes a 128-byte wire-format siginfo_t into
// the named Siginfo struct. The queued buffer is whatever the kernel
// wrote via PTRACE_GETSIGINFO (external path) or what
// buildSelfSiginfo fabricated (internal path); either way these five
// fields plus Rest cover everything BuildRtSigframe needs.
func siginfoFromBytes(b [sigInfoBytes]byte) Siginfo {
	le := binary.LittleEndian
	var si Siginfo
	si.Signo = int32(le.Uint32(b[0:]))
	si.Errno = int32(le.Uint32(b[4:]))
	si.Code = int32(le.Uint32(b[8:]))
	si.Pid = int32(le.Uint32(b[16:]))
	si.Uid = le.Uint32(b[20:])
	copy(si.Rest[:], b[24:])
	return si
}

// syscallRegsFromUnix is the inverse of ptraceRegsFromSyscall in
// regs_amd64.go. Both structs mirror the kernel's user_regs_struct
// and have identical layout, but Go disallows direct conversion
// between distinct named types.
func syscallRegsFromUnix(in *unix.PtraceRegs) syscall.PtraceRegs {
	return syscall.PtraceRegs{
		R15: in.R15, R14: in.R14, R13: in.R13, R12: in.R12,
		Rbp: in.Rbp, Rbx: in.Rbx,
		R11: in.R11, R10: in.R10, R9: in.R9, R8: in.R8,
		Rax: in.Rax, Rcx: in.Rcx, Rdx: in.Rdx,
		Rsi: in.Rsi, Rdi: in.Rdi,
		Orig_rax: in.Orig_rax,
		Rip:      in.Rip,
		Cs:       in.Cs,
		Eflags:   in.Eflags,
		Rsp:      in.Rsp,
		Ss:       in.Ss,
		Fs_base:  in.Fs_base,
		Gs_base:  in.Gs_base,
		Ds:       in.Ds, Es: in.Es, Fs: in.Fs, Gs: in.Gs,
	}
}

// defaultIgnored returns true for signals whose SIG_DFL action is
// "ignore" per POSIX. The complement set — terminate-by-default — is
// the interesting one: the caller kills the tracee for those. Stop/
// continue signals are out of scope for commit 3 (the Sentry has no
// stopped-state bookkeeping yet).
//
// SIGCHLD/SIGURG/SIGWINCH/SIGIO are all "informational"; SIGCONT
// resumes a stopped task and defaults to ignore when the task isn't
// stopped, which is always the case in our tracee lifecycle.
func defaultIgnored(signo int) bool {
	switch signo {
	case int(unix.SIGCHLD), int(unix.SIGURG), int(unix.SIGWINCH),
		int(unix.SIGCONT), int(unix.SIGIO):
		return true
	}
	return false
}

// ptraceGetsiginfo reads the kernel-held siginfo_t for a tracee in
// signal-delivery-stop. PTRACE_GETSIGINFO is request 0x4202. The
// result lands in the caller's 128-byte buffer so Enqueue can stash
// it verbatim; deliverOne later feeds it back to BuildRtSigframe.
//
// On failure (most often when the platform called us during a
// non-signal stop) we return a zero buffer. The caller treats that as
// "kernel gave us nothing to forward" and fabricates a SI_USER-ish
// siginfo via buildSelfSiginfo — less faithful but never crashes.
func ptraceGetsiginfo(pid int) [sigInfoBytes]byte {
	const ptraceGetSiginfo = 0x4202
	var buf [sigInfoBytes]byte
	_, _, e := syscall.Syscall6(
		syscall.SYS_PTRACE,
		ptraceGetSiginfo,
		uintptr(pid),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		0, 0,
	)
	if e != 0 {
		_, _ = fmt.Fprintf(logWriter(),
			"  [sentry] GETSIGINFO(pid=%d): %v\n", pid, e)
		return [sigInfoBytes]byte{}
	}
	return buf
}
