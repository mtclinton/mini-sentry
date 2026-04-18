//go:build linux

package main

// platform.go — The Platform layer (maps to gVisor's pkg/sentry/platform)
//
// In gVisor, the Platform is the mechanism that intercepts syscalls from the
// sandboxed application. gVisor supports three platforms:
//
//   1. ptrace   — Uses PTRACE_SYSEMU to trap every syscall. Simple but slow
//                  because every syscall requires a context switch to the tracer.
//                  This is what we implement here.
//
//   2. systrap  — Uses seccomp-bpf to install a filter that triggers SIGSYS on
//                  every syscall. A signal handler in the sandboxed process's
//                  address space handles the syscall via shared memory with the
//                  Sentry. Faster because no context switch for handled syscalls.
//                  This is gVisor's default platform since 2023.
//
//   3. KVM      — Uses Linux KVM to run the sandboxed process in a lightweight
//                  VM. The Sentry acts as both guest OS and VMM. Best isolation
//                  but requires hardware virtualization support.
//
// All three platforms implement the same interface: intercept a syscall,
// read its arguments, let the Sentry handle it, write the return value back.
// The Sentry doesn't care which platform is in use — it just sees syscall
// numbers and arguments.
//
// Our implementation uses PTRACE_SYSEMU, which is specifically designed for
// syscall emulation: it stops the tracee on syscall entry and SKIPS the
// actual kernel syscall. The tracee never executes the real syscall — we
// handle it entirely in userspace and inject the return value.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ptraceSysemu calls PTRACE_SYSEMU directly via raw syscall.
//
// PTRACE_SYSEMU (constant 31) is the key to syscall emulation: it resumes
// the tracee and stops it at the NEXT syscall entry, but tells the kernel
// to SKIP executing the actual syscall. We inject our own return value
// instead. This is exactly what gVisor's ptrace platform does.
//
// We define this ourselves because x/sys/unix doesn't expose PtraceSysemu
// on all architectures. Calling ptrace() directly with the raw constant
// works on both amd64 and arm64 Linux (where PTRACE_SYSEMU = 31).
func ptraceSysemu(pid int, signal int) error {
	const PTRACE_SYSEMU = 31
	_, _, e := syscall.Syscall6(
		syscall.SYS_PTRACE,
		PTRACE_SYSEMU,
		uintptr(pid),
		0,
		uintptr(signal),
		0, 0,
	)
	if e != 0 {
		return e
	}
	return nil
}

// PtracePlatform intercepts syscalls from a child process using PTRACE_SYSEMU.
// Maps to: gVisor's pkg/sentry/platform/ptrace.
type PtracePlatform struct {
	sentry *Sentry
}

func NewPtracePlatform(sentry *Sentry) *PtracePlatform {
	return &PtracePlatform{sentry: sentry}
}

// Run forks a child process, attaches ptrace, and enters the syscall
// interception loop. Returns the child's exit code.
//
// This is the heart of the sandbox. The sequence is:
//   1. Fork child with PTRACE_TRACEME (child requests tracing)
//   2. Child calls exec() to load the target program
//   3. exec() triggers a SIGTRAP (because PTRACE_TRACEME)
//   4. We set PTRACE_O_TRACESYSGOOD for clean syscall-stop detection
//   5. We enter the loop: PTRACE_SYSEMU → wait → handle → repeat
//
// PTRACE_SYSEMU is critical: unlike PTRACE_SYSCALL (which stops on entry
// AND exit, and actually executes the syscall), SYSEMU stops ONLY on entry
// and SKIPS the real syscall. The kernel never sees it. This is exactly
// what gVisor needs — the Sentry IS the kernel.
func (p *PtracePlatform) Run(spec *ExecSpec) (int, error) {
	// CRITICAL: Lock this goroutine to an OS thread.
	// ptrace is per-thread in Linux — all ptrace operations on a tracee
	// must come from the same thread that attached. Go's goroutine scheduler
	// migrates goroutines between OS threads, which would break ptrace.
	// gVisor solves this the same way in its ptrace platform.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Resolve the program path.
	path, err := exec.LookPath(spec.Program)
	if err != nil {
		return -1, fmt.Errorf("program not found: %s: %w", spec.Program, err)
	}

	// Fork the child with PTRACE_TRACEME.
	// SysProcAttr.Ptrace = true sets PTRACE_TRACEME in the child before exec.
	// This means the child will stop on its first instruction after exec(),
	// giving us a chance to configure ptrace options.
	argv := append([]string{spec.Program}, spec.Args...)
	procAttr := &syscall.ProcAttr{
		Files: []uintptr{0, 1, 2}, // stdin, stdout, stderr pass through
		Env:   spec.BuildEnv(os.Environ()),
		Dir:   spec.Cwd,
		Sys: &syscall.SysProcAttr{
			Ptrace: true, // Child calls PTRACE_TRACEME before exec
		},
	}
	applyCredToSysProcAttr(procAttr.Sys, spec)
	child, err := syscall.ForkExec(path, argv, procAttr)
	if err != nil {
		return -1, fmt.Errorf("fork+exec failed: %w", err)
	}

	// Apply rlimits on the freshly-forked child. Has to happen before
	// we resume tracing; prlimit64 is safe to call on a stopped tracee.
	// Note: RLIMIT_STACK and RLIMIT_AS are consumed by the kernel during
	// exec and will not fully take effect when set post-ForkExec — document
	// this caveat rather than pretend otherwise.
	if err := spec.applyRlimits(child); err != nil {
		_ = syscall.Kill(child, syscall.SIGKILL)
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(child, &ws, 0, nil)
		return -1, fmt.Errorf("apply rlimits: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  [platform] child pid=%d, waiting for exec stop...\n", child)

	// Wait for the child to stop after exec (SIGTRAP from PTRACE_TRACEME).
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(child, &ws, 0, nil)
	if err != nil {
		return -1, fmt.Errorf("wait after exec failed: %w", err)
	}
	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP {
		return -1, fmt.Errorf("unexpected wait status after exec: %v", ws)
	}

	// Set ptrace options:
	//   TRACESYSGOOD — sets bit 7 in the signal number for syscall-stops,
	//                   so we can distinguish syscall-stops from signal-stops.
	//   TRACEEXEC   — get notified on exec() calls.
	//   TRACEEXIT   — get notified before the child exits.
	//   TRACECLONE  — get notified on clone(2). The new thread inherits
	//                  these options and is auto-stopped with SIGSTOP on
	//                  its first instruction so the tracer can set up
	//                  per-thread bookkeeping. ADR 002 §2.
	err = syscall.PtraceSetOptions(child, syscall.PTRACE_O_TRACESYSGOOD|
		syscall.PTRACE_O_TRACEEXEC|
		syscall.PTRACE_O_TRACEEXIT|
		syscall.PTRACE_O_TRACECLONE)
	if err != nil {
		return -1, fmt.Errorf("ptrace set options failed: %w", err)
	}

	// Stamp the main thread's tid now that we know it. NewSignalState
	// creates the implicit main ThreadState with tid=0; from this
	// point on FindThread(child) resolves to that state so mask /
	// altstack / pending-queue lookups key correctly.
	p.sentry.signals.SetMainTid(child)

	fmt.Fprintf(os.Stderr, "  [platform] ptrace configured, entering syscall interception loop\n\n")

	// Enter the syscall interception loop.
	// This is the main loop of the sandbox. It runs until the child exits.
	return p.interceptLoop(child)
}

// interceptLoop is the core ptrace loop that intercepts every syscall.
//
// For each iteration:
//   1. PTRACE_SYSEMU — resume the thread we last stopped
//   2. Wait4(-1, WALL) — block until ANY traced thread stops
//   3. GETREGS       — read syscall number and arguments from registers
//   4. Sentry.Handle — handle the syscall in userspace
//   5. SETREGS       — write return value into RAX
//   6. goto 1
//
// ADR 002 §4 rewrote this loop to be multi-thread aware: we no longer
// hardcode `mainPid` into wait4, and we resume whichever tid last
// stopped. `mainPid` survives only as the identity of the initial
// tracee — its exit terminates the sandbox; worker-thread exits
// unregister a ThreadState and keep the loop running.
func (p *PtracePlatform) interceptLoop(mainPid int) (int, error) {
	// activeTid is the thread we most recently stopped. It starts as
	// the main tracee (post-exec stop) and updates each iteration to
	// whichever tid Wait4 returned. PTRACE_SYSEMU always resumes a
	// specific tid, so we have to remember which one.
	activeTid := mainPid

	for {
		// Drain Sentry-queued signals before resuming. Phase 3b
		// commit 3 (ADR 001 §3) makes the Sentry authoritative for
		// signal delivery: sendSelfSignal and the signal-stop branch
		// below enqueue onto SignalState.pending, and this drain is
		// where frames actually get built. The drain is cheap when
		// the queue is empty — one atomic DequeueUnblocked lookup.
		//
		// Pre-routing (commit 2): the drain still operates on the
		// single implicit main ThreadState through the SignalState
		// shim. Commit 3 converts it to a per-thread walk.
		if res, err := p.deliverPending(activeTid); err != nil {
			return -1, fmt.Errorf("signal drain: %w", err)
		} else if res.terminate != 0 {
			// SIG_DFL terminate hit the queue. We don't try to
			// forward the original signal (the tracee is stopped
			// by ptrace; its next-resume semantics are messy);
			// SIGKILL is unblockable and produces a deterministic
			// wait status.
			_ = syscall.Kill(activeTid, syscall.SIGKILL)
			_, _ = fmt.Fprintf(logWriter(),
				"  [sentry] SIG_DFL terminate %s → SIGKILL\n",
				signalName(res.terminate))
		}

		// Resume the thread we last stopped with PTRACE_SYSEMU.
		// SYSEMU = stop at next syscall entry, but DON'T execute it.
		// The kernel skips the syscall entirely — we are the kernel now.
		err := ptraceSysemu(activeTid, 0)
		if err != nil {
			if err == syscall.ESRCH {
				// Tracee died between iterations (multi-threaded
				// exit_group race). We couldn't recover an exit code
				// from wait because the tracee is already reaped in
				// the passthrough path; return cleanly with code 0.
				return 0, nil
			}
			return -1, fmt.Errorf("PTRACE_SYSEMU failed: %w", err)
		}

		// Wait for ANY traced thread to stop. WALL (__WALL) is
		// required under PTRACE_O_TRACECLONE so wait4 reports events
		// from cloned threads, not just ordinary SIGCHLD-delivering
		// children. The returned wpid identifies which thread the
		// event belongs to.
		var ws syscall.WaitStatus
		wpid, err := syscall.Wait4(-1, &ws, unix.WALL, nil)
		if err != nil {
			return -1, fmt.Errorf("waitpid failed: %w", err)
		}
		activeTid = wpid

		// Check what happened.
		switch {
		case ws.Exited():
			// A thread exited. If it's the main tracee, the sandbox
			// is done; otherwise unregister and keep looping. Linux
			// tears down the whole thread group on exit_group, so
			// worker-thread exits typically shortly precede the main
			// tracee's own exit.
			if wpid == mainPid {
				return ws.ExitStatus(), nil
			}
			p.sentry.signals.DetachThread(wpid)
			// After a worker exit, activeTid points at a dead thread.
			// Reset it to the main tracee so the next SYSEMU targets
			// a live tid. A worker exit comes with the main thread
			// still stopped at some prior point, so SYSEMU(main) is
			// a valid next move only if main is also stopped. That's
			// only true at startup or after we explicitly stopped it.
			// In practice the worker's exit races with main's next
			// wait4 event; either way the next wait4 will re-pin
			// activeTid to a stopped thread. Use mainPid as a
			// placeholder value that's guaranteed to exist.
			activeTid = mainPid
			continue

		case ws.Signaled():
			// Thread killed by a signal. Same main-vs-worker rule.
			if wpid == mainPid {
				return 128 + int(ws.Signal()), nil
			}
			p.sentry.signals.DetachThread(wpid)
			activeTid = mainPid
			continue

		case ws.Stopped():
			sig := ws.StopSignal()

			// PTRACE_EVENT_CLONE: the stopping thread just called
			// clone(2). The new child tid is in GETEVENTMSG.
			// Register it on the thread group so follow-on events
			// for that tid route to a real ThreadState. The child
			// is already stopped by the kernel with SIGSTOP as its
			// first stop; its event will surface on a later wait4.
			if ws.TrapCause() == syscall.PTRACE_EVENT_CLONE {
				if newTid, ok := getPtraceEventMsg(wpid); ok {
					p.sentry.signals.AttachThread(int(newTid))
				}
				continue
			}

			// Check for other ptrace events (exec, exit, etc.)
			if ws.TrapCause() == syscall.PTRACE_EVENT_EXIT {
				// Worker threads announce their exit via EVENT_EXIT
				// before the actual WIFEXITED status comes through.
				// Unregister now so routing can't pick the dying
				// tid; the actual exit reap happens on the next
				// wait4 iteration and hits the Exited() branch
				// above (where main-vs-worker decides whether we
				// return or keep looping).
				if wpid != mainPid {
					p.sentry.signals.DetachThread(wpid)
				}
				continue
			}
			if ws.TrapCause() == syscall.PTRACE_EVENT_EXEC {
				// Child called exec(). Continue — we'll intercept
				// the new program's syscalls from here.
				continue
			}

			// Syscall-stop: signal is SIGTRAP | 0x80 (because TRACESYSGOOD).
			if sig == syscall.SIGTRAP|0x80 {
				err = p.handleSyscallStop(wpid, mainPid)
				if err != nil {
					if exited, ok := err.(errExitedDuringPassthrough); ok {
						if wpid == mainPid {
							return exited.code, nil
						}
						p.sentry.signals.DetachThread(wpid)
						activeTid = mainPid
						continue
					}
					return -1, err
				}
				continue
			}

			// Regular signal-stop: handed off to the arch-specific
			// routine. Phase 3b commit 3 on amd64 enqueues onto the
			// Sentry's pending queue so the top-of-loop drain builds
			// the rt_sigframe and redirects RIP (ADR 001 §3). arm64
			// keeps Phase 3a behavior — forward to the kernel, let it
			// deliver — until arm64 gets its own frame builder (3c).
			if sig == syscall.SIGTRAP {
				continue // ptrace-related, don't forward
			}
			// SIGSTOP on a newly-attached thread is ptrace's way of
			// saying "your new child has arrived, stopped and ready
			// to be stepped." Swallow it: we resume the thread on
			// the next SYSEMU. AttachThread is idempotent so we can
			// safely call it here even if EVENT_CLONE already
			// registered the tid.
			if sig == syscall.SIGSTOP && wpid != mainPid {
				p.sentry.signals.AttachThread(wpid)
				continue
			}
			if code, terminated, err := p.handleSignalStop(wpid, sig); err != nil {
				return -1, err
			} else if terminated {
				return code, nil
			}

		default:
			return -1, fmt.Errorf("unexpected wait status: %v", ws)
		}
	}
}

// getPtraceEventMsg wraps PTRACE_GETEVENTMSG (op 0x4201). For
// PTRACE_EVENT_CLONE the returned value is the new thread's tid.
// Go's syscall package doesn't expose the call, so we issue it
// directly. Returns (msg, ok); ok=false on a ptrace error (tracee
// dying, bad op) so callers can just drop the event.
func getPtraceEventMsg(pid int) (uint64, bool) {
	const PTRACE_GETEVENTMSG = 0x4201
	var msg uint64
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE,
		uintptr(PTRACE_GETEVENTMSG),
		uintptr(pid), 0,
		uintptr(unsafe.Pointer(&msg)), 0, 0)
	if errno != 0 {
		return 0, false
	}
	return msg, true
}

// handleSyscallStop reads the registers, lets the Sentry handle the syscall,
// and writes the return value back.
//
// On x86_64, the syscall convention is:
//   RAX = syscall number (on entry)
//   RDI, RSI, RDX, R10, R8, R9 = arguments 1-6
//   RAX = return value (on exit)
//
// On arm64, the convention is:
//   X8  = syscall number
//   X0-X5 = arguments 1-6
//   X0  = return value
//
// We read the registers, dispatch to the Sentry, and write RAX/X0 back.
// PTRACE_SYSEMU already skipped the real syscall, so whatever we put in
// RAX/X0 is what the child sees as the syscall result.
func (p *PtracePlatform) handleSyscallStop(tid, tgid int) error {
	// Read the stopping thread's registers.
	var regs unix.PtraceRegs
	err := unix.PtraceGetRegs(tid, &regs)
	if err != nil {
		return fmt.Errorf("PTRACE_GETREGS failed: %w", err)
	}

	// Extract syscall number and arguments from registers.
	sc := regsToSyscall(&regs)

	// Let the Sentry handle it.
	// This is the key abstraction: the Platform doesn't know what the
	// syscalls mean. It just reads numbers and passes them to the Sentry.
	// The Sentry is the kernel — it decides what to do.
	// Under multi-thread (ADR 002): tgid is the main tracee pid, tid is
	// the specific thread that stopped. For single-thread guests they're
	// equal.
	ret, action := p.sentry.HandleSyscall(tgid, tid, sc)

	if action == ActionPassthrough {
		// The Sentry wants the real kernel to run this syscall.
		// See passthroughSyscall for the mechanics.
		if err := p.passthroughSyscall(tid, &regs); err != nil {
			return err
		}
		// Read the kernel's actual return value out of RAX/X0 and hand
		// it to the Sentry so any pending post-passthrough bookkeeping
		// (registering kernel-allocated fds, cleaning up close entries)
		// can complete. Safe to ignore the error here — if GETREGS fails
		// the child is likely dying anyway and the main loop's next wait
		// will surface it.
		var postRegs unix.PtraceRegs
		if err := unix.PtraceGetRegs(tid, &postRegs); err == nil {
			p.sentry.PostPassthrough(tid, getSyscallReturn(&postRegs))
		}
		return nil
	}

	if action == ActionKeepRegs {
		// Handler already wrote the register file via PTRACE_SETREGS
		// (rt_sigreturn restoring a signal frame). Overwriting rax now
		// would undo the restore — just resume the tracee.
		return nil
	}

	// Write the return value back into the child's registers.
	setSyscallReturn(&regs, ret)
	err = unix.PtraceSetRegs(tid, &regs)
	if err != nil {
		return fmt.Errorf("PTRACE_SETREGS failed: %w", err)
	}

	return nil
}

// passthroughSyscall executes the current syscall in the real kernel.
//
// After PTRACE_SYSEMU stopped us at syscall entry, the kernel has already
// moved past the `syscall` instruction AND flagged the syscall as emulated
// (it will be skipped when we resume, no matter how we resume). So we
// can't simply "continue and let it run" — the skip is sticky for this
// entry.
//
// The workaround: rewind the instruction pointer back to the `syscall`
// instruction (2 bytes on x86_64, 4 bytes on arm64) and resume under
// PTRACE_SYSCALL mode. The tracee re-executes the instruction, which
// triggers a fresh syscall-entry stop — this time without the emulated
// flag set, so the kernel actually runs it. We then resume once more to
// reach the syscall-exit stop, and return to the main loop. The real
// kernel's return value is already sitting in RAX/X0 where the tracee
// expects it.
//
// This is essentially what gVisor's ptrace platform does for syscalls it
// wants delegated to the host kernel.
func (p *PtracePlatform) passthroughSyscall(pid int, regs *unix.PtraceRegs) error {
	// Rewind RIP/PC to re-execute the syscall instruction.
	rewindSyscallInstruction(regs)
	// On amd64 the kernel overwrites RAX with -ENOSYS during the SYSEMU
	// entry stop; restore it to the syscall number so the re-issued
	// syscall dispatches to the right handler. No-op on arm64.
	restoreSyscallNumber(regs)
	if err := unix.PtraceSetRegs(pid, regs); err != nil {
		return fmt.Errorf("passthrough SETREGS (rewind) failed: %w", err)
	}

	// Resume with PTRACE_SYSCALL. The tracee executes the `syscall`
	// instruction again and stops at the new syscall-entry.
	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		return fmt.Errorf("passthrough PTRACE_SYSCALL (to entry) failed: %w", err)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("passthrough wait (entry) failed: %w", err)
	}
	if exited, ok := drainExitIfTerminating(pid, ws); ok {
		return exited
	}
	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP|0x80 {
		return fmt.Errorf("passthrough: expected syscall-entry stop, got %v", ws)
	}

	// Resume again. The kernel actually executes the syscall this time
	// and stops at syscall-exit.
	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		if err == syscall.ESRCH {
			// Tracee died between waits — typically exit_group in a
			// multi-threaded tracee where another thread's exit has
			// already torn the group down. Treat as clean exit.
			return errExitedDuringPassthrough{code: 0}
		}
		return fmt.Errorf("passthrough PTRACE_SYSCALL (to exit) failed: %w", err)
	}
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		if err == syscall.ECHILD {
			return errExitedDuringPassthrough{code: 0}
		}
		return fmt.Errorf("passthrough wait (exit) failed: %w", err)
	}
	if exited, ok := drainExitIfTerminating(pid, ws); ok {
		return exited
	}
	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP|0x80 {
		return fmt.Errorf("passthrough: expected syscall-exit stop, got %v", ws)
	}
	// RAX/X0 now holds the real kernel's return value. Main loop will
	// reissue PTRACE_SYSEMU to advance to the next syscall.
	return nil
}

type errExitedDuringPassthrough struct{ code int }

func (e errExitedDuringPassthrough) Error() string {
	return fmt.Sprintf("tracee exited during passthrough: code=%d", e.code)
}

// drainExitIfTerminating converts a tracee-terminating wait status into
// errExitedDuringPassthrough so the main loop can surface the exit code.
// Handles both direct WIFEXITED (exit_group terminated before any ptrace
// stop) and PTRACE_EVENT_EXIT (TRACEEXIT option fires before the tracee
// actually dies; we pump one PTRACE_CONT to drain to WIFEXITED). Either
// wait slot in passthroughSyscall can land here depending on timing —
// exit_group's entry-resume can go straight to EVENT_EXIT before a
// syscall-entry stop is reported on some kernels.
func drainExitIfTerminating(pid int, ws syscall.WaitStatus) (errExitedDuringPassthrough, bool) {
	if ws.Exited() {
		return errExitedDuringPassthrough{code: ws.ExitStatus()}, true
	}
	if ws.Signaled() {
		return errExitedDuringPassthrough{code: 128 + int(ws.Signal())}, true
	}
	if !ws.Stopped() || ws.TrapCause() != syscall.PTRACE_EVENT_EXIT {
		return errExitedDuringPassthrough{}, false
	}
	var status uint64
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE,
		uintptr(0x4201), // PTRACE_GETEVENTMSG
		uintptr(pid), 0, uintptr(unsafe.Pointer(&status)), 0, 0)
	if errno != 0 {
		// Fall back to zero code; the main loop will still observe
		// the exit via its own wait4 on the next iteration.
		_ = syscall.PtraceCont(pid, 0)
		return errExitedDuringPassthrough{code: 0}, true
	}
	if err := syscall.PtraceCont(pid, 0); err != nil {
		return errExitedDuringPassthrough{code: int(status>>8) & 0xff}, true
	}
	// One final wait to reap the real WIFEXITED status and keep the
	// main loop from observing a stale stop. We discard its result
	// because status already carries the exit code.
	var final syscall.WaitStatus
	_, _ = syscall.Wait4(pid, &final, 0, nil)
	return errExitedDuringPassthrough{code: int(status>>8) & 0xff}, true
}
