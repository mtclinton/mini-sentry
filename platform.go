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
		syscall.Wait4(child, &ws, 0, nil)
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
	err = syscall.PtraceSetOptions(child, syscall.PTRACE_O_TRACESYSGOOD|
		syscall.PTRACE_O_TRACEEXEC|
		syscall.PTRACE_O_TRACEEXIT)
	if err != nil {
		return -1, fmt.Errorf("ptrace set options failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  [platform] ptrace configured, entering syscall interception loop\n\n")

	// Enter the syscall interception loop.
	// This is the main loop of the sandbox. It runs until the child exits.
	return p.interceptLoop(child)
}

// interceptLoop is the core ptrace loop that intercepts every syscall.
//
// For each iteration:
//   1. PTRACE_SYSEMU — resume child until next syscall entry
//   2. waitpid       — block until child stops
//   3. GETREGS       — read syscall number and arguments from registers
//   4. Sentry.Handle — handle the syscall in userspace
//   5. SETREGS       — write return value into RAX
//   6. goto 1
//
// This is the exact same loop gVisor's ptrace platform runs, minus
// signal forwarding and multi-thread support.
func (p *PtracePlatform) interceptLoop(pid int) (int, error) {
	for {
		// Resume the child with PTRACE_SYSEMU.
		// SYSEMU = stop at next syscall entry, but DON'T execute it.
		// The kernel skips the syscall entirely — we are the kernel now.
		err := ptraceSysemu(pid, 0)
		if err != nil {
			return -1, fmt.Errorf("PTRACE_SYSEMU failed: %w", err)
		}

		// Wait for the child to stop.
		var ws syscall.WaitStatus
		_, err = syscall.Wait4(pid, &ws, 0, nil)
		if err != nil {
			return -1, fmt.Errorf("waitpid failed: %w", err)
		}

		// Check what happened.
		switch {
		case ws.Exited():
			// Child called exit() and the kernel processed it.
			return ws.ExitStatus(), nil

		case ws.Signaled():
			// Child was killed by a signal.
			return 128 + int(ws.Signal()), nil

		case ws.Stopped():
			sig := ws.StopSignal()

			// Check for ptrace events (exec, exit, etc.)
			if ws.TrapCause() == syscall.PTRACE_EVENT_EXIT {
				// Child is about to exit. Continue to let it finish.
				continue
			}
			if ws.TrapCause() == syscall.PTRACE_EVENT_EXEC {
				// Child called exec(). Continue — we'll intercept
				// the new program's syscalls from here.
				continue
			}

			// Syscall-stop: signal is SIGTRAP | 0x80 (because TRACESYSGOOD).
			if sig == syscall.SIGTRAP|0x80 {
				err = p.handleSyscallStop(pid)
				if err != nil {
					if exited, ok := err.(errExitedDuringPassthrough); ok {
						return exited.code, nil
					}
					return -1, err
				}
				continue
			}

			// Regular signal-stop: forward the signal to the child.
			// In gVisor, signal delivery is a whole subsystem.
			// We just pass it through.
			if sig == syscall.SIGTRAP {
				continue // ptrace-related, don't forward
			}
			fmt.Fprintf(os.Stderr, "  [platform] forwarding signal %d to child\n", sig)
			err = ptraceSysemu(pid, int(sig))
			if err != nil {
				return -1, fmt.Errorf("signal forward failed: %w", err)
			}
			// Skip the SYSEMU at top of loop since we just resumed
			var ws2 syscall.WaitStatus
			syscall.Wait4(pid, &ws2, 0, nil)
			if ws2.Exited() {
				return ws2.ExitStatus(), nil
			}

		default:
			return -1, fmt.Errorf("unexpected wait status: %v", ws)
		}
	}
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
func (p *PtracePlatform) handleSyscallStop(pid int) error {
	// Read the child's registers.
	var regs unix.PtraceRegs
	err := unix.PtraceGetRegs(pid, &regs)
	if err != nil {
		return fmt.Errorf("PTRACE_GETREGS failed: %w", err)
	}

	// Extract syscall number and arguments from registers.
	sc := regsToSyscall(&regs)

	// Let the Sentry handle it.
	// This is the key abstraction: the Platform doesn't know what the
	// syscalls mean. It just reads numbers and passes them to the Sentry.
	// The Sentry is the kernel — it decides what to do.
	ret, action := p.sentry.HandleSyscall(pid, sc)

	if action == ActionPassthrough {
		// The Sentry wants the real kernel to run this syscall.
		// See passthroughSyscall for the mechanics.
		return p.passthroughSyscall(pid, &regs)
	}

	// Write the return value back into the child's registers.
	setSyscallReturn(&regs, ret)
	err = unix.PtraceSetRegs(pid, &regs)
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
	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP|0x80 {
		return fmt.Errorf("passthrough: expected syscall-entry stop, got %v", ws)
	}

	// Resume again. The kernel actually executes the syscall this time
	// and stops at syscall-exit.
	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		return fmt.Errorf("passthrough PTRACE_SYSCALL (to exit) failed: %w", err)
	}
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("passthrough wait (exit) failed: %w", err)
	}
	if ws.Exited() {
		// Some syscalls (exit_group) terminate the tracee inside the
		// kernel call — there's no exit-stop. Propagate.
		return errExitedDuringPassthrough{code: ws.ExitStatus()}
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
