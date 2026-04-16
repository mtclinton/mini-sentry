//go:build linux && amd64

package main

// regs_amd64.go — x86_64 register mapping for syscall interception.
//
// On x86_64 Linux, the syscall ABI is:
//   RAX = syscall number (input), return value (output)
//   RDI = arg1, RSI = arg2, RDX = arg3
//   R10 = arg4, R8 = arg5, R9 = arg6
//
// Note: R10 (not RCX) for arg4 — the kernel clobbers RCX with the return
// address, so the libc syscall wrapper moves arg4 from RCX to R10.

import "golang.org/x/sys/unix"

// regsToSyscall extracts the syscall number and arguments from x86_64 registers.
func regsToSyscall(regs *unix.PtraceRegs) SyscallArgs {
	return SyscallArgs{
		Number: uint64(regs.Orig_rax), // Orig_rax preserves the syscall number
		Args: [6]uint64{
			regs.Rdi, // arg1
			regs.Rsi, // arg2
			regs.Rdx, // arg3
			regs.R10, // arg4 (NOT Rcx — kernel clobbers Rcx)
			regs.R8,  // arg5
			regs.R9,  // arg6
		},
	}
}

// setSyscallReturn writes the return value into RAX.
func setSyscallReturn(regs *unix.PtraceRegs, ret uint64) {
	regs.Rax = ret
}

// getSyscallReturn reads the return value left by the kernel after a
// passthrough syscall completes. Used by the Platform to surface the
// real result back to the Sentry (e.g. to register kernel-allocated
// fds returned by passthrough openat).
func getSyscallReturn(regs *unix.PtraceRegs) uint64 {
	return regs.Rax
}

// rewindSyscallInstruction moves RIP back to the `syscall` instruction.
// On x86_64, `syscall` is the 2-byte opcode 0f 05. After PTRACE_SYSEMU
// stops us at syscall entry, RIP already points past it — rewind so the
// tracee re-executes the instruction under PTRACE_SYSCALL mode.
func rewindSyscallInstruction(regs *unix.PtraceRegs) {
	regs.Rip -= 2
}

// restoreSyscallNumber puts the syscall number back into RAX.
// The kernel copies RAX to Orig_rax on entry and may overwrite RAX
// itself (with -ENOSYS) during the SYSEMU stop. When we re-issue the
// syscall we need RAX to carry the original number again.
func restoreSyscallNumber(regs *unix.PtraceRegs) {
	regs.Rax = regs.Orig_rax
}
