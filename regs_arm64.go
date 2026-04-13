//go:build linux && arm64

package main

// regs_arm64.go — ARM64 (aarch64) register mapping for syscall interception.
//
// On arm64 Linux, the syscall ABI is:
//   X8  = syscall number
//   X0  = arg1 / return value
//   X1  = arg2, X2 = arg3, X3 = arg4, X4 = arg5, X5 = arg6
//
// Note: Unlike x86_64 where the syscall number and return value use different
// registers (RAX for return, Orig_rax for number), arm64 uses X8 for the
// number and X0 for both arg1 and the return value.

import "golang.org/x/sys/unix"

// regsToSyscall extracts the syscall number and arguments from arm64 registers.
func regsToSyscall(regs *unix.PtraceRegs) SyscallArgs {
	return SyscallArgs{
		Number: regs.Regs[8], // X8 = syscall number
		Args: [6]uint64{
			regs.Regs[0], // X0 = arg1
			regs.Regs[1], // X1 = arg2
			regs.Regs[2], // X2 = arg3
			regs.Regs[3], // X3 = arg4
			regs.Regs[4], // X4 = arg5
			regs.Regs[5], // X5 = arg6
		},
	}
}

// setSyscallReturn writes the return value into X0.
func setSyscallReturn(regs *unix.PtraceRegs, ret uint64) {
	regs.Regs[0] = ret
}

// rewindSyscallInstruction moves PC back to the `svc #0` instruction.
// On arm64, svc is 4 bytes. Required so the tracee re-executes the
// syscall under PTRACE_SYSCALL for passthrough.
func rewindSyscallInstruction(regs *unix.PtraceRegs) {
	regs.Pc -= 4
}

// restoreSyscallNumber is a no-op on arm64: the syscall number lives
// in X8 and isn't clobbered between the SYSEMU entry stop and the next
// execution of svc.
func restoreSyscallNumber(regs *unix.PtraceRegs) {}
