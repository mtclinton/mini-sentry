//go:build linux && amd64

package main

// setfpregs_amd64.go — PTRACE_SETFPREGS wrapper, inverse of GetFpregs.
//
// PTRACE_SETFPREGS writes a 512-byte FXSAVE image back to the tracee.
// Paired with GetFpregs (PTRACE_GETFPREGS) in the signal-frame
// save/restore path: a handler reads fp state on entry, the builder
// bakes it into the sigframe, and on rt_sigreturn we SetFpregs the
// (possibly-mutated) snapshot so an FXRSTOR-equivalent restore happens
// transparently when the tracee resumes.  AVX/AVX-512 preservation
// would need PTRACE_SETREGSET(NT_X86_XSTATE) — deferred to 3c.

import (
	"syscall"
	"unsafe"
)

// PTRACE_SETFPREGS = 15 on Linux amd64.  Defined in uapi's
// <sys/ptrace.h> as PTRACE_SETFPREGS.
const ptraceSetFpregs = 15

// SetFpregs writes a 512-byte FXSAVE image to the stopped tracee.
// Caller's responsibility to ensure the tracee is in a ptrace-stop.
func SetFpregs(pid int, fp *FxRegs) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PTRACE,
		ptraceSetFpregs,
		uintptr(pid),
		0,
		uintptr(unsafe.Pointer(&fp[0])),
		0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
