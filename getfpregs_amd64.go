//go:build linux && amd64

package main

// getfpregs_amd64.go — PTRACE_GETFPREGS wrapper.
//
// PTRACE_GETFPREGS is the older, simpler ioctl for reading a stopped
// tracee's floating-point state: it returns a fixed 512-byte FXSAVE
// snapshot, no XSAVE header, no XCR0 negotiation.  That's adequate
// for Phase 3b's signal-delivery path, which only promises to
// preserve FXSAVE-visible state (x87 + SSE + XMM).  AVX / AVX-512
// preservation would need PTRACE_GETREGSET(NT_X86_XSTATE) and is
// deferred to 3c.  See ADR §2.

import (
	"syscall"
	"unsafe"
)

// PTRACE_GETFPREGS = 14 on Linux amd64.  Defined in uapi's
// <sys/ptrace.h> as PTRACE_GETFPREGS.
const ptraceGetFpregs = 14

// fxregsSize is the kernel's fixed size for the FXSAVE snapshot
// returned by PTRACE_GETFPREGS.  The Linux kernel copies struct
// user_i387_struct (= 512 bytes on amd64) into the caller buffer.
const fxregsSize = 512

// FxRegs is an opaque 512-byte FXSAVE image.  The builder only
// memcpys it into the frame; no field access needed.
type FxRegs [fxregsSize]byte

// GetFpregs fetches the FXSAVE snapshot for the stopped tracee.  The
// tracee must already be in a ptrace-stop — caller's responsibility.
func GetFpregs(pid int) (FxRegs, error) {
	var fp FxRegs
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PTRACE,
		ptraceGetFpregs,
		uintptr(pid),
		0,
		uintptr(unsafe.Pointer(&fp[0])),
		0, 0,
	)
	if errno != 0 {
		return fp, errno
	}
	return fp, nil
}
