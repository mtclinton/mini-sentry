//go:build linux && amd64

package main

// sig_amd64.go — raw-syscall SIGUSR1 handler wiring for Test 7 and
// Test 9 (ADR 002 §5.1 and §5.4). Bypasses os/signal on purpose:
// that package relays via Go's per-m gsignal thread, which picks its
// own delivery thread and defeats the per-thread routing the ADR is
// trying to exercise. Raw rt_sigaction + a pure-asm handler gives
// the Sentry a clean path to prove delivery.

import (
	"syscall"
	"unsafe"
)

// sigactionKernel matches the 8-byte-sigset kernel ABI for
// rt_sigaction on x86_64. Distinct from glibc's padded struct
// sigaction — the *syscall* always takes the kernel layout because
// the kernel owns the ABI. The arm64 layout differs (no restorer)
// and is out of scope for this file.
type sigactionKernel struct {
	Handler  uintptr
	Flags    uint64
	Restorer uintptr
	Mask     uint64
}

// sigCounter is bumped from sigusr1Handler (pure asm, LOCK XADDL).
// Read with sync/atomic.LoadInt32 on the test side so the handler
// increment is observed in the right memory order.
var sigCounter int32

// sigusr1Handler / restoreRT are defined in sig_amd64.s but never
// called from Go (Go-declared asm funcs grow an ABIInternal wrapper
// whose PUSHQ BP / CALL abi0 prologue shifts RSP by 16, breaking the
// kernel's C-ABI signal-entry contract). Instead we install them via
// sigusr1HandlerPC / restoreRTPC, DATA symbols populated in asm with
// the bare ABI0 entry addresses.
var (
	sigusr1HandlerPC uintptr
	restoreRTPC      uintptr
)

// SA_SIGINFO / SA_RESTORER bits. x/sys/unix doesn't export them on
// linux/amd64 as of v0.28.0 and the cmd/guest binary is
// deliberately zero-dep, so pin the values here.
const (
	saSigInfo  = 0x00000004
	saRestorer = 0x04000000
)

// installRealSigUsr1 registers sigusr1Handler on SIGUSR1 via raw
// rt_sigaction. SA_RESTORER is required on x86_64 — without it the
// kernel's own rt_sigaction would substitute the vdso trampoline as
// sa_restorer, but our sysRtSigaction path mirrors the struct
// as-written and BuildRtSigframe uses act.restorer as the pretcode.
// A zero pretcode would crash the handler's RET into a null deref.
func installRealSigUsr1() error {
	act := sigactionKernel{
		Handler:  sigusr1HandlerPC,
		Flags:    saSigInfo | saRestorer,
		Restorer: restoreRTPC,
	}
	_, _, e := syscall.RawSyscall6(
		syscall.SYS_RT_SIGACTION,
		uintptr(syscall.SIGUSR1),
		uintptr(unsafe.Pointer(&act)),
		0,
		8, // sigsetsize
		0, 0)
	if e != 0 {
		return e
	}
	return nil
}

// realSigSupported reports whether this build has the pure-asm
// handler wired. amd64 does; other arches set this to false via
// sig_other.go and skip Tests 7-real and 9.
const realSigSupported = true
