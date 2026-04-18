//go:build linux && !amd64

package main

// sig_other.go — non-amd64 stub for the raw-syscall SIGUSR1 handler.
// ADR 002 keeps arm64 signal delivery deferred (§7 "arm64 delivery"),
// and the pure-asm handler in sig_amd64.s is x86_64-specific, so
// builds for other arches drop the real-handler path and fall back
// to the SIG_IGN Test 7 from Phase 3c commit 3. Test 9 is gated on
// realSigSupported and runs amd64-only.

import "syscall"

var sigCounter int32

func installRealSigUsr1() error {
	return syscall.ENOSYS
}

const realSigSupported = false
