//go:build linux && arm64

package main

// sentry_arm64.go — arm64-specific syscall dispatch.
//
// On arm64, legacy syscall numbers (open, stat, fstat, access, etc.)
// don't exist. Only the *at() variants are available, and they're already
// registered in the cross-arch table. TLS is set via the TPIDR_EL0
// register rather than arch_prctl, so there are no arm64-only syscalls
// to add.

// addArchSyscalls is a no-op on arm64 — every syscall arm64 programs
// use is already registered by buildSyscallTable in sentry.go.
func (s *Sentry) addArchSyscalls() {}
