//go:build linux

package main

// platform_iface.go — Pluggable platform abstraction.
//
// In gVisor, Platform is the mechanism for intercepting syscalls from the
// sandboxed process. gVisor ships three: ptrace, systrap (seccomp + SIGSYS),
// and KVM. We ship two: ptrace (PTRACE_SYSEMU) and seccomp (SECCOMP_RET_USER_NOTIF).
//
// The Sentry and syscall handlers are identical across platforms — only
// the interception mechanism differs.
type Platform interface {
	Run(spec *ExecSpec) (int, error)
}
