//go:build linux && amd64

package main

// sentry_amd64.go — x86_64-specific syscall dispatch.
//
// On amd64, several legacy syscall numbers exist that were removed on arm64.
// We register them into the cross-arch syscall table here so sentry.go
// stays clean.

import "golang.org/x/sys/unix"

// addArchSyscalls installs amd64-only entries into the dispatch table.
//
// arch_prctl is the big one: it sets the FS base for TLS, and without a
// real kernel executing it Go's runtime crashes on the first %fs-relative
// memory access. The numbers for these syscalls don't exist on arm64,
// which is why they live in an arch-tagged file.
func (s *Sentry) addArchSyscalls() {
	s.syscalls[unix.SYS_FSTAT] = SyscallEntry{
		name:    "fstat",
		handler: (*Sentry).sysFstat,
	}
	s.syscalls[unix.SYS_STAT] = SyscallEntry{
		name: "stat",
		handler: func(s *Sentry, pid int, sc SyscallArgs) uint64 {
			// stat(path, statbuf) → newfstatat(AT_FDCWD, path, statbuf, 0)
			sc.Args = [6]uint64{^uint64(99), sc.Args[0], sc.Args[1], 0, 0, 0}
			return s.sysStat(pid, sc)
		},
	}
	s.syscalls[unix.SYS_LSTAT] = SyscallEntry{
		name: "lstat",
		handler: func(s *Sentry, pid int, sc SyscallArgs) uint64 {
			sc.Args = [6]uint64{^uint64(99), sc.Args[0], sc.Args[1], 0, 0, 0}
			return s.sysStat(pid, sc)
		},
	}
	// Legacy access() — rewrite as faccessat and reuse that handler.
	s.syscalls[unix.SYS_ACCESS] = SyscallEntry{
		name: "access",
		handler: func(s *Sentry, pid int, sc SyscallArgs) uint64 {
			sc.Args = [6]uint64{^uint64(99), sc.Args[0], sc.Args[1], 0, 0, 0}
			return s.sysFaccessat(pid, sc)
		},
	}
	// Legacy readlink() — thin wrapper around readlinkat semantics.
	s.syscalls[unix.SYS_READLINK] = SyscallEntry{
		name:    "readlink",
		handler: (*Sentry).sysReadlink,
	}
	// Legacy open() — rewrite as openat(AT_FDCWD, ...).
	s.syscalls[unix.SYS_OPEN] = SyscallEntry{
		name: "open",
		handler: func(s *Sentry, pid int, sc SyscallArgs) uint64 {
			sc.Args = [6]uint64{^uint64(99), sc.Args[0], sc.Args[1], sc.Args[2], 0, 0}
			return s.sysOpenat(pid, sc)
		},
	}
	s.syscalls[unix.SYS_DUP2] = SyscallEntry{
		name:    "dup2",
		handler: func(s *Sentry, _ int, sc SyscallArgs) uint64 { return s.sysDup2(sc) },
	}
	// Legacy getdents (non-64) — reuse the 64-bit implementation. The
	// struct layouts differ but musl/glibc prefer getdents64 anyway.
	s.syscalls[unix.SYS_GETDENTS] = SyscallEntry{
		name:    "getdents",
		handler: (*Sentry).sysGetdents64,
	}
	s.syscalls[unix.SYS_ARCH_PRCTL] = SyscallEntry{
		name:        "arch_prctl",
		passthrough: true,
	}
	// rt_sigreturn is emulated on amd64 as of Phase 3b commit 2: our
	// handler decodes the rt_sigframe the (Sentry-delivered, commit 3)
	// signal flow left on the user stack and restores the tracee's
	// register and fp state.  buildSyscallTable registered a passthrough
	// entry to keep arm64 and pre-3b behavior working; we override it
	// here.
	s.syscalls[unix.SYS_RT_SIGRETURN] = SyscallEntry{
		name:    "rt_sigreturn",
		handler: (*Sentry).sysRtSigreturn,
	}
}
