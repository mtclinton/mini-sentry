//go:build linux

package main

// compat.go — Compatibility shims and additional syscall handlers.
//
// Modern glibc uses openat(AT_FDCWD, ...) instead of open(...), and
// faccessat() instead of access(). On arm64, the old syscall numbers
// don't even exist — only the *at() variants are available.
//
// In gVisor, this mapping lives in the syscall table initialization
// (pkg/sentry/syscalls/linux/linux64.go) where both old and new
// syscall numbers point to the same handler function.

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

// sysFaccessat handles faccessat(dirfd, pathname, mode, flags).
// Also handles access() on amd64 (which glibc rewrites to faccessat).
// We just check if the file exists in the VFS.
func (s *Sentry) sysFaccessat(pid int, sc SyscallArgs) uint64 {
	// dirfd := int32(sc.Args[0]) // AT_FDCWD = -100
	pathPtr := sc.Args[1]
	// mode := sc.Args[2]

	path := readStringFromChild(pid, pathPtr, 256)

	// Identity-mount passthrough: same treatment as openat/stat so the
	// dynamic linker can probe for ld.so / libc under --mount entries.
	cleanPath := filepath.Clean(path)
	if hostPath, _, ok := matchMount(s.mounts, cleanPath); ok && hostPath == cleanPath {
		s.requestPassthrough(nil)
		return 0
	}
	_, eno := s.vfs.Lookup(path)
	if eno == 0 {
		return 0
	}
	if eno != unix.ENOENT {
		return errno(eno)
	}
	// Also allow paths that look like directories we might have files under
	if s.vfs.ListDir(path) != nil {
		return 0
	}
	return errno(unix.ENOENT)
}
