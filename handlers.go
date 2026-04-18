//go:build linux

package main

// handlers.go — Syscall handler implementations (maps to gVisor's kernel/syscalls/)
//
// Each function here implements one Linux syscall. In gVisor, these live in
// pkg/sentry/syscalls/linux/ — one file per syscall or group of related syscalls.
// Each handler is pure Go code that emulates what the Linux kernel would do.
//
// The key security insight: none of these handlers call the real syscall.
// When a sandboxed process calls read(), our sysRead() serves data from
// the virtual filesystem — the real kernel's read() is never invoked.
// When it calls write() to stdout, we call the host's write() on fd 1 —
// but only because we explicitly decided stdout should pass through.
// Every byte of I/O is mediated by our code.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// shouldPassthroughFD decides whether operations targeting fd must be
// executed by the real kernel rather than the Sentry's virtual-FD logic.
//
// Decision rules:
//
//   - fd in table & isRealFD → kernel owns the real fd, passthrough.
//   - fd in table & virtual  → Sentry handles it (stdio, VFS file, socket).
//   - fd missing, fd < virtualFDBase → almost certainly a kernel-allocated
//     fd from a passthrough openat (ld.so opening libc); passthrough.
//   - fd missing, fd ≥ virtualFDBase → garbage or double-closed virtual;
//     caller should surface EBADF.
//
// The virtualFDBase split is what prevents us from laundering bad fd
// references into successful passthroughs: anything the Sentry could
// have handed out lives at or above 10000, so the kernel never sees
// a bogus re-close of a virtual fd.
func (s *Sentry) shouldPassthroughFD(fd int) bool {
	if f, ok := s.fdTable[fd]; ok {
		return f.isRealFD
	}
	return fd < virtualFDBase
}

// maxTransfer caps any single ptrace-backed transfer to protect the
// Sentry from OOM if a guest (or a fuzzer) asks for an absurd size.
// Short reads/writes are legal on Linux, so capping is transparent.
const maxTransfer = 16 * 1024 * 1024

// ──────────────────────────────────────────────────────────────────────
// READ — read(fd, buf, count)
//
// In gVisor: vfs.FileDescription.Read() → specific filesystem implementation
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysRead(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	buf := sc.Args[1]  // pointer in child's address space
	count := sc.Args[2]

	// Unknown or kernel-owned fd: let the real kernel do the read.
	// Anonymous guest file fds, stdio, and virtual sockets stay here.
	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if count == 0 {
		return 0
	}

	// Virtual socket fds: pull bytes off the Sentry-owned net.Conn.
	// The guest never learns the fd is a proxied connection.
	if f.isSocket {
		if f.conn == nil {
			return errno(syscall.ENOTCONN)
		}
		if count > maxTransfer {
			count = maxTransfer
		}
		tmp := make([]byte, count)
		s.mu.Unlock()
		n, err := f.conn.Read(tmp)
		s.mu.Lock()
		if n > 0 {
			writeToChild(pid, buf, tmp[:n])
			return uint64(n)
		}
		if err != nil {
			return 0 // EOF
		}
		return 0
	}

	// Host FDs (stdin): read from the real FD.
	// In gVisor, this goes through the "host" filesystem implementation.
	if f.isHost {
		if count > maxTransfer {
			count = maxTransfer
		}
		data := make([]byte, count)
		n, err := syscall.Read(f.hostFD, data)
		if err != nil {
			return errno(err.(syscall.Errno))
		}
		// Write the data into the child's memory via ptrace.
		writeToChild(pid, buf, data[:n])
		return uint64(n)
	}

	// Virtual file: serve data from the VFS.
	// This is the Gofer path — data comes from our in-memory filesystem.
	if f.offset < 0 || f.offset >= int64(len(f.data)) {
		return 0 // EOF
	}
	capped := count
	if capped > maxTransfer {
		capped = maxTransfer
	}
	// Avoid int64 overflow when offset + count would wrap.
	remaining := int64(len(f.data)) - f.offset
	if int64(capped) > remaining {
		capped = uint64(remaining)
	}
	chunk := f.data[f.offset : f.offset+int64(capped)]
	writeToChild(pid, buf, chunk)
	f.offset += int64(capped)
	return uint64(len(chunk))
}

// ──────────────────────────────────────────────────────────────────────
// PREAD64 — pread64(fd, buf, count, offset)
//
// Like read(), but reads at a given file offset without changing the
// file position. The dynamic linker (ld-linux) uses pread64 heavily to
// read ELF headers and program segments at specific offsets.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysPread64(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	buf := sc.Args[1]
	count := sc.Args[2]
	offset := int64(sc.Args[3])

	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if count == 0 {
		return 0
	}

	// Virtual file: serve data from the VFS at the requested offset,
	// without moving the file position (unlike sysRead).
	if offset < 0 || offset >= int64(len(f.data)) {
		return 0 // EOF
	}
	capped := count
	if capped > maxTransfer {
		capped = maxTransfer
	}
	remaining := int64(len(f.data)) - offset
	if int64(capped) > remaining {
		capped = uint64(remaining)
	}
	chunk := f.data[offset : offset+int64(capped)]
	writeToChild(pid, buf, chunk)
	return uint64(len(chunk))
}

// ──────────────────────────────────────────────────────────────────────
// PWRITE64 — pwrite64(fd, buf, count, offset)
//
// Like write(), but at a given offset. We only support passthrough fds
// (kernel-owned); virtual files are read-only.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysPwrite64(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])

	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	// Virtual fds are read-only — no pwrite support.
	return errno(syscall.EBADF)
}

// ──────────────────────────────────────────────────────────────────────
// WRITE — write(fd, buf, count)
//
// In gVisor: vfs.FileDescription.Write()
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysWrite(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	buf := sc.Args[1]
	count := sc.Args[2]

	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if count == 0 {
		return 0
	}
	if count > maxTransfer {
		count = maxTransfer
	}

	// Read the data from the child's memory.
	data := readFromChild(pid, buf, count)

	// Virtual socket fds: push bytes to the Sentry-owned net.Conn.
	if f.isSocket {
		if f.conn == nil {
			return errno(syscall.ENOTCONN)
		}
		s.mu.Unlock()
		n, err := f.conn.Write(data)
		s.mu.Lock()
		if err != nil {
			if n > 0 {
				return uint64(n)
			}
			return errno(syscall.EPIPE)
		}
		return uint64(n)
	}

	// Host FDs (stdout, stderr): write to the real FD.
	if f.isHost && f.writable {
		n, err := syscall.Write(f.hostFD, data)
		if err != nil {
			return errno(err.(syscall.Errno))
		}
		return uint64(n)
	}

	return errno(syscall.EBADF)
}

// ──────────────────────────────────────────────────────────────────────
// OPENAT — openat(dirfd, pathname, flags, mode)
//
// In gVisor: vfs.VirtualFilesystem.OpenAt() → Gofer → host filesystem
// This is where the Gofer architecture shines: the Sentry asks the Gofer
// "does this file exist? give me its contents" — the Sentry never opens
// a real file descriptor on the host.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysOpenat(pid int, sc SyscallArgs) uint64 {
	// dirfd := int32(sc.Args[0]) // AT_FDCWD = -100
	pathPtr := sc.Args[1]
	// flags := sc.Args[2]

	// Read the pathname from the child's memory.
	path := readStringFromChild(pid, pathPtr, 256)

	// Mount check. If the path is under a --mount entry where the host
	// and guest paths are identical, hand the openat to the real kernel.
	// The kernel opens the file in the child's own fd namespace, so the
	// fd number the guest sees is the one the kernel allocated. We don't
	// register the fd in fdTable — subsequent reads/writes/fstats/mmaps
	// against unknown fds fall through to the kernel via the
	// shouldPassthroughFD rule (see the fd-op handlers below).
	//
	// Phase-2 limitation: only identity mounts (host == guest) can be
	// passed through this way. For a rewriting mount (host != guest)
	// we'd need to mutate the path in child memory before the kernel
	// reads it — doable but carries TOCTTOU risk; deferred.
	cleanPath := filepath.Clean(path)
	if hostPath, _, ok := matchMount(s.mounts, cleanPath); ok && hostPath == cleanPath {
		_, _ = fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → passthrough (mount %s)\n", path, hostPath)
		s.requestPassthrough(nil)
		return 0
	}

	// Try a regular file first.
	data, eno := s.vfs.Lookup(path)
	if eno == 0 {
		fd := s.nextFD
		s.nextFD++
		s.fdTable[fd] = &OpenFile{path: path, data: data}
		_, _ = fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → fd %d (%d bytes)\n", path, fd, len(data))
		return uint64(fd)
	}

	// EACCES / any non-ENOENT error is propagated as-is. ENOENT may
	// still turn into a successful directory open below.
	if eno != syscall.ENOENT {
		_, _ = fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → %v\n", path, eno)
		return errno(eno)
	}

	// Fall back to a directory open (opendir()/O_DIRECTORY). We don't
	// enforce the flag — if the name identifies a directory in the VFS,
	// we hand back a directory fd and let getdents64 / fstat figure out
	// the rest.
	if entries := s.vfs.ListDir(path); entries != nil {
		fd := s.nextFD
		s.nextFD++
		s.fdTable[fd] = &OpenFile{path: path, isDir: true}
		_, _ = fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → fd %d (dir, %d entries)\n", path, fd, len(entries))
		return uint64(fd)
	}

	_, _ = fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → ENOENT (not in sandbox)\n", path)
	return errno(syscall.ENOENT)
}

// ──────────────────────────────────────────────────────────────────────
// CLOSE — close(fd)
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysClose(sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	if s.shouldPassthroughFD(fd) {
		// For tracked real fds (rare — openat doesn't register today, but
		// we keep the hook for when it does), drop the bookkeeping entry
		// once the kernel confirms the close succeeded.
		if f, ok := s.fdTable[fd]; ok && f.isRealFD {
			s.requestPassthrough(func(retval uint64) {
				if int64(retval) == 0 {
					delete(s.fdTable, fd)
				}
			})
		} else {
			s.requestPassthrough(nil)
		}
		return 0
	}
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	// Don't close host FDs (stdin/stdout/stderr).
	if f.isHost {
		return 0
	}
	// Socket: close the real outbound connection.
	if f.isSocket && f.conn != nil {
		_ = f.conn.Close()
	}
	delete(s.fdTable, fd)
	return 0
}

// ──────────────────────────────────────────────────────────────────────
// FSTAT / NEWFSTATAT — stat a file descriptor or path
//
// Returns a fabricated stat structure. In gVisor, the Gofer fetches real
// metadata from the host filesystem. We return plausible fake values.
// ──────────────────────────────────────────────────────────────────────

// sysStat handles both fstat(fd, statbuf) and newfstatat(dirfd, path, statbuf, flags).
// The isFstat parameter distinguishes them — true for fstat, false for newfstatat.
// On arm64, fstat doesn't exist as a syscall, so only newfstatat is called from
// sentry.go. On amd64, fstat is dispatched from sentry_amd64.go.
func (s *Sentry) sysStat(pid int, sc SyscallArgs) uint64 {
	return s.doStat(pid, sc, false)
}

func (s *Sentry) sysFstat(pid int, sc SyscallArgs) uint64 {
	return s.doStat(pid, sc, true)
}

func (s *Sentry) doStat(pid int, sc SyscallArgs, isFstat bool) uint64 {
	var (
		size  int64
		isDir bool
	)

	if isFstat {
		fd := int(sc.Args[0])
		if s.shouldPassthroughFD(fd) {
			s.requestPassthrough(nil)
			return 0
		}
		f, ok := s.fdTable[fd]
		if !ok {
			return errno(syscall.EBADF)
		}
		size = int64(len(f.data))
		isDir = f.isDir
	} else {
		// newfstatat(dirfd, path, statbuf, flags). An empty path with
		// AT_EMPTY_PATH means "stat the dirfd itself" — common pattern
		// from modern glibc fstat(). Otherwise look up the path.
		pathPtr := sc.Args[1]
		flags := sc.Args[3]
		path := readStringFromChild(pid, pathPtr, 256)
		if path == "" && flags&0x1000 != 0 /* AT_EMPTY_PATH */ {
			fd := int(sc.Args[0])
			if s.shouldPassthroughFD(fd) {
				s.requestPassthrough(nil)
				return 0
			}
			f, ok := s.fdTable[fd]
			if !ok {
				return errno(syscall.EBADF)
			}
			size = int64(len(f.data))
			isDir = f.isDir
		} else {
			// Path-based stat: mount check for identity passthrough,
			// otherwise VFS lookup.
			cleanPath := filepath.Clean(path)
			if hostPath, _, ok := matchMount(s.mounts, cleanPath); ok && hostPath == cleanPath {
				s.requestPassthrough(nil)
				return 0
			}
			data, eno := s.vfs.Lookup(path)
			if eno == 0 {
				size = int64(len(data))
			} else if entries := s.vfs.ListDir(path); entries != nil {
				isDir = true
			} else {
				return errno(eno)
			}
		}
	}

	// Build a minimal stat structure.
	// On amd64, struct stat is 144 bytes. On arm64, it's 128 bytes.
	// We fill in the fields the C library cares about.
	var stat unix.Stat_t
	if isDir {
		stat.Mode = 040755 // S_IFDIR | rwxr-xr-x
		stat.Nlink = 2
	} else {
		stat.Mode = 0100644 // S_IFREG | rw-r--r--
		stat.Nlink = 1
	}
	stat.Size = size
	stat.Blksize = 4096
	stat.Blocks = (size + 511) / 512

	var statBuf uintptr
	if isFstat {
		statBuf = uintptr(sc.Args[1]) // fstat: arg2 is statbuf
	} else {
		statBuf = uintptr(sc.Args[2]) // newfstatat: arg3 is statbuf
	}
	statBytes := (*[unsafe.Sizeof(stat)]byte)(unsafe.Pointer(&stat))[:]
	writeToChild(pid, uint64(statBuf), statBytes)
	return 0
}

// ──────────────────────────────────────────────────────────────────────
// LSEEK — lseek(fd, offset, whence)
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysLseek(sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	offset := int64(sc.Args[1])
	whence := int(sc.Args[2])

	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}

	switch whence {
	case 0: // SEEK_SET
		f.offset = offset
	case 1: // SEEK_CUR
		f.offset += offset
	case 2: // SEEK_END
		f.offset = int64(len(f.data)) + offset
	default:
		return errno(syscall.EINVAL)
	}
	return uint64(f.offset)
}

// ──────────────────────────────────────────────────────────────────────
// IOCTL — ioctl(fd, request, ...)
//
// We handle TCGETS (terminal attributes query) to let programs detect
// whether stdout is a terminal. Everything else returns ENOTTY.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysIoctl(sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	request := sc.Args[1]
	if request == unix.TCGETS {
		// "Not a terminal" — this makes programs like cat skip line buffering.
		return errno(syscall.ENOTTY)
	}
	return errno(syscall.ENOTTY)
}

// ──────────────────────────────────────────────────────────────────────
// FCNTL — fcntl(fd, cmd, ...)
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysFcntl(sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	cmd := int(sc.Args[1])

	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	if _, ok := s.fdTable[fd]; !ok {
		return errno(syscall.EBADF)
	}
	switch cmd {
	case unix.F_GETFD:
		return 0 // no close-on-exec
	case unix.F_SETFD:
		return 0
	case unix.F_GETFL:
		return 0 // O_RDONLY
	default:
		return errno(syscall.EINVAL)
	}
}

// ──────────────────────────────────────────────────────────────────────
// GETDENTS64 — read directory entries
//
// Returns the list of files in our virtual filesystem.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysGetdents64(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	buf := sc.Args[1]
	bufSize := sc.Args[2]

	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}

	// If we already returned entries for this FD, return 0 (end of directory).
	if f.offset > 0 {
		return 0
	}

	// Get directory listing from VFS.
	dir := f.path
	if dir == "" {
		dir = "/"
	}
	entries := s.vfs.ListDir(dir)
	if entries == nil {
		return errno(syscall.ENOTDIR)
	}

	// Pack dirent64 structures into the buffer.
	var packed []byte
	var inode uint64 = 1000
	for _, name := range entries {
		inode++
		d := packDirent64(inode, name, 8) // DT_REG = 8
		if uint64(len(packed)+len(d)) > bufSize {
			break
		}
		packed = append(packed, d...)
	}

	if len(packed) > 0 {
		writeToChild(pid, buf, packed)
	}
	f.offset = 1 // Mark as "returned entries"
	return uint64(len(packed))
}

// packDirent64 builds a linux_dirent64 structure.
func packDirent64(ino uint64, name string, dtype byte) []byte {
	nameBytes := append([]byte(name), 0) // null-terminated
	reclen := 8 + 8 + 2 + 1 + len(nameBytes)
	// Align to 8 bytes
	if reclen%8 != 0 {
		reclen += 8 - (reclen % 8)
	}
	buf := make([]byte, reclen)
	binary.LittleEndian.PutUint64(buf[0:8], ino)        // d_ino
	binary.LittleEndian.PutUint64(buf[8:16], 0)         // d_off
	binary.LittleEndian.PutUint16(buf[16:18], uint16(reclen)) // d_reclen
	buf[18] = dtype                                      // d_type
	copy(buf[19:], nameBytes)                            // d_name
	return buf
}

// ──────────────────────────────────────────────────────────────────────
// BRK — brk(addr)
//
// brk manages the program break (top of the data segment / heap).
// If addr is 0, return the current break. Otherwise, move the break.
// In gVisor, this is handled by the MemoryManager with real page tracking.
// We just move a pointer — the actual memory is the child's own.
// ──────────────────────────────────────────────────────────────────────

//nolint:unused // educational placeholder — SYSEMU can't emulate brk
// from userspace (it modifies kernel-managed page tables). Documented
// in the README's syscall table; preserved for parity with gVisor's
// handler model.
func (s *Sentry) sysBrk(sc SyscallArgs) uint64 {
	addr := sc.Args[0]
	if addr == 0 {
		return s.brkAddr
	}
	if addr > s.brkAddr {
		s.brkAddr = addr
	}
	return s.brkAddr
}

// ──────────────────────────────────────────────────────────────────────
// MMAP — mmap(addr, length, prot, flags, fd, offset)
//
// Memory mapping. For anonymous mappings (MAP_ANONYMOUS), we return a
// fake address from a reserved range. For file-backed mappings, we'd
// need to actually map the file — not implemented in this mini version.
//
// In gVisor, the MemoryManager handles this with real page table
// management, backed by a host memfd. Our version is a stub that
// works for the common case of anonymous heap/stack allocations.
// ──────────────────────────────────────────────────────────────────────

//nolint:unused // educational placeholder — same reasoning as sysBrk.
func (s *Sentry) sysMmap(sc SyscallArgs) uint64 {
	addr := sc.Args[0]
	length := sc.Args[1]
	flags := int(sc.Args[3])

	if flags&unix.MAP_ANONYMOUS != 0 {
		// Anonymous mapping: allocate from our fake address space.
		// The child's ptrace address space is real, so we just let the
		// kernel handle the actual allocation — we return a hint address
		// and the child's libc will work with it.
		if addr != 0 {
			return addr // Fixed mapping at requested address
		}
		// Return a fake address. In practice, PTRACE_SYSEMU means the
		// kernel won't actually allocate this — the child's libc will
		// just treat it as the mmap return value.
		result := s.brkAddr
		s.brkAddr += (length + 4095) & ^uint64(4095) // page-align
		return result
	}

	// File-backed mapping not supported in this mini version.
	return errno(syscall.ENODEV)
}

// ──────────────────────────────────────────────────────────────────────
// ARCH_PRCTL — arch_prctl(code, addr)
//
// Sets architecture-specific thread state. On x86_64, this is primarily
// used to set the FS base register for thread-local storage (TLS).
// We pass this through to the real kernel because it only affects the
// child's own register state — no security implications.
//
// On arm64, TLS is set via the TPIDR_EL0 register (no arch_prctl needed).
// ──────────────────────────────────────────────────────────────────────

//nolint:unused,unparam // educational placeholder — TLS setup lives
// in the kernel via SYSEMU passthrough, not in a userspace handler.
// pid is kept in the signature to match the platform's handler shape.
func (s *Sentry) sysArchPrctl(pid int, sc SyscallArgs) uint64 {
	code := int(sc.Args[0])

	switch code {
	case 0x1002: // ARCH_SET_FS
		// Set the FS base register for TLS. This is safe to pass through.
		// In gVisor, this is handled by the platform-specific code.
		return 0 // Accept — the ptrace mechanism handles FS base implicitly
	case 0x1001: // ARCH_SET_GS
		return 0
	case 0x1003: // ARCH_GET_FS
		return 0
	case 0x1004: // ARCH_GET_GS
		return 0
	default:
		return errno(syscall.EINVAL)
	}
}

// ──────────────────────────────────────────────────────────────────────
// PRLIMIT64 — prlimit64(pid, resource, new_limit, old_limit)
//
// Get/set resource limits. We return generous defaults.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysPrlimit64(pid int, sc SyscallArgs) uint64 {
	oldLimitPtr := sc.Args[3]

	if oldLimitPtr != 0 {
		// Return a permissive limit: 1MB stack, unlimited everything else
		var limit [16]byte // struct rlimit { rlim_cur, rlim_max }
		binary.LittleEndian.PutUint64(limit[0:8], 8*1024*1024) // 8MB soft
		binary.LittleEndian.PutUint64(limit[8:16], 8*1024*1024) // 8MB hard
		writeToChild(pid, oldLimitPtr, limit[:])
	}
	return 0
}

// ──────────────────────────────────────────────────────────────────────
// GETRANDOM — getrandom(buf, buflen, flags)
//
// Fill a buffer with random bytes. In gVisor, this uses the host's
// /dev/urandom. We use Go's crypto/rand.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysGetrandom(pid int, sc SyscallArgs) uint64 {
	buf := sc.Args[0]
	bufLen := sc.Args[1]

	if bufLen > maxTransfer {
		bufLen = maxTransfer
	}
	if bufLen == 0 {
		return 0
	}
	data := make([]byte, bufLen)
	rand.Read(data)
	writeToChild(pid, buf, data)
	return bufLen
}

// ──────────────────────────────────────────────────────────────────────
// WRITEV — writev(fd, iov, iovcnt)
//
// Glibc's printf family uses writev instead of plain write when multiple
// buffers need to land atomically (e.g. format string + interpolated
// pieces). We walk the iovec array in the child, pull each chunk out,
// and dispatch to the same path sysWrite uses.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysWritev(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	iovPtr := sc.Args[1]
	iovcnt := int(sc.Args[2])

	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if !f.isHost || !f.writable {
		return errno(syscall.EBADF)
	}
	if iovcnt <= 0 || iovcnt > 1024 {
		return errno(syscall.EINVAL)
	}

	// struct iovec { void *iov_base; size_t iov_len; } — 16 bytes on 64-bit.
	const iovecSize = 16
	iovBlock := readFromChild(pid, iovPtr, uint64(iovcnt*iovecSize))
	// readFromChild returns a short/empty slice on EFAULT; only walk
	// whole entries that actually came back, otherwise a garbage iov
	// pointer would panic on the binary.LittleEndian access below.
	entries := len(iovBlock) / iovecSize
	if entries == 0 {
		return errno(syscall.EFAULT)
	}
	var total uint64
	for i := 0; i < entries; i++ {
		off := i * iovecSize
		base := binary.LittleEndian.Uint64(iovBlock[off : off+8])
		length := binary.LittleEndian.Uint64(iovBlock[off+8 : off+16])
		if length == 0 {
			continue
		}
		if length > maxTransfer {
			length = maxTransfer
		}
		data := readFromChild(pid, base, length)
		if len(data) == 0 {
			continue
		}
		n, err := syscall.Write(f.hostFD, data)
		if err != nil {
			if total > 0 {
				return total
			}
			return errno(err.(syscall.Errno))
		}
		total += uint64(n)
	}
	return total
}

// ──────────────────────────────────────────────────────────────────────
// READLINK / READLINKAT — symlink resolution
//
// Glibc's static init reads /proc/self/exe to learn where the binary
// lives. We fake a plausible answer; anything else we don't know about
// returns ENOENT.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysReadlinkat(pid int, sc SyscallArgs) uint64 {
	// readlinkat(dirfd, pathname, buf, bufsiz)
	pathPtr := sc.Args[1]
	bufPtr := sc.Args[2]
	bufsiz := sc.Args[3]
	path := readStringFromChild(pid, pathPtr, 256)
	return s.doReadlink(pid, path, bufPtr, bufsiz)
}

func (s *Sentry) sysReadlink(pid int, sc SyscallArgs) uint64 {
	pathPtr := sc.Args[0]
	bufPtr := sc.Args[1]
	bufsiz := sc.Args[2]
	path := readStringFromChild(pid, pathPtr, 256)
	return s.doReadlink(pid, path, bufPtr, bufsiz)
}

func (s *Sentry) doReadlink(pid int, path string, bufPtr, bufsiz uint64) uint64 {
	var target string
	switch path {
	case "/proc/self/exe", "/proc/self/exe/":
		target = "/sandboxed"
	default:
		return errno(syscall.EINVAL) // not a symlink
	}
	if uint64(len(target)) > bufsiz {
		target = target[:bufsiz]
	}
	writeToChild(pid, bufPtr, []byte(target))
	return uint64(len(target))
}

// ──────────────────────────────────────────────────────────────────────
// GETCWD — getcwd(buf, size)
//
// Always "/" inside the sandbox. Linux returns the NUL-terminated string
// length (including the NUL).
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysGetcwd(pid int, sc SyscallArgs) uint64 {
	bufPtr := sc.Args[0]
	size := sc.Args[1]
	const cwd = "/\x00"
	if size < uint64(len(cwd)) {
		return errno(syscall.ERANGE)
	}
	writeToChild(pid, bufPtr, []byte(cwd))
	return uint64(len(cwd))
}

// ──────────────────────────────────────────────────────────────────────
// UNAME — uname(buf)
//
// Fabricate a utsname so the sandbox has a stable identity that isn't
// the host's. struct utsname is 6 × 65-byte fixed strings (390 bytes).
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysUname(pid int, sc SyscallArgs) uint64 {
	bufPtr := sc.Args[0]
	var buf [6 * 65]byte
	fields := []string{
		"Linux",               // sysname
		"mini-sentry-sandbox", // nodename
		"6.0.0-mini-sentry",   // release
		"#1 SMP mini-sentry",  // version
		"x86_64",              // machine
		"(none)",              // domainname
	}
	for i, s := range fields {
		copy(buf[i*65:], s)
	}
	writeToChild(pid, bufPtr, buf[:])
	return 0
}

// ──────────────────────────────────────────────────────────────────────
// DUP / DUP2 / DUP3 — fd duplication
//
// Glibc's fd-slot bookkeeping reaches for these during init. We mirror
// the fdTable entry under a new fd number. Same underlying data, so
// closing one leaves the other intact as long as it's in the table.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysDup(sc SyscallArgs) uint64 {
	oldFD := int(sc.Args[0])
	if s.shouldPassthroughFD(oldFD) {
		s.requestPassthrough(nil)
		return 0
	}
	f, ok := s.fdTable[oldFD]
	if !ok {
		return errno(syscall.EBADF)
	}
	newFD := s.nextFD
	s.nextFD++
	copy := *f
	s.fdTable[newFD] = &copy
	return uint64(newFD)
}

func (s *Sentry) sysDup2(sc SyscallArgs) uint64 {
	oldFD := int(sc.Args[0])
	newFD := int(sc.Args[1])
	if s.shouldPassthroughFD(oldFD) {
		s.requestPassthrough(nil)
		return 0
	}
	f, ok := s.fdTable[oldFD]
	if !ok {
		return errno(syscall.EBADF)
	}
	if oldFD == newFD {
		return uint64(newFD)
	}
	copy := *f
	s.fdTable[newFD] = &copy
	if newFD >= s.nextFD {
		s.nextFD = newFD + 1
	}
	return uint64(newFD)
}

// ──────────────────────────────────────────────────────────────────────
// SYSINFO / FSTATFS — system and filesystem info
//
// Return a fixed, plausible description so callers don't panic when
// probing for free memory or mount flags.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysSysinfo(pid int, sc SyscallArgs) uint64 {
	bufPtr := sc.Args[0]
	// struct sysinfo { long uptime; ulong loads[3]; ulong totalram;
	//                  ulong freeram; ulong sharedram; ulong bufferram;
	//                  ulong totalswap; ulong freeswap; ushort procs;
	//                  ushort pad; ulong totalhigh; ulong freehigh;
	//                  uint mem_unit; char _f[20-2*sizeof(long)-sizeof(int)]; }
	var buf [112]byte
	binary.LittleEndian.PutUint64(buf[0:8], 1)                 // uptime 1s
	binary.LittleEndian.PutUint64(buf[32:40], 1024*1024*1024)  // totalram 1GB
	binary.LittleEndian.PutUint64(buf[40:48], 512*1024*1024)   // freeram 512MB
	binary.LittleEndian.PutUint64(buf[72:80], 1)               // procs
	binary.LittleEndian.PutUint32(buf[104:108], 1)             // mem_unit
	writeToChild(pid, bufPtr, buf[:])
	return 0
}

func (s *Sentry) sysFstatfs(pid int, sc SyscallArgs) uint64 {
	bufPtr := sc.Args[1]
	// struct statfs on amd64 is 120 bytes. We zero-fill except for a
	// sane block size and a benign "tmpfs-ish" magic.
	var buf [120]byte
	binary.LittleEndian.PutUint64(buf[0:8], 0x01021994)  // f_type = TMPFS_MAGIC
	binary.LittleEndian.PutUint64(buf[8:16], 4096)       // f_bsize
	binary.LittleEndian.PutUint64(buf[16:24], 1024*1024) // f_blocks
	binary.LittleEndian.PutUint64(buf[24:32], 1024*1024) // f_bfree
	writeToChild(pid, bufPtr, buf[:])
	return 0
}

// ──────────────────────────────────────────────────────────────────────
// FADVISE64 — fadvise64(fd, offset, len, advice)
//
// Advisory hint about expected file access patterns. Glibc calls this
// on nearly every fopen(). Purely advisory — the kernel is free to
// ignore it, so returning 0 (success) is always correct.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysFadvise64(_ int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	if s.shouldPassthroughFD(fd) {
		s.requestPassthrough(nil)
		return 0
	}
	// Virtual fds: accept the hint and do nothing.
	return 0
}

// ──────────────────────────────────────────────────────────────────────
// COPY_FILE_RANGE — copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
//
// Modern cat/cp try this first for zero-copy file transfer, then fall
// back to read+write when it returns ENOSYS or EXDEV. We return ENOSYS
// so callers use the normal path which we handle fine.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysCopyFileRange(_ int, _ SyscallArgs) uint64 {
	return errno(syscall.ENOSYS)
}

// ──────────────────────────────────────────────────────────────────────
// PRCTL — prctl(option, arg2, arg3, arg4, arg5)
//
// Process control. Glibc uses it during early init for things like
// PR_SET_NAME, PR_GET_DUMPABLE, PR_SET_VMA. We handle the common
// cases and return 0 (success) or EINVAL for unknown options.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysPrctl(pid int, sc SyscallArgs) uint64 {
	option := int(sc.Args[0])

	switch option {
	case 15: // PR_SET_NAME — set the thread name
		return 0
	case 16: // PR_GET_NAME — get the thread name
		name := []byte("sandboxed\x00")
		writeToChild(pid, sc.Args[1], name)
		return 0
	case 4: // PR_GET_DUMPABLE
		return 1
	case 3: // PR_SET_DUMPABLE
		return 0
	case 38: // PR_SET_NO_NEW_PRIVS
		return 0
	case 0x53564d41: // PR_SET_VMA (ARM64, used by some allocators)
		return 0
	default:
		// Return success for unknown options — glibc often probes
		// capabilities and ignores failure gracefully.
		return 0
	}
}

// ──────────────────────────────────────────────────────────────────────
// STATFS — statfs(path, buf)
//
// Returns filesystem info for a path. Glibc/coreutils use this to
// detect filesystem types (e.g., ls checks for remote filesystems
// to decide whether to stat() lazily).
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysStatfs(pid int, sc SyscallArgs) uint64 {
	pathPtr := sc.Args[0]
	bufPtr := sc.Args[1]
	path := readStringFromChild(pid, pathPtr, 256)

	// Check if this path is on an identity mount — passthrough.
	cleanPath := filepath.Clean(path)
	if hostPath, _, ok := matchMount(s.mounts, cleanPath); ok && hostPath == cleanPath {
		s.requestPassthrough(nil)
		return 0
	}

	// Virtual filesystem: return a tmpfs-like description.
	var buf [120]byte
	binary.LittleEndian.PutUint64(buf[0:8], 0x01021994)  // f_type = TMPFS_MAGIC
	binary.LittleEndian.PutUint64(buf[8:16], 4096)       // f_bsize
	binary.LittleEndian.PutUint64(buf[16:24], 1024*1024) // f_blocks
	binary.LittleEndian.PutUint64(buf[24:32], 1024*1024) // f_bfree
	writeToChild(pid, bufPtr, buf[:])
	return 0
}

// ──────────────────────────────────────────────────────────────────────
// STATX — statx(dirfd, pathname, flags, mask, statxbuf)
//
// Modern stat variant preferred by recent coreutils. For passthrough
// paths (identity mounts) we let the kernel handle it. For VFS paths,
// we fabricate a response from the same data doStat uses.
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysStatx(pid int, sc SyscallArgs) uint64 {
	pathPtr := sc.Args[1]
	bufPtr := sc.Args[4]
	flags := sc.Args[2]
	path := readStringFromChild(pid, pathPtr, 256)

	// AT_EMPTY_PATH with a valid dirfd → stat the fd itself.
	if path == "" && flags&0x1000 != 0 /* AT_EMPTY_PATH */ {
		fd := int(sc.Args[0])
		if s.shouldPassthroughFD(fd) {
			s.requestPassthrough(nil)
			return 0
		}
		// Fall through to fabricate a response for virtual fds.
	} else if path != "" {
		// Path-based: check for identity mount → passthrough.
		cleanPath := filepath.Clean(path)
		if hostPath, _, ok := matchMount(s.mounts, cleanPath); ok && hostPath == cleanPath {
			s.requestPassthrough(nil)
			return 0
		}
	}

	// Fabricate a statx response for virtual paths.
	// struct statx is 256 bytes on x86_64.
	var buf [256]byte
	// stx_mask: STATX_BASIC_STATS (0x07ff)
	binary.LittleEndian.PutUint32(buf[0:4], 0x07ff)
	// stx_blksize
	binary.LittleEndian.PutUint32(buf[4:8], 4096)
	// stx_mode: check if it's a known VFS path
	data, eno := s.vfs.Lookup(path)
	if eno == 0 {
		// Regular file
		binary.LittleEndian.PutUint16(buf[22:24], 0100644) // S_IFREG | rw-r--r--
		binary.LittleEndian.PutUint32(buf[24:28], 1)       // stx_nlink
		binary.LittleEndian.PutUint64(buf[40:48], uint64(len(data))) // stx_size
	} else if entries := s.vfs.ListDir(path); entries != nil {
		// Directory
		binary.LittleEndian.PutUint16(buf[22:24], 040755) // S_IFDIR | rwxr-xr-x
		binary.LittleEndian.PutUint32(buf[24:28], 2)      // stx_nlink
	} else {
		return errno(syscall.ENOENT)
	}
	writeToChild(pid, bufPtr, buf[:])
	return 0
}

// ──────────────────────────────────────────────────────────────────────
// Helper: read/write the child's memory via ptrace
//
// In gVisor, the Sentry accesses application memory through the platform's
// AddressSpace abstraction. On the ptrace platform, this uses
// PTRACE_PEEKDATA / PTRACE_POKEDATA (word-at-a-time) or process_vm_readv
// (bulk copy). We use process_vm_readv/writev for efficiency.
// ──────────────────────────────────────────────────────────────────────

func readFromChild(pid int, addr, size uint64) []byte {
	if size == 0 {
		return nil
	}
	if size > maxTransfer {
		size = maxTransfer
	}
	buf := make([]byte, size)
	localIov := unix.Iovec{Base: &buf[0], Len: size}
	remoteIov := unix.RemoteIovec{Base: uintptr(addr), Len: int(size)}
	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{remoteIov}, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [platform] process_vm_readv failed: %v (addr=0x%x, size=%d)\n", err, addr, size)
		return buf[:0]
	}
	return buf[:n]
}

func writeToChild(pid int, addr uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	if len(data) > maxTransfer {
		data = data[:maxTransfer]
	}
	localIov := unix.Iovec{Base: &data[0], Len: uint64(len(data))}
	remoteIov := unix.RemoteIovec{Base: uintptr(addr), Len: len(data)}
	_, err := unix.ProcessVMWritev(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{remoteIov}, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [platform] process_vm_writev failed: %v (addr=0x%x, size=%d)\n", err, addr, len(data))
	}
}

//nolint:unparam // maxLen is callsite-tunable for future callers that
// need shorter caps (e.g. bounded path reads on recvfrom).
func readStringFromChild(pid int, addr uint64, maxLen int) string {
	buf := readFromChild(pid, addr, uint64(maxLen))
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// ──────────────────────────────────────────────────────────────────────
// Signal handlers (Phase 3a)
//
// These handlers mirror the guest's rt_sigaction / rt_sigprocmask /
// kill / tkill / tgkill activity into s.signals. The pattern is
// "observe then passthrough" — we decode the arguments, update our
// SignalState, and then requestPassthrough so the kernel still
// installs the real handler or applies the real mask change. The
// single exception is a kill() targeting the guest itself: the guest
// believes its PID is 1 (we spoof getpid/gettid), so we rewrite the
// target to the tracee's real host PID and fire a host kill() from
// the Sentry thread. The kernel queues the signal as pending; on the
// next resume our platform wait loop routes it through SignalState.
//
// ABI reminder (amd64 / arm64 kernel_sigaction layout):
//
//   struct kernel_sigaction {
//       void     *sa_handler;    // +0,  8 bytes
//       unsigned long sa_flags;  // +8,  8 bytes
//       void     *sa_restorer;   // +16, 8 bytes  (only on arches with SA_RESTORER)
//       sigset_t  sa_mask;       // +24, 8 bytes  (1 word == 64 bits on Linux)
//   };
//
// Total: 32 bytes. struct sigaction (the glibc layout) differs —
// sa_mask is padded to 128 bytes on glibc — but the *syscall* always
// takes the kernel layout because the kernel defines the ABI.
//
// rt_sigaction also takes a trailing sigsetsize argument to
// distinguish the kernel ABI (8) from legacy (longer) layouts. We
// accept any value that fits — correctness is up to the kernel on
// passthrough.
// ──────────────────────────────────────────────────────────────────────

// sysRtSigaction — record the new disposition, write the old one back
// if requested, then passthrough so the kernel installs the handler
// for real.
//
//   int rt_sigaction(int signum,
//                    const struct kernel_sigaction *act,
//                    struct kernel_sigaction *oldact,
//                    size_t sigsetsize);
//
// The wire layout of struct kernel_sigaction differs between amd64 and
// arm64 (amd64 has sa_restorer, arm64 doesn't); we look up the offsets
// from the per-arch kernelSigactionLayout and size from
// kernelSigactionSize defined in regs_<arch>.go.
func (s *Sentry) sysRtSigaction(pid int, sc SyscallArgs) uint64 {
	signum := int(sc.Args[0])
	actPtr := sc.Args[1]
	oldactPtr := sc.Args[2]
	layout := kernelSigactionLayout

	// Capture the old disposition *before* we let the new one land.
	// We need it for the oldact write-back below — the kernel will
	// clobber its copy during passthrough.
	old := s.signals.GetAction(signum)

	if actPtr != 0 {
		buf := readFromChild(pid, actPtr, kernelSigactionSize)
		if len(buf) >= kernelSigactionSize {
			newAct := SigAction{
				handler: binary.LittleEndian.Uint64(buf[layout.handlerOff : layout.handlerOff+8]),
				flags:   binary.LittleEndian.Uint64(buf[layout.flagsOff : layout.flagsOff+8]),
				mask:    sigset(binary.LittleEndian.Uint64(buf[layout.maskOff : layout.maskOff+8])),
			}
			if layout.hasRestorer {
				newAct.restorer = binary.LittleEndian.Uint64(buf[layout.restorerOff : layout.restorerOff+8])
			}
			s.signals.SetAction(signum, newAct)
			_, _ = fmt.Fprintf(logWriter(), "  [sentry] rt_sigaction: %s -> %s\n",
				signalName(signum), newAct.String())
		}
	}

	if oldactPtr != 0 {
		// Write our mirrored previous disposition to *oldact. This
		// matches what the kernel would write, because we've been
		// keeping the mirror in sync on every successful call.
		buf := make([]byte, kernelSigactionSize)
		binary.LittleEndian.PutUint64(buf[layout.handlerOff:layout.handlerOff+8], old.handler)
		binary.LittleEndian.PutUint64(buf[layout.flagsOff:layout.flagsOff+8], old.flags)
		binary.LittleEndian.PutUint64(buf[layout.maskOff:layout.maskOff+8], uint64(old.mask))
		if layout.hasRestorer {
			binary.LittleEndian.PutUint64(buf[layout.restorerOff:layout.restorerOff+8], old.restorer)
		}
		writeToChild(pid, oldactPtr, buf)
	}

	// Passthrough so Go's runtime actually has the handler installed
	// with the kernel — otherwise SIGSEGV on a nil deref would be a
	// silent black hole. On return, we don't need to read anything
	// back: the kernel's oldact write we pre-empted with our own
	// mirrored copy above.
	s.requestPassthrough(nil)
	return 0
}

// sysSigaltstack — mirror the guest's alternate signal stack onto
// SignalState, then passthrough so the kernel's copy also sees it
// (synchronous signals like SIGSEGV still go through the kernel's
// delivery path and SA_ONSTACK there depends on the kernel knowing
// about the altstack).
//
//   int sigaltstack(const stack_t *ss, stack_t *old_ss);
//
// Queries (ss==NULL) are a plain passthrough — the kernel writes
// *old_ss from its copy, which is always in sync with ours because we
// passthrough every successful write. The mirror exists for
// deliverOne's SA_ONSTACK branch, not for serving reads.
func (s *Sentry) sysSigaltstack(pid int, sc SyscallArgs) uint64 {
	ssPtr := sc.Args[0]
	if ssPtr != 0 {
		buf := readFromChild(pid, ssPtr, 24)
		if len(buf) >= 24 {
			var as StackT
			as.SS_sp = binary.LittleEndian.Uint64(buf[0:8])
			as.SS_flags = int32(binary.LittleEndian.Uint32(buf[8:12]))
			as.SS_size = binary.LittleEndian.Uint64(buf[16:24])
			s.signals.SetAltStack(as)
			_, _ = fmt.Fprintf(logWriter(),
				"  [sentry] sigaltstack: sp=0x%x size=%d flags=0x%x\n",
				as.SS_sp, as.SS_size, as.SS_flags)
		}
	}
	// Let the kernel validate and write *old_ss. If validation fails,
	// the guest sees the real errno; our mirror is speculative but
	// deliverOne's AltStackUsable gate catches obviously-bad values
	// before we try to forge a frame on them.
	s.requestPassthrough(nil)
	return 0
}

// sysRtSigprocmask — update the Sentry-side mask mirror, then
// passthrough.
//
//   int rt_sigprocmask(int how, const sigset_t *set,
//                      sigset_t *oldset, size_t sigsetsize);
//
// how: SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2.
func (s *Sentry) sysRtSigprocmask(pid int, sc SyscallArgs) uint64 {
	how := int(sc.Args[0])
	setPtr := sc.Args[1]
	oldsetPtr := sc.Args[2]

	// The "read current mask" case is just (set==NULL, oldset!=NULL).
	// We still pass it through but update our mirror for symmetry.
	var newSet sigset
	if setPtr != 0 {
		buf := readFromChild(pid, setPtr, 8)
		if len(buf) >= 8 {
			newSet = sigset(binary.LittleEndian.Uint64(buf))
		}
	}

	var oldMask sigset
	if setPtr != 0 {
		oldMask = s.signals.SetMask(how, newSet)
	} else {
		oldMask = s.signals.GetMask()
	}
	_, _ = fmt.Fprintf(logWriter(), "  [sentry] rt_sigprocmask: how=%d set=0x%x -> mask=0x%x\n",
		how, uint64(newSet), uint64(s.signals.GetMask()))

	if oldsetPtr != 0 {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(oldMask))
		writeToChild(pid, oldsetPtr, buf[:])
	}

	// Passthrough so the kernel applies the mask change for real.
	// Signal delivery still happens kernel-side in Phase 3a; the
	// mirror is only for platform routing visibility.
	s.requestPassthrough(nil)
	return 0
}

// sysKill — kill(pid, sig). In mini-sentry the guest always sees itself
// as PID 1 (see SYS_GETPID emulation), so the idiomatic "raise your
// own signal" form is kill(1, sig) or kill(getpid(), sig). We
// recognise those and serve them without exposing the host PID
// namespace: we call the real kernel kill() with the tracee's actual
// PID. Other target pids passthrough unmodified (in practice the
// guest rarely targets anything else because it only sees itself).
func (s *Sentry) sysKill(pid int, sc SyscallArgs) uint64 {
	targetPid := int64(sc.Args[0])
	signum := int(sc.Args[1])
	if targetPid == 1 || targetPid == 0 || targetPid == -1 {
		// 1 = guest's own PID (we spoof); 0 = "send to my process
		// group" (we're alone); -1 = "every process I can reach"
		// (ditto, just us). In all three cases the target is the
		// tracee itself.
		return s.sendSelfSignal(pid, signum, "kill")
	}
	s.requestPassthrough(nil)
	return 0
}

// sysTkill — tkill(tid, sig). The tracee's view of its own TID is 1
// (see SYS_GETTID), so the same rewrite applies.
func (s *Sentry) sysTkill(pid int, sc SyscallArgs) uint64 {
	targetTid := int64(sc.Args[0])
	signum := int(sc.Args[1])
	if targetTid == 1 {
		return s.sendSelfSignal(pid, signum, "tkill")
	}
	s.requestPassthrough(nil)
	return 0
}

// sysTgkill — tgkill(tgid, tid, sig).
func (s *Sentry) sysTgkill(pid int, sc SyscallArgs) uint64 {
	tgid := int64(sc.Args[0])
	tid := int64(sc.Args[1])
	signum := int(sc.Args[2])
	if tgid == 1 && tid == 1 {
		return s.sendSelfSignal(pid, signum, "tgkill")
	}
	s.requestPassthrough(nil)
	return 0
}

// sendSelfSignal queues a self-targeted signal onto SignalState.pending.
// The platform wait loop drains the queue at the next resume point —
// Sentry-side delivery builds the rt_sigframe and redirects the
// tracee's RIP to the installed handler (deliver_amd64.go). Phase
// 3b commit 3 replaces the earlier Phase 3a behavior, which issued a
// real host kill() and relied on the kernel to build the frame.
//
// A signum of 0 is the "is this process alive" probe — we return 0
// without queueing anything, matching kill(pid, 0) semantics.
//
// We fabricate a minimal SI_USER-shaped siginfo (si_signo, si_code,
// si_pid, si_uid). That's what the kernel would write for a kill(2)
// from a sibling process; on delivery the tracee sees a siginfo_t
// consistent with the self-raise origin. "pid" here is the spoofed
// tgid=1 and "uid" is 0 because that's what the guest sees via our
// getpid/getuid handlers.
func (s *Sentry) sendSelfSignal(pid, signum int, from string) uint64 {
	if signum == 0 {
		return 0
	}
	if signum < 1 || signum >= nSig {
		return errno(syscall.EINVAL)
	}
	s.signals.CountGenerated(signum)
	if s.useHostSignalDelivery {
		// Seccomp platform: no ptrace, no drain. Fall back to a real
		// host kill — the kernel builds the frame and delivers. This
		// matches pre-3b behavior on seccomp and keeps self-kill
		// tests like guest/main.go Test 7 working there.
		if err := syscall.Kill(pid, syscall.Signal(signum)); err != nil {
			if e, ok := err.(syscall.Errno); ok {
				return errno(e)
			}
			return errno(syscall.EPERM)
		}
		_, _ = fmt.Fprintf(logWriter(),
			"  [sentry] %s(self, %s) -> host kill (seccomp)\n",
			from, signalName(signum))
		return 0
	}
	info := buildSelfSiginfo(signum)
	s.signals.Enqueue(signum, info)
	_, _ = fmt.Fprintf(logWriter(), "  [sentry] %s(self, %s) -> enqueued\n",
		from, signalName(signum))
	return 0
}

// buildSelfSiginfo fabricates the 128-byte siginfo_t the kernel would
// write for a sibling-process kill(2). Layout on both amd64 and arm64:
//
//	si_signo (i32) | si_errno (i32) | si_code (i32) | pad(4) |
//	si_pid   (i32) | si_uid   (u32) | ... (rest zero) ...
//
// si_code = SI_USER = 0; si_pid = the tgid the guest sees (1); si_uid = 0.
func buildSelfSiginfo(signum int) [sigInfoBytes]byte {
	var info [sigInfoBytes]byte
	binary.LittleEndian.PutUint32(info[0:4], uint32(signum))
	// si_errno (offset 4) and si_code (offset 8) stay zero: SI_USER == 0.
	binary.LittleEndian.PutUint32(info[16:20], 1) // si_pid: guest sees tgid 1
	binary.LittleEndian.PutUint32(info[20:24], 0) // si_uid: guest runs as root
	return info
}

