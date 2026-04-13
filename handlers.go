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
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

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

	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF) // bad file descriptor
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
// WRITE — write(fd, buf, count)
//
// In gVisor: vfs.FileDescription.Write()
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysWrite(pid int, sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
	buf := sc.Args[1]
	count := sc.Args[2]

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

	// Try a regular file first.
	data, eno := s.vfs.Lookup(path)
	if eno == 0 {
		fd := s.nextFD
		s.nextFD++
		s.fdTable[fd] = &OpenFile{path: path, data: data}
		fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → fd %d (%d bytes)\n", path, fd, len(data))
		return uint64(fd)
	}

	// EACCES / any non-ENOENT error is propagated as-is. ENOENT may
	// still turn into a successful directory open below.
	if eno != syscall.ENOENT {
		fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → %v\n", path, eno)
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
		fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → fd %d (dir, %d entries)\n", path, fd, len(entries))
		return uint64(fd)
	}

	fmt.Fprintf(logWriter(), "  [sentry] openat(%q) → ENOENT (not in sandbox)\n", path)
	return errno(syscall.ENOENT)
}

// ──────────────────────────────────────────────────────────────────────
// CLOSE — close(fd)
// ──────────────────────────────────────────────────────────────────────

func (s *Sentry) sysClose(sc SyscallArgs) uint64 {
	fd := int(sc.Args[0])
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
		f.conn.Close()
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
			if f, ok := s.fdTable[fd]; ok {
				size = int64(len(f.data))
				isDir = f.isDir
			} else {
				return errno(syscall.EBADF)
			}
		} else {
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

	f, ok := s.fdTable[fd]
	if !ok {
		return errno(syscall.EBADF)
	}
	if !(f.isHost && f.writable) {
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

func readStringFromChild(pid int, addr uint64, maxLen int) string {
	buf := readFromChild(pid, addr, uint64(maxLen))
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

