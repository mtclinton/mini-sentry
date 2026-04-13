//go:build linux

package main

// sentry.go — The Sentry / userspace kernel (maps to gVisor's pkg/sentry/kernel)
//
// In gVisor, the Sentry is a ~200,000-line Go program that implements the
// Linux kernel interface. It handles every syscall, manages processes,
// memory, signals, pipes, sockets, and filesystems — all in userspace.
//
// Our mini-sentry handles ~15 syscalls, enough to run simple programs.
// The key insight is the same: the sandboxed process thinks it's talking
// to the Linux kernel, but every syscall is handled by Go code that we
// control. We decide what files exist, what data to return, and what
// operations are allowed.
//
// Why this matters for security:
//   - A kernel exploit in the sandboxed program hits our Go code, not the
//     real kernel. Go is memory-safe — no buffer overflows, no UAF.
//   - We control the syscall surface. If a syscall isn't implemented here,
//     it returns ENOSYS. The attack surface is exactly what we chose.
//   - The virtual filesystem means the sandboxed process can't see or
//     touch the real host filesystem — it only sees what we provide.

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// SyscallArgs holds the decoded syscall number and arguments.
// Architecture-specific code (regs_*.go) fills this from CPU registers.
type SyscallArgs struct {
	Number uint64
	Args   [6]uint64
}

// SyscallAction tells the Platform what to do with a syscall.
//
// Emulated syscalls are handled entirely in the Sentry — the Platform
// injects the returned value into the tracee's RAX and the real kernel
// never sees the syscall. This is the PTRACE_SYSEMU fast path.
//
// Passthrough syscalls are executed by the real kernel against the
// tracee's own process. We need this for operations that manipulate
// low-level process state the Sentry can't emulate: the FS base register
// (arch_prctl), real memory mappings (mmap/munmap/mprotect), the program
// break (brk), signal masks, etc. The Platform rewinds RIP back to the
// `syscall` instruction and re-runs it under PTRACE_SYSCALL mode so the
// kernel actually executes it.
type SyscallAction int

const (
	ActionReturn      SyscallAction = iota // inject the returned value
	ActionPassthrough                      // execute in the real kernel
)

// SyscallHandler implements one syscall. Returns the value the sandboxed
// process will see as the syscall result (negative = -errno).
//
// Maps to: gVisor's kernel.SyscallFn in pkg/sentry/kernel/syscalls.go
type SyscallHandler func(s *Sentry, pid int, sc SyscallArgs) uint64

// SyscallEntry is one row of the syscall dispatch table.
//
// A nil handler paired with passthrough=true means "let the real kernel
// run this syscall against the tracee". Otherwise the handler is invoked
// and its return value is injected into RAX.
//
// Maps to: gVisor's kernel.Syscall struct in pkg/sentry/kernel/syscalls.go
type SyscallEntry struct {
	handler     SyscallHandler
	name        string
	passthrough bool
}

// Sentry is the userspace kernel. It maintains per-process state
// (open file descriptors, memory mappings) and dispatches syscalls
// to the appropriate handler.
//
// Maps to: gVisor's pkg/sentry/kernel.Kernel
type Sentry struct {
	vfs       VFS
	netPolicy *NetPolicy
	mu        sync.Mutex
	stats     map[string]int // syscall name → count

	// syscalls is the dispatch table. Built once in NewSentry and then
	// read-only, so no locking is needed for lookups.
	//
	// Maps to: gVisor's SyscallTable in pkg/sentry/kernel/syscalls.go
	// (see SyscallTable.Lookup in pkg/sentry/syscalls/linux/linux64.go).
	syscalls map[uint64]SyscallEntry

	// fdTable maps file descriptor numbers to open files.
	// In gVisor, this is the kernel.FDTable with reference counting,
	// close-on-exec flags, etc. Ours is a simple map.
	//
	// FDs 0, 1, 2 are pre-opened as stdin/stdout/stderr and passed
	// through to the host (the Sentry's own stdin/stdout/stderr).
	fdTable map[int]*OpenFile
	nextFD  int

	// brkAddr tracks the program break for brk() syscall.
	// In gVisor, this is managed by the MemoryManager.
	brkAddr uint64
}

// OpenFile represents an open file descriptor in the sandbox.
// Maps to: gVisor's vfs.FileDescription
type OpenFile struct {
	path     string
	data     []byte // file contents (from VFS)
	offset   int64  // current read/write position
	isHost   bool   // true for stdin/stdout/stderr (passed through)
	hostFD   int    // actual host FD (only if isHost)
	writable bool
	isDir    bool // true when this fd was opened against a directory

	// Socket state — populated when the fd represents a virtual TCP
	// socket dialed by the Sentry on the guest's behalf. conn is nil
	// between socket() and connect(); after connect() it owns the real
	// outbound TCP connection.
	isSocket   bool
	sockFamily int
	conn       net.Conn
	remoteIP   net.IP
	remotePort int
	localIP    net.IP
	localPort  int
}

func NewSentry(vfs VFS) *Sentry {
	return NewSentryWithPolicy(vfs, nil)
}

// NewSentryWithPolicy builds a Sentry with an optional outbound-network
// policy. A nil policy means "allow everything" (policy.Allowed treats
// a nil receiver as permissive), matching the --net-allow default.
func NewSentryWithPolicy(vfs VFS, policy *NetPolicy) *Sentry {
	s := &Sentry{
		vfs:       vfs,
		netPolicy: policy,
		stats:     make(map[string]int),
		fdTable:   make(map[int]*OpenFile),
		nextFD:    3, // 0,1,2 are reserved for stdio
		brkAddr:   0x10000000, // initial program break
	}
	// Pre-open stdio file descriptors.
	// These pass through to the host — the sandbox can write to stdout.
	// In gVisor, stdio is handled through the TTY subsystem or host FD maps.
	s.fdTable[0] = &OpenFile{path: "/dev/stdin", isHost: true, hostFD: 0}
	s.fdTable[1] = &OpenFile{path: "/dev/stdout", isHost: true, hostFD: 1, writable: true}
	s.fdTable[2] = &OpenFile{path: "/dev/stderr", isHost: true, hostFD: 2, writable: true}

	s.buildSyscallTable()
	s.addArchSyscalls()
	return s
}

// buildSyscallTable populates the cross-architecture syscall entries.
// Architecture-specific syscalls are added afterwards by addArchSyscalls
// (see sentry_amd64.go / sentry_arm64.go).
func (s *Sentry) buildSyscallTable() {
	// Tiny wrappers for handlers whose method signature doesn't already
	// match SyscallHandler (pid unused, or constant return).
	emulated := func(nr uint64, name string, h SyscallHandler) {
		s.syscalls[nr] = SyscallEntry{name: name, handler: h}
	}
	passthrough := func(nr uint64, name string) {
		s.syscalls[nr] = SyscallEntry{name: name, passthrough: true}
	}
	constRet := func(v uint64) SyscallHandler {
		return func(*Sentry, int, SyscallArgs) uint64 { return v }
	}

	s.syscalls = make(map[uint64]SyscallEntry)

	// ── File operations (maps to gVisor's VFS2) ──────────────────────
	emulated(unix.SYS_READ, "read", (*Sentry).sysRead)
	emulated(unix.SYS_WRITE, "write", (*Sentry).sysWrite)
	emulated(unix.SYS_WRITEV, "writev", (*Sentry).sysWritev)
	emulated(unix.SYS_OPENAT, "openat", (*Sentry).sysOpenat)
	emulated(unix.SYS_CLOSE, "close", func(s *Sentry, _ int, sc SyscallArgs) uint64 { return s.sysClose(sc) })
	emulated(unix.SYS_NEWFSTATAT, "newfstatat", (*Sentry).sysStat)
	emulated(unix.SYS_LSEEK, "lseek", func(s *Sentry, _ int, sc SyscallArgs) uint64 { return s.sysLseek(sc) })
	emulated(unix.SYS_IOCTL, "ioctl", func(s *Sentry, _ int, sc SyscallArgs) uint64 { return s.sysIoctl(sc) })
	emulated(unix.SYS_FCNTL, "fcntl", func(s *Sentry, _ int, sc SyscallArgs) uint64 { return s.sysFcntl(sc) })
	emulated(unix.SYS_GETDENTS64, "getdents64", (*Sentry).sysGetdents64)
	emulated(unix.SYS_FACCESSAT, "faccessat", (*Sentry).sysFaccessat)
	emulated(unix.SYS_READLINKAT, "readlinkat", (*Sentry).sysReadlinkat)
	emulated(unix.SYS_GETCWD, "getcwd", (*Sentry).sysGetcwd)
	emulated(unix.SYS_UNAME, "uname", (*Sentry).sysUname)
	emulated(unix.SYS_SYSINFO, "sysinfo", (*Sentry).sysSysinfo)
	emulated(unix.SYS_FSTATFS, "fstatfs", (*Sentry).sysFstatfs)
	emulated(unix.SYS_DUP, "dup", func(s *Sentry, _ int, sc SyscallArgs) uint64 { return s.sysDup(sc) })
	emulated(unix.SYS_DUP3, "dup3", func(s *Sentry, _ int, sc SyscallArgs) uint64 { return s.sysDup2(sc) })

	// ── Network (virtual TCP proxy via the Sentry) ──────────────────
	// socket() allocates a virtual fd; connect() dials the real
	// outbound TCP from the Sentry after a policy check; read/write
	// on these fds go through the proxied net.Conn (see sysRead/sysWrite).
	emulated(unix.SYS_SOCKET, "socket", (*Sentry).sysSocket)
	emulated(unix.SYS_CONNECT, "connect", (*Sentry).sysConnect)
	emulated(unix.SYS_SENDTO, "sendto", (*Sentry).sysSendto)
	emulated(unix.SYS_RECVFROM, "recvfrom", (*Sentry).sysRecvfrom)
	emulated(unix.SYS_GETPEERNAME, "getpeername", (*Sentry).sysGetpeername)
	emulated(unix.SYS_GETSOCKNAME, "getsockname", (*Sentry).sysGetsockname)
	emulated(unix.SYS_SETSOCKOPT, "setsockopt", (*Sentry).sysSetsockopt)
	emulated(unix.SYS_GETSOCKOPT, "getsockopt", (*Sentry).sysGetsockopt)

	// ── Architecture / thread setup ─────────────────────────────────
	// set_tid_address stores a pointer for clear_child_tid on exit.
	// Return the child's TID (we fake it as the PID).
	emulated(unix.SYS_SET_TID_ADDRESS, "set_tid_address",
		func(_ *Sentry, pid int, _ SyscallArgs) uint64 { return uint64(pid) })
	emulated(unix.SYS_SET_ROBUST_LIST, "set_robust_list", constRet(0))
	emulated(unix.SYS_RSEQ, "rseq", constRet(0))
	emulated(unix.SYS_PRLIMIT64, "prlimit64", (*Sentry).sysPrlimit64)
	emulated(unix.SYS_GETRANDOM, "getrandom", (*Sentry).sysGetrandom)

	// ── Identity (fake root in sandbox) ─────────────────────────────
	emulated(unix.SYS_GETUID, "getuid", constRet(0))
	emulated(unix.SYS_GETEUID, "geteuid", constRet(0))
	emulated(unix.SYS_GETGID, "getgid", constRet(0))
	emulated(unix.SYS_GETEGID, "getegid", constRet(0))
	emulated(unix.SYS_GETPID, "getpid", constRet(1))  // PID 1 inside the sandbox, like a container
	emulated(unix.SYS_GETTID, "gettid", constRet(1))

	// ── Passthrough: real kernel executes these against the tracee ──
	//
	// Memory management: mmap/munmap/mprotect/brk change the tracee's
	// page tables — only the kernel can do that safely.
	//
	// Signals: rt_sigaction/rt_sigprocmask/sigaltstack/rt_sigreturn
	// touch per-process signal state the kernel manages. Go's runtime
	// installs real handlers and expects them to fire.
	//
	// Threading/sync: futex and clone/gettid need real kernel primitives.
	//
	// exit/exit_group must actually terminate the process. If we emulate
	// them the Go runtime returns from its exit wrapper and executes
	// whatever garbage follows (typically ud2 → SIGSEGV).
	passthrough(unix.SYS_MMAP, "mmap")
	passthrough(unix.SYS_MUNMAP, "munmap")
	passthrough(unix.SYS_MPROTECT, "mprotect")
	passthrough(unix.SYS_BRK, "brk")
	passthrough(unix.SYS_MREMAP, "mremap")
	passthrough(unix.SYS_MADVISE, "madvise")
	passthrough(unix.SYS_RT_SIGACTION, "rt_sigaction")
	passthrough(unix.SYS_RT_SIGPROCMASK, "rt_sigprocmask")
	passthrough(unix.SYS_RT_SIGRETURN, "rt_sigreturn")
	passthrough(unix.SYS_SIGALTSTACK, "sigaltstack")
	passthrough(unix.SYS_FUTEX, "futex")
	passthrough(unix.SYS_SCHED_YIELD, "sched_yield")
	passthrough(unix.SYS_SCHED_GETAFFINITY, "sched_getaffinity")
	passthrough(unix.SYS_NANOSLEEP, "nanosleep")
	passthrough(unix.SYS_CLOCK_NANOSLEEP, "clock_nanosleep")
	passthrough(unix.SYS_CLONE, "clone")
	passthrough(unix.SYS_CLONE3, "clone3")
	passthrough(unix.SYS_TGKILL, "tgkill")
	passthrough(unix.SYS_KILL, "kill")
	passthrough(unix.SYS_EXIT, "exit")
	passthrough(unix.SYS_EXIT_GROUP, "exit_group")
}

// HandleSyscall dispatches a syscall through the table.
// This is the main entry point called by the Platform for every intercepted syscall.
//
// Maps to: gVisor's kernel.Task.executeSyscall() via SyscallTable.Lookup().
//
// The return value is what the sandboxed process sees as the syscall result.
// Convention: negative values are -errno (e.g., -2 = -ENOENT = "file not found").
//
// The SyscallAction tells the Platform whether to inject the returned value
// (ActionReturn) or to execute the syscall in the real kernel (ActionPassthrough).
func (s *Sentry) HandleSyscall(pid int, sc SyscallArgs) (uint64, SyscallAction) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.syscalls[sc.Number]
	if !ok {
		name := fmt.Sprintf("syscall_%d", sc.Number)
		s.stats[name]++
		fmt.Fprintf(logWriter(), "  [sentry] ENOSYS: %s (#%d) — not implemented\n", name, sc.Number)
		return errno(syscall.ENOSYS), ActionReturn
	}

	s.stats[entry.name]++

	if entry.passthrough {
		fmt.Fprintf(logWriter(), "  [sentry] passthrough: %s (#%d)\n", entry.name, sc.Number)
		return 0, ActionPassthrough
	}

	return entry.handler(s, pid, sc), ActionReturn
}

// PrintStats outputs a summary of handled syscalls.
func (s *Sentry) PrintStats(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := 0
	for _, count := range s.stats {
		total += count
	}
	fmt.Fprintf(w, "│  Syscalls intercepted: %-29d│\n", total)
	fmt.Fprintf(w, "│  Breakdown:                                         │\n")

	// Sort by count (simple selection — it's a small map)
	type entry struct {
		name  string
		count int
	}
	var entries []entry
	for name, count := range s.stats {
		entries = append(entries, entry{name, count})
	}
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].count > entries[i].count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	for _, e := range entries {
		fmt.Fprintf(w, "│    %-20s %5d                       │\n", e.name, e.count)
	}
}

// errno converts a Go syscall.Errno to the kernel return convention.
// Negative value = error, e.g., -ENOENT = -2.
// Zero or positive = success.
func errno(e syscall.Errno) uint64 {
	if e == 0 {
		return 0
	}
	return uint64(-int64(e))
}

func logWriter() io.Writer {
	if os.Getenv("MINI_SENTRY_VERBOSE") != "" {
		return os.Stderr
	}
	return io.Discard
}
