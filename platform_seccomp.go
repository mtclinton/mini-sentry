//go:build linux

package main

// platform_seccomp.go — Seccomp + user-notify platform (educational cousin
// of gVisor's systrap).
//
// Design
// ------
// The child process installs a seccomp-BPF filter whose verdict is driven
// by the syscall number:
//
//   emulated syscalls     → SECCOMP_RET_USER_NOTIF  (the Sentry handles them)
//   everything else       → SECCOMP_RET_ALLOW       (real kernel runs them)
//
// When the child makes an emulated syscall, the kernel freezes the child
// and queues a notification on a listener fd the Sentry is polling. The
// Sentry reads the notification (pid, syscall nr, args), dispatches through
// the exact same HandleSyscall path the ptrace platform uses, then writes a
// response (return value or negative errno). The kernel unfreezes the child
// with that result. ALLOWed syscalls — getpid, mmap, brk, futex, etc. —
// are never observed by the Sentry at all. That's the performance story
// vs. ptrace, which stops the child on every syscall.
//
// The awkward part is getting the listener fd out of the child. seccomp()
// must be called from the process that the filter will apply to (the child,
// after fork and before exec), but the fd the call returns has to end up
// in the Sentry (the parent). We solve this with a re-exec dance:
//
//   1. Parent creates a SOCK_SEQPACKET socketpair.
//   2. Parent fork+execs /proc/self/exe with MINI_SENTRY_BOOTSTRAP=1 and
//      the child end of the socketpair mapped to fd 3.
//   3. The re-invoked binary sees the env var and enters runSeccompBootstrap:
//        prctl(PR_SET_NO_NEW_PRIVS)
//        seccomp(SET_MODE_FILTER, NEW_LISTENER, prog)  → listener fd
//        sendmsg(fd 3, SCM_RIGHTS{listener fd})
//        execve(real target)
//   4. Parent recvmsg's the listener fd, closes its socket, and enters the
//      notification loop.
//
// Between filter install and execve, the bootstrap MUST NOT make any
// syscall in the emulated set — there's no Sentry listening yet, so a
// USER_NOTIF from that window would deadlock. We minimize the window by
// pre-building sendmsg/execve arguments before installing, and by using
// raw syscalls (no Go stdlib wrappers that might allocate or yield).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	bootstrapEnvVar = "MINI_SENTRY_BOOTSTRAP"
	emulatedEnvVar  = "MINI_SENTRY_EMULATED_SYSCALLS"

	prSetNoNewPrivs = 38

	// BPF opcodes we need.
	bpfLD_W_ABS  = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJMP_JEQ_K = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRET_K     = 0x06 // BPF_RET | BPF_K
)

// sockFilter matches `struct sock_filter` (8 bytes).
type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// sockFprog matches `struct sock_fprog` on 64-bit Linux (16 bytes with
// padding between Len and Filter so the pointer is 8-byte aligned).
type sockFprog struct {
	Len    uint16
	_      [6]byte
	Filter *sockFilter
}

// seccompData mirrors the kernel's struct seccomp_data (64 bytes).
type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

// seccompNotif matches struct seccomp_notif (80 bytes). Layout:
//   id:u64, pid:u32, flags:u32, data:seccompData
type seccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

// seccompNotifResp matches struct seccomp_notif_resp (24 bytes):
//   id:u64, val:i64, error:i32, flags:u32
type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// SeccompPlatform routes emulated syscalls through a seccomp user-notify
// listener fd. Passthrough syscalls (anything not in allowList or explicitly
// excluded) bypass the Sentry entirely — they hit the real kernel directly.
//
// allowList names syscall numbers that should NOT be trapped even if the
// Sentry has a handler for them. main.go uses this to exclude SYS_GETPID
// when running --benchmark, so the getpid() hot loop gets the full
// "seccomp passthrough costs nothing" treatment.
type SeccompPlatform struct {
	sentry    *Sentry
	allowList []uint64
}

func NewSeccompPlatform(sentry *Sentry, allow []uint64) *SeccompPlatform {
	return &SeccompPlatform{sentry: sentry, allowList: allow}
}

// emulatedSyscalls returns the syscall numbers the BPF filter should trap
// with SECCOMP_RET_USER_NOTIF.
func (p *SeccompPlatform) emulatedSyscalls() []uint32 {
	allow := make(map[uint64]bool, len(p.allowList))
	for _, n := range p.allowList {
		allow[n] = true
	}
	var out []uint32
	for nr, entry := range p.sentry.syscalls {
		if entry.passthrough || entry.handler == nil {
			continue
		}
		if allow[nr] {
			continue
		}
		out = append(out, uint32(nr))
	}
	return out
}

func (p *SeccompPlatform) Run(program string, args ...string) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	path, err := exec.LookPath(program)
	if err != nil {
		return -1, fmt.Errorf("program not found: %s: %w", program, err)
	}

	// Socketpair for handoff of the seccomp listener fd from child to parent.
	// SEQPACKET keeps a single sendmsg/recvmsg 1:1 so we don't have to
	// length-prefix anything.
	sp, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return -1, fmt.Errorf("socketpair: %w", err)
	}
	parentSock, childSock := sp[0], sp[1]

	// Serialize the trap set for the bootstrap to consume.
	emulated := p.emulatedSyscalls()
	emStrs := make([]string, 0, len(emulated))
	for _, n := range emulated {
		emStrs = append(emStrs, strconv.FormatUint(uint64(n), 10))
	}

	selfExe, err := os.Executable()
	if err != nil {
		syscall.Close(parentSock)
		syscall.Close(childSock)
		return -1, fmt.Errorf("os.Executable: %w", err)
	}

	// Strip our own bootstrap vars from the env we pass through, so the
	// target doesn't accidentally re-enter bootstrap mode if it happens
	// to be mini-sentry itself.
	env := make([]string, 0, len(os.Environ())+2)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, bootstrapEnvVar+"=") || strings.HasPrefix(e, emulatedEnvVar+"=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env,
		bootstrapEnvVar+"=1",
		emulatedEnvVar+"="+strings.Join(emStrs, ","),
	)

	// argv[0] is cosmetic; argv[1:] is what the bootstrap will exec.
	bootstrapArgv := append([]string{"mini-sentry-bootstrap", path}, args...)

	child, err := syscall.ForkExec(selfExe, bootstrapArgv, &syscall.ProcAttr{
		Files: []uintptr{0, 1, 2, uintptr(childSock)},
		Env:   env,
	})
	syscall.Close(childSock)
	if err != nil {
		syscall.Close(parentSock)
		return -1, fmt.Errorf("fork bootstrap: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  [seccomp] bootstrap pid=%d, awaiting listener fd...\n", child)

	// Receive the listener fd from the bootstrap before it execs.
	buf := make([]byte, 8)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := syscall.Recvmsg(parentSock, buf, oob, 0)
	syscall.Close(parentSock)
	if err != nil {
		return -1, fmt.Errorf("recvmsg listener fd: %w", err)
	}
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(scms) == 0 {
		return -1, fmt.Errorf("parse cmsg: %v", err)
	}
	fds, err := syscall.ParseUnixRights(&scms[0])
	if err != nil || len(fds) == 0 {
		return -1, errors.New("no listener fd in cmsg")
	}
	listenerFD := fds[0]

	fmt.Fprintf(os.Stderr, "  [seccomp] listener fd=%d, entering notification loop\n\n", listenerFD)

	// Non-blocking so we can interleave Wait4(WNOHANG) with notification drains.
	if err := unix.SetNonblock(listenerFD, true); err != nil {
		syscall.Close(listenerFD)
		return -1, fmt.Errorf("set nonblock: %w", err)
	}

	return p.notifLoop(child, listenerFD)
}

// notifLoop drains USER_NOTIF events from the listener and watches for
// child exit. We poll with a short timeout so we pick up child exit even
// when no more notifications are queued (which is the common case after
// exit_group, since that syscall is ALLOW and never trapped).
func (p *SeccompPlatform) notifLoop(child, listenerFD int) (int, error) {
	pollFds := []unix.PollFd{{Fd: int32(listenerFD), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(pollFds, 10)
		if err != nil && err != syscall.EINTR {
			syscall.Close(listenerFD)
			return -1, fmt.Errorf("poll: %w", err)
		}

		// Drain everything currently ready.
		for {
			var notif seccompNotif
			_, _, e := syscall.Syscall(syscall.SYS_IOCTL,
				uintptr(listenerFD),
				uintptr(unix.SECCOMP_IOCTL_NOTIF_RECV),
				uintptr(unsafe.Pointer(&notif)))
			// NOTIF_RECV on a non-blocking listener returns ENOENT when the
			// notification queue is empty. EAGAIN is documented for newer
			// kernels; accept both. EINTR means we got signalled — retry next
			// poll cycle. Anything else means the listener is dead.
			if e == syscall.EAGAIN || e == syscall.ENOENT || e == syscall.EINTR {
				break
			}
			if e != 0 {
				goto drained
			}

			sc := SyscallArgs{
				Number: uint64(uint32(notif.Data.Nr)),
				Args:   notif.Data.Args,
			}
			ret, _ := p.sentry.HandleSyscall(int(notif.PID), sc)

			resp := seccompNotifResp{ID: notif.ID}
			signed := int64(ret)
			// Negative errnos live in the small negative range; map them to
			// resp.Error. Everything else (counts, fds, addresses) goes in val.
			if signed < 0 && signed >= -4095 {
				resp.Error = int32(signed)
			} else {
				resp.Val = signed
			}

			_, _, e = syscall.Syscall(syscall.SYS_IOCTL,
				uintptr(listenerFD),
				uintptr(unix.SECCOMP_IOCTL_NOTIF_SEND),
				uintptr(unsafe.Pointer(&resp)))
			// ENOENT here = target died before we could reply. Benign.
			if e != 0 && e != syscall.ENOENT {
				fmt.Fprintf(os.Stderr, "  [seccomp] NOTIF_SEND error: %v\n", e)
			}
		}

	drained:
		var ws syscall.WaitStatus
		wpid, werr := syscall.Wait4(child, &ws, syscall.WNOHANG, nil)
		if werr != nil {
			if werr == syscall.EINTR {
				continue
			}
			syscall.Close(listenerFD)
			return -1, fmt.Errorf("wait4: %w", werr)
		}
		if wpid == child {
			syscall.Close(listenerFD)
			if ws.Exited() {
				return ws.ExitStatus(), nil
			}
			if ws.Signaled() {
				return 128 + int(ws.Signal()), nil
			}
			return -1, fmt.Errorf("unexpected wait status: %v", ws)
		}
	}
}

// RunSeccompBootstrap is invoked from main() at the very top. If we were
// launched as a bootstrap (MINI_SENTRY_BOOTSTRAP=1 in env), this installs
// the seccomp filter, hands the listener fd to the parent, and execs the
// real target. It never returns on success. If we're NOT a bootstrap, it
// returns immediately and main continues normally.
func RunSeccompBootstrap() {
	if os.Getenv(bootstrapEnvVar) == "" {
		return
	}

	runtime.LockOSThread()

	emList := os.Getenv(emulatedEnvVar)
	var emulated []uint32
	for _, s := range strings.Split(emList, ",") {
		if s == "" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bootstrap: bad syscall nr %q: %v\n", s, err)
			os.Exit(1)
		}
		emulated = append(emulated, uint32(n))
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "bootstrap: missing target program")
		os.Exit(1)
	}
	target := os.Args[1]
	argv := os.Args[1:]
	envv := os.Environ()

	// Build exec arguments now — every allocation here is pre-filter
	// and therefore free of USER_NOTIF concerns.
	argv0p, err := syscall.BytePtrFromString(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap: bad target: %v\n", err)
		os.Exit(1)
	}
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap: bad argv: %v\n", err)
		os.Exit(1)
	}
	envvp, err := syscall.SlicePtrFromStrings(envv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap: bad envv: %v\n", err)
		os.Exit(1)
	}

	// Pre-build the sendmsg scatter-gather / cmsg with a placeholder fd.
	// We'll patch the real listener fd in after seccomp() returns it.
	var msgBuf [1]byte
	iov := syscall.Iovec{Base: &msgBuf[0]}
	iov.SetLen(1)

	oob := syscall.UnixRights(-1)
	fdPtr := (*int32)(unsafe.Pointer(&oob[syscall.CmsgLen(0)]))

	var msghdr syscall.Msghdr
	msghdr.Iov = &iov
	msghdr.Iovlen = 1
	msghdr.Control = &oob[0]
	msghdr.SetControllen(len(oob))

	// PR_SET_NO_NEW_PRIVS is required for non-root seccomp filters.
	_, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0)
	if e != 0 {
		fmt.Fprintf(os.Stderr, "bootstrap: prctl(NO_NEW_PRIVS): %v\n", e)
		os.Exit(1)
	}

	prog := buildSeccompFilter(emulated)
	fprog := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}

	// Install the filter. From this line onward we must avoid any syscall
	// in the emulated set: the Sentry isn't listening yet, and a USER_NOTIF
	// would deadlock us.
	r1, _, e := syscall.Syscall(unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		uintptr(unsafe.Pointer(&fprog)))
	if e != 0 {
		fmt.Fprintf(os.Stderr, "bootstrap: seccomp(): %v\n", e)
		os.Exit(1)
	}
	*fdPtr = int32(r1)

	// Raw sendmsg to avoid any Go wrapper that might allocate.
	_, _, e = syscall.Syscall(syscall.SYS_SENDMSG, 3, uintptr(unsafe.Pointer(&msghdr)), 0)
	if e != 0 {
		// write/stderr is emulated — can't fmt.Printf. Exit with a
		// distinctive code so the parent can tell what happened.
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 97, 0, 0)
	}

	// execve. Filter survives exec, so the target process inherits it.
	syscall.RawSyscall(syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0p)),
		uintptr(unsafe.Pointer(&argvp[0])),
		uintptr(unsafe.Pointer(&envvp[0])))

	// Only reached on execve failure.
	syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 98, 0, 0)
}

// buildSeccompFilter emits:
//
//   A = seccomp_data.nr
//   for each emulated N: if A == N: return USER_NOTIF
//   return ALLOW
//
// Linear scan, which is fine at O(emulated) ≈ 22 instructions. The BPF
// program limit is 4096 instructions, so we have plenty of headroom.
func buildSeccompFilter(emulated []uint32) []sockFilter {
	prog := make([]sockFilter, 0, 2+2*len(emulated))
	// offsetof(seccomp_data.nr) == 0.
	prog = append(prog, sockFilter{Code: bpfLD_W_ABS, K: 0})
	for _, nr := range emulated {
		// If A != nr, skip the next instruction.
		prog = append(prog, sockFilter{Code: bpfJMP_JEQ_K, Jt: 0, Jf: 1, K: nr})
		prog = append(prog, sockFilter{Code: bpfRET_K, K: unix.SECCOMP_RET_USER_NOTIF})
	}
	prog = append(prog, sockFilter{Code: bpfRET_K, K: unix.SECCOMP_RET_ALLOW})
	return prog
}
