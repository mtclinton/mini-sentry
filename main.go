//go:build linux

// mini-sentry: A minimal userspace kernel in Go, inspired by gVisor.
//
// Two pluggable platforms intercept syscalls from the sandboxed process:
//
//   - ptrace  (default): PTRACE_SYSEMU stops the child on every syscall.
//                         Simple, correct, slow — every syscall is a
//                         round-trip to the parent.
//
//   - seccomp:           A seccomp-BPF filter routes emulated syscalls
//                         to the Sentry via SECCOMP_RET_USER_NOTIF and
//                         lets everything else (getpid, mmap, futex, etc.)
//                         hit the real kernel directly.
//
// The filesystem has two backends too:
//
//   - gofer   (default): a separate child process serves files over a
//                         Unix socket. This is the gVisor architecture —
//                         a compromised Sentry still can't touch files
//                         the Gofer won't serve.
//
//   - in-mem:            the VFS lives inside the Sentry process as a
//                         map (--gofer=false). Simpler for debugging.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func main() {
	// Bootstrap branches — each returns immediately if not selected by env.
	// Check these before flag.Parse: they take os.Args / the environment
	// as their sole input and then exec into the real target.
	RunGoferBootstrap()
	RunSeccompBootstrap()

	var (
		platformName = flag.String("platform", "ptrace", "interception platform: ptrace or seccomp")
		benchmark    = flag.Bool("benchmark", false, "run a getpid() hot loop in the guest for platform timing")
		useGofer     = flag.Bool("gofer", true, "use a separate Gofer process for the VFS (set false for in-memory)")
		goferRoot    = flag.String("gofer-root", "", "optional host directory the Gofer serves read-only")
		goferDeny    = flag.String("gofer-deny", "", "comma-separated guest-path prefixes that always return EACCES")
		netAllow     = flag.String("net-allow", "", "comma-separated CIDR:port outbound network allowlist (empty = allow all)")
		netDeny      = flag.String("net-deny", "", "comma-separated CIDR:port outbound network denylist (port 0 = all ports; deny beats allow)")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "mini-sentry: a minimal userspace kernel inspired by gVisor\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <program> [args...]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s ./cmd/guest/guest\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --platform=seccomp ./cmd/guest/guest\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --gofer=false ./cmd/guest/guest\n", os.Args[0])
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	program := flag.Arg(0)
	programArgs := flag.Args()[1:]
	if *benchmark {
		programArgs = append(programArgs, "--benchmark")
	}

	// VFS — our Gofer. Either a real out-of-process gofer, or an
	// in-memory stand-in that keeps the same interface.
	var (
		vfs          VFS
		goferCleanup func()
		vfsLabel     string
	)
	if *useGofer {
		client, cleanup, err := startGofer(*goferRoot, *goferDeny)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mini-sentry: failed to start gofer: %v\n", err)
			os.Exit(1)
		}
		vfs = client
		goferCleanup = cleanup
		vfsLabel = "gofer process (RPC)"
	} else {
		mem := NewInMemoryVFS()
		mem.SetDenies(parseDenyList(*goferDeny))
		vfs = mem
		vfsLabel = "in-memory map"
	}
	seedDefaults(vfs.AddFile)

	policy, err := NewNetPolicy(*netAllow, *netDeny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mini-sentry: %v\n", err)
		os.Exit(1)
	}

	sentry := NewSentryWithPolicy(vfs, policy)

	// For benchmark mode we want getpid() to actually get the "seccomp is
	// faster" treatment — i.e., ALLOW in the filter so it never traps.
	// The ptrace platform still stops on every getpid, since ptrace can't
	// selectively ignore.
	var allowList []uint64
	if *benchmark {
		allowList = append(allowList, unix.SYS_GETPID)
	}

	var platform Platform
	var platformLabel string
	switch *platformName {
	case "ptrace":
		platform = NewPtracePlatform(sentry)
		platformLabel = "ptrace (PTRACE_SYSEMU)"
	case "seccomp":
		platform = NewSeccompPlatform(sentry, allowList)
		platformLabel = "seccomp (SECCOMP_RET_USER_NOTIF)"
	default:
		fmt.Fprintf(os.Stderr, "unknown platform: %q (want ptrace or seccomp)\n", *platformName)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(os.Stderr, "│  mini-sentry: userspace kernel starting              │\n")
	fmt.Fprintf(os.Stderr, "│  Platform: %s│\n", padRight(platformLabel, 41))
	fmt.Fprintf(os.Stderr, "│  VFS:      %s│\n", padRight(vfsLabel, 41))
	fmt.Fprintf(os.Stderr, "│  Sandboxing: %s│\n", padRight(strings.Join(flag.Args(), " "), 38))
	fmt.Fprintf(os.Stderr, "├─────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(os.Stderr, "│  Architecture (maps to gVisor):                      │\n")
	fmt.Fprintf(os.Stderr, "│    Platform  → %s│\n", padRight(platformLabel, 37))
	fmt.Fprintf(os.Stderr, "│    Sentry    → Go handlers (emulate kernel)          │\n")
	gvLine := fmt.Sprintf("%s (%d files)", vfsLabel, vfs.FileCount())
	fmt.Fprintf(os.Stderr, "│    Gofer/VFS → %s│\n", padRight(gvLine, 37))
	fmt.Fprintf(os.Stderr, "└─────────────────────────────────────────────────────┘\n\n")

	exitCode, err := platform.Run(program, programArgs...)

	if goferCleanup != nil {
		goferCleanup()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nmini-sentry: error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(os.Stderr, "│  Sandbox exited (code %d)                             │\n", exitCode)
	fmt.Fprintf(os.Stderr, "├─────────────────────────────────────────────────────┤\n")
	sentry.PrintStats(os.Stderr)
	fmt.Fprintf(os.Stderr, "└─────────────────────────────────────────────────────┘\n")

	os.Exit(exitCode)
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}

