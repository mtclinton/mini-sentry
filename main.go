//go:build linux

// sentry-exec: run any Linux binary inside a mini-sentry sandbox.
//
// The tool wraps the Sentry's two platforms, its VFS (in-memory or
// out-of-process Gofer), and its network policy behind a single CLI
// that resembles tools like `firejail`, `bubblewrap`, or `runsc do`.
//
// Platforms
//
//   - ptrace  (default): PTRACE_SYSEMU stops the guest on every syscall.
//                         Simple, correct, slow — every syscall is a
//                         round-trip to the Sentry.
//
//   - seccomp:           A seccomp-BPF filter routes emulated syscalls
//                         to the Sentry via SECCOMP_RET_USER_NOTIF and
//                         lets everything else (getpid, mmap, futex, etc.)
//                         hit the real kernel directly.
//
// Filesystem
//
//   - gofer   (default): a separate child process serves files over a
//                         Unix socket. This is the gVisor architecture —
//                         a compromised Sentry still can't touch files
//                         the Gofer won't serve.
//
//   - in-mem:            the VFS lives inside the Sentry process as a
//                         map (--gofer=false). Simpler for debugging.
//
// --mount entries expose host subtrees to the guest (longest guest
// prefix wins). --gofer-root is a back-compat shorthand for mounting
// a single host tree at /.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const progName = "sentry-exec"

func main() {
	// Bootstrap branches — each returns immediately if not selected by env.
	// Check these before flag.Parse: they take os.Args / the environment
	// as their sole input and then exec into the real target.
	RunGoferBootstrap()
	RunSeccompBootstrap()

	opts := parseFlags()

	// VFS — our Gofer. Either a real out-of-process gofer, or an
	// in-memory stand-in that keeps the same interface.
	var (
		vfs          VFS
		goferCleanup func()
		vfsLabel     string
	)
	if opts.useGofer {
		client, cleanup, err := startGofer(opts.goferRoot, strings.Join(opts.goferDeny, ","), opts.mounts)
		if err != nil {
			fatalf("failed to start gofer: %v", err)
		}
		vfs = client
		goferCleanup = cleanup
		vfsLabel = "gofer process (RPC)"
	} else {
		mem := NewInMemoryVFS()
		mem.SetDenies(opts.goferDeny)
		vfs = mem
		vfsLabel = "in-memory map"
	}
	seedDefaults(vfs.AddFile)

	policy, err := NewNetPolicy(
		strings.Join(opts.netAllow, ","),
		strings.Join(opts.netDeny, ","),
	)
	if err != nil {
		fatalf("%v", err)
	}

	sentry := NewSentryWithPolicy(vfs, policy)

	// For benchmark mode we want getpid() to actually get the "seccomp is
	// faster" treatment — i.e., ALLOW in the filter so it never traps.
	var allowList []uint64
	if opts.benchmark {
		allowList = append(allowList, unix.SYS_GETPID)
	}

	var platform Platform
	var platformLabel string
	switch opts.platform {
	case "ptrace":
		platform = NewPtracePlatform(sentry)
		platformLabel = "ptrace (PTRACE_SYSEMU)"
	case "seccomp":
		platform = NewSeccompPlatform(sentry, allowList)
		platformLabel = "seccomp (SECCOMP_RET_USER_NOTIF)"
	default:
		fatalf("unknown platform: %q (want ptrace or seccomp)", opts.platform)
	}

	spec := NewExecSpecDefaults()
	spec.Program = opts.program
	spec.Args = opts.programArgs
	spec.ExtraEnv = opts.env
	spec.Cwd = opts.cwd
	spec.UID = opts.uid
	spec.GID = opts.gid
	spec.Rlimits = opts.rlimits
	if opts.benchmark {
		spec.Args = append(spec.Args, "--benchmark")
	}

	printStartBanner(os.Stderr, platformLabel, vfsLabel, vfs.FileCount(), spec)

	exitCode, runErr := platform.Run(spec)

	if goferCleanup != nil {
		goferCleanup()
	}

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "\n%s: error: %v\n", progName, runErr)
		os.Exit(1)
	}

	printExitBanner(os.Stderr, exitCode, sentry)
	os.Exit(exitCode)
}

// options is the parsed CLI state. Kept in a struct so the individual
// Flag parsing, merging, and validation steps stay testable.
type options struct {
	platform string

	useGofer  bool
	goferRoot string
	goferDeny []string

	mounts []Mount

	netAllow []string
	netDeny  []string

	env     []string
	cwd     string
	uid     int
	gid     int
	rlimits []RlimitSpec

	benchmark   bool
	program     string
	programArgs []string
}

// parseFlags processes os.Args and returns a validated options struct.
// Exits on bad input.
func parseFlags() *options {
	fs := flag.NewFlagSet(progName, flag.ExitOnError)

	var (
		platformName = fs.String("platform", "ptrace", "interception platform: ptrace or seccomp")
		useGofer     = fs.Bool("gofer", true, "run the VFS as a separate Gofer process (false → in-memory)")
		goferRoot    = fs.String("gofer-root", "", "optional host directory served read-only at / (legacy, prefer --mount)")
		benchmark    = fs.Bool("benchmark", false, "run a getpid() hot loop in the guest for platform timing")
		cwd          = fs.String("cwd", "", "working directory for the guest (default: inherit)")
		userFlag     = fs.String("user", "", "guest uid (name or number); default: inherit")
		groupFlag    = fs.String("group", "", "guest gid (name or number); default: inherit")

		mountFlag    = &stringSliceFlag{name: "mount"}
		goferDenyF   = &stringSliceFlag{name: "gofer-deny"}
		netAllowF    = &stringSliceFlag{name: "net-allow"}
		netDenyF     = &stringSliceFlag{name: "net-deny"}
		envF         = &stringSliceFlag{name: "env"}
		rlimitF      = &stringSliceFlag{name: "rlimit"}
	)
	fs.Var(mountFlag, "mount",
		"bind-mount a host path into the guest as HOST:GUEST[:ro|:rw] (repeatable)")
	fs.Var(goferDenyF, "gofer-deny",
		"guest-path prefix that always returns EACCES (repeatable or comma-separated)")
	fs.Var(netAllowF, "net-allow",
		"outbound CIDR:port allowlist entry (repeatable; empty = allow all)")
	fs.Var(netDenyF, "net-deny",
		"outbound CIDR:port denylist entry (repeatable; port 0 = all ports; deny beats allow)")
	fs.Var(envF, "env",
		"extra environment variable KEY=VAL for the guest (repeatable, last wins)")
	fs.Var(rlimitF, "rlimit",
		"guest rlimit override NAME=SOFT[:HARD] (repeatable; names: "+rlimitNameList()+")")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: run any Linux binary inside a mini-sentry sandbox\n\n", progName)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <program> [args...]\n\n", progName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s ./cmd/guest/guest\n", progName)
		fmt.Fprintf(os.Stderr, "  %s --platform=seccomp ./samples/echo hello\n", progName)
		fmt.Fprintf(os.Stderr, "  %s --mount /lib:/lib:ro --mount /tmp:/tmp /usr/bin/cat /tmp/x\n", progName)
		fmt.Fprintf(os.Stderr, "  %s --rlimit nofile=64 --rlimit cpu=5 ./samples/stress\n", progName)
		fmt.Fprintf(os.Stderr, "  %s --user nobody --group nogroup --cwd / ./samples/pwd\n", progName)
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	mounts, err := parseMounts(mountFlag.Values())
	if err != nil {
		fatalf("parse --mount: %v", err)
	}

	var rlimits []RlimitSpec
	for _, r := range rlimitF.Values() {
		spec, err := parseRlimit(r)
		if err != nil {
			fatalf("parse --rlimit: %v", err)
		}
		rlimits = append(rlimits, spec)
	}

	uid := -1
	if *userFlag != "" {
		uid, err = parseUserSpec(*userFlag)
		if err != nil {
			fatalf("parse --user: %v", err)
		}
	}
	gid := -1
	if *groupFlag != "" {
		gid, err = parseGroupSpec(*groupFlag)
		if err != nil {
			fatalf("parse --group: %v", err)
		}
	}

	opts := &options{
		platform:    *platformName,
		useGofer:    *useGofer,
		goferRoot:   *goferRoot,
		goferDeny:   parseDenyList(strings.Join(goferDenyF.Values(), ",")),
		mounts:      mounts,
		netAllow:    netAllowF.Values(),
		netDeny:     netDenyF.Values(),
		env:         envF.Values(),
		cwd:         *cwd,
		uid:         uid,
		gid:         gid,
		rlimits:     rlimits,
		benchmark:   *benchmark,
		program:     fs.Arg(0),
		programArgs: fs.Args()[1:],
	}
	return opts
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s: "+format+"\n", append([]interface{}{progName}, args...)...)
	os.Exit(1)
}

func printStartBanner(w *os.File, platformLabel, vfsLabel string, fileCount int, spec *ExecSpec) {
	fmt.Fprintf(w, "\n┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(w, "│  %s: userspace kernel starting              │\n", padRight(progName, 10))
	fmt.Fprintf(w, "│  Platform: %s│\n", padRight(platformLabel, 41))
	fmt.Fprintf(w, "│  VFS:      %s│\n", padRight(vfsLabel, 41))
	cmd := spec.Program + " " + strings.Join(spec.Args, " ")
	fmt.Fprintf(w, "│  Sandboxing: %s│\n", padRight(strings.TrimSpace(cmd), 38))
	fmt.Fprintf(w, "├─────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(w, "│  Architecture (maps to gVisor):                      │\n")
	fmt.Fprintf(w, "│    Platform  → %s│\n", padRight(platformLabel, 37))
	fmt.Fprintf(w, "│    Sentry    → Go handlers (emulate kernel)          │\n")
	gvLine := fmt.Sprintf("%s (%d files)", vfsLabel, fileCount)
	fmt.Fprintf(w, "│    Gofer/VFS → %s│\n", padRight(gvLine, 37))
	fmt.Fprintf(w, "└─────────────────────────────────────────────────────┘\n\n")
}

func printExitBanner(w *os.File, exitCode int, sentry *Sentry) {
	fmt.Fprintf(w, "\n┌─────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(w, "│  Sandbox exited (code %d)                             │\n", exitCode)
	fmt.Fprintf(w, "├─────────────────────────────────────────────────────┤\n")
	sentry.PrintStats(w)
	fmt.Fprintf(w, "└─────────────────────────────────────────────────────┘\n")
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}
