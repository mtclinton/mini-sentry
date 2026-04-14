//go:build linux

package main

// execspec.go — ExecSpec carries all the knobs that shape how the guest
// process is spawned. It's the shared input for the ptrace and seccomp
// platforms, so main.go builds one spec and hands it to whichever
// platform the user picked.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// ExecSpec describes the guest process and the environment it runs in.
//
// A zero-value ExecSpec (other than Program) means "inherit everything
// from the Sentry" — same env, same cwd, same uid/gid, no rlimit
// overrides. CLI flags populate the non-default fields.
type ExecSpec struct {
	Program string   // absolute path, after LookPath
	Args    []string // argv[1:] — argv[0] is always Program

	// Env is the complete environment for the guest. If nil the guest
	// inherits the Sentry's env; if non-nil it replaces it entirely.
	// Use ExtraEnv for the common "inherit plus a few overrides" case.
	Env      []string
	ExtraEnv []string // appended to the inherited env

	// Cwd is the working directory for the guest. Empty means "inherit".
	Cwd string

	// UID/GID are applied via SysProcAttr.Credential in the child before
	// exec. A value of -1 means "inherit from the Sentry".
	UID int
	GID int

	// Rlimits are applied to the guest after fork (via prlimit64 on the
	// child PID) so setting RLIMIT_NOFILE=64 for the guest doesn't
	// clamp the Sentry's own fd table. See applyRlimits.
	Rlimits []RlimitSpec
}

// RlimitSpec is one rlimit override, parsed from --rlimit NAME=SOFT[:HARD].
// If Hard is 0, applyRlimits uses Soft for both.
type RlimitSpec struct {
	Resource int
	Name     string
	Soft     uint64
	Hard     uint64
}

// NewExecSpecDefaults returns a spec with "inherit everything" defaults.
func NewExecSpecDefaults() *ExecSpec {
	return &ExecSpec{
		UID: -1,
		GID: -1,
	}
}

// BuildEnv returns the env slice to hand to ForkExec. If Env is non-nil
// it wins outright; otherwise we take the Sentry's env and append
// ExtraEnv (with KEY= overrides de-duplicated, last wins).
func (s *ExecSpec) BuildEnv(base []string) []string {
	if s.Env != nil {
		return append([]string(nil), s.Env...)
	}
	if len(s.ExtraEnv) == 0 {
		return append([]string(nil), base...)
	}
	// Merge: keep base, then apply ExtraEnv overrides in order.
	out := append([]string(nil), base...)
	for _, e := range s.ExtraEnv {
		k, _, _ := strings.Cut(e, "=")
		// Drop any existing entry for this key so the override wins.
		filtered := out[:0]
		for _, existing := range out {
			ek, _, _ := strings.Cut(existing, "=")
			if ek != k {
				filtered = append(filtered, existing)
			}
		}
		out = append(filtered, e)
	}
	return out
}

// applyRlimits calls prlimit64 on the given PID for every rlimit in the
// spec. Called right after ForkExec, so the guest picks up the new
// limits before doing much of anything. RLIMIT_STACK is a special case
// (consumed by the kernel during exec) and will not always take effect
// if applied after ForkExec returns — document this, don't lie about it.
func (s *ExecSpec) applyRlimits(pid int) error {
	for _, r := range s.Rlimits {
		hard := r.Hard
		if hard == 0 {
			hard = r.Soft
		}
		limit := unix.Rlimit{Cur: r.Soft, Max: hard}
		if err := unix.Prlimit(pid, r.Resource, &limit, nil); err != nil {
			return fmt.Errorf("prlimit %s=%d:%d: %w", r.Name, r.Soft, hard, err)
		}
	}
	return nil
}

// parseRlimit parses "name=soft[:hard]" into an RlimitSpec.
func parseRlimit(s string) (RlimitSpec, error) {
	eq := strings.IndexByte(s, '=')
	if eq < 0 {
		return RlimitSpec{}, fmt.Errorf("expected NAME=VALUE, got %q", s)
	}
	name := strings.ToLower(strings.TrimSpace(s[:eq]))
	val := strings.TrimSpace(s[eq+1:])

	resource, ok := rlimitNames[name]
	if !ok {
		return RlimitSpec{}, fmt.Errorf("unknown rlimit %q (want: %s)", name, rlimitNameList())
	}

	softStr, hardStr, hasHard := strings.Cut(val, ":")
	soft, err := strconv.ParseUint(strings.TrimSpace(softStr), 10, 64)
	if err != nil {
		return RlimitSpec{}, fmt.Errorf("soft limit for %s: %w", name, err)
	}
	spec := RlimitSpec{Resource: resource, Name: name, Soft: soft}
	if hasHard {
		hard, err := strconv.ParseUint(strings.TrimSpace(hardStr), 10, 64)
		if err != nil {
			return RlimitSpec{}, fmt.Errorf("hard limit for %s: %w", name, err)
		}
		spec.Hard = hard
	}
	return spec, nil
}

// rlimitNames is the mapping from CLI-facing short names to syscall
// constants. Kept intentionally narrow — we can add more as users ask.
var rlimitNames = map[string]int{
	"as":         unix.RLIMIT_AS,
	"core":       unix.RLIMIT_CORE,
	"cpu":        unix.RLIMIT_CPU,
	"data":       unix.RLIMIT_DATA,
	"fsize":      unix.RLIMIT_FSIZE,
	"nofile":     unix.RLIMIT_NOFILE,
	"stack":      unix.RLIMIT_STACK,
	"memlock":    unix.RLIMIT_MEMLOCK,
	"nproc":      unix.RLIMIT_NPROC,
	"rss":        unix.RLIMIT_RSS,
	"msgqueue":   unix.RLIMIT_MSGQUEUE,
	"nice":       unix.RLIMIT_NICE,
	"rtprio":     unix.RLIMIT_RTPRIO,
	"sigpending": unix.RLIMIT_SIGPENDING,
}

func rlimitNameList() string {
	names := make([]string, 0, len(rlimitNames))
	for k := range rlimitNames {
		names = append(names, k)
	}
	// Deterministic order for error messages and docs.
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return strings.Join(names, ", ")
}

// parseUserSpec turns "alice" or "1000" into a numeric uid. Symbolic
// names resolve through the Sentry's /etc/passwd via os/user.
func parseUserSpec(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1, errors.New("empty user")
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return -1, err
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	return n, nil
}

// parseGroupSpec is the gid analog of parseUserSpec.
func parseGroupSpec(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1, errors.New("empty group")
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return -1, err
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, fmt.Errorf("parse gid %q: %w", g.Gid, err)
	}
	return n, nil
}

// stringSliceFlag is a flag.Value that accepts repeated --flag=value
// occurrences and collects them into a slice. Used for --mount,
// --rlimit, --env, --net-allow, --net-deny.
type stringSliceFlag struct {
	name   string // diagnostics only
	values []string
}

func (s *stringSliceFlag) String() string { return strings.Join(s.values, ",") }

func (s *stringSliceFlag) Set(v string) error {
	// Allow comma-separated batches too so --mount=a,b works like two
	// --mount flags. Users who actually need commas inside values can
	// pass them as separate --mount occurrences.
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		s.values = append(s.values, part)
	}
	return nil
}

// Values returns the accumulated slice. Nil-safe.
func (s *stringSliceFlag) Values() []string {
	if s == nil {
		return nil
	}
	return s.values
}

// mustLookPath is a thin wrapper around exec.LookPath that prints a
// useful error and exits. The guest program path has to resolve before
// we bother forking or spawning a Gofer.
func mustLookPath(prog string) string {
	if strings.ContainsRune(prog, '/') {
		// Absolute or relative path — let it stand; stat-check so we
		// fail fast with a sensible message instead of deep in ptrace.
		if _, err := os.Stat(prog); err != nil {
			fmt.Fprintf(os.Stderr, "sentry-exec: %v\n", err)
			os.Exit(1)
		}
		return prog
	}
	// Bare name — PATH lookup.
	path, err := lookPath(prog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentry-exec: %v\n", err)
		os.Exit(1)
	}
	return path
}

// Indirect so tests can stub.
var lookPath = exec.LookPath

// stripEnv returns a copy of env with every entry whose KEY matches
// one of the supplied names removed. Used by the seccomp platform to
// avoid re-entering bootstrap mode if the spec's env happened to carry
// MINI_SENTRY_* vars (e.g., from a previous sandbox invocation).
func stripEnv(env []string, names ...string) []string {
	if len(names) == 0 {
		return append([]string(nil), env...)
	}
	out := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		skip := false
		for _, n := range names {
			if k == n {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, e)
		}
	}
	return out
}

// applyCredToSysProcAttr sets SysProcAttr.Credential from the spec's
// UID/GID if either is non-default (-1). Both platforms call this so
// the child enters exec with the right credentials; we can't just
// setuid/setgid in parent since that would drop the Sentry's own
// privileges.
func applyCredToSysProcAttr(s *syscall.SysProcAttr, spec *ExecSpec) {
	if spec == nil || s == nil || (spec.UID < 0 && spec.GID < 0) {
		return
	}
	// Start from the Sentry's creds, then override whichever side was
	// specified. syscall.Credential has no "inherit" sentinel so we
	// fill both explicitly.
	uid := spec.UID
	gid := spec.GID
	if uid < 0 {
		uid = os.Getuid()
	}
	if gid < 0 {
		gid = os.Getgid()
	}
	s.Credential = &syscall.Credential{
		Uid:         uint32(uid),
		Gid:         uint32(gid),
		NoSetGroups: true, // don't fiddle with supplementary groups
	}
}

