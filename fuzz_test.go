//go:build linux

package main

// fuzz_test.go — Go fuzz targets for path resolution, the wire protocol,
// and HandleSyscall. The only contract is "never panic". Application
// errors (ENOENT/EACCES, gob decode failures, etc.) are expected and
// not fuzz failures.

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// newFuzzRoot builds a tiny host directory tree the resolver can chew on:
//
//	<root>/good.txt
//	<root>/sub/ok.txt
//	<root>/link_out -> /etc/hostname     (escaping symlink)
//	<root>/link_in  -> sub/ok.txt        (in-bounds symlink)
//
// Returned path is the absolute root.
func newFuzzRoot(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "good.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "ok.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink("/etc/hostname", filepath.Join(root, "link_out"))
	_ = os.Symlink("sub/ok.txt", filepath.Join(root, "link_in"))
	return root
}

// FuzzResolvePath pushes arbitrary guest paths through the Gofer's
// resolveHost. Invariant: if it claims success, the returned real path
// must live inside the realized root — i.e. cannot escape via ".." or
// a symlink. If it claims failure, we only require "did not panic".
func FuzzResolvePath(f *testing.F) {
	seeds := []string{
		"/",
		"good.txt",
		"/good.txt",
		"sub/ok.txt",
		"/sub/ok.txt",
		"../../../etc/passwd",
		"/../../../etc/passwd",
		"/link_out",    // symlink escape
		"/link_in",     // in-bounds symlink
		"//good.txt",   // duplicate slashes
		"/sub/../good.txt",
		"/nonexistent",
		"",
		"\x00",
		"/café/ünicode",
		string(make([]byte, 4096)), // very long path
	}
	for _, s := range seeds {
		f.Add(s)
	}

	root := newFuzzRoot(f)
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		f.Fatal(err)
	}

	g := newGoferServer(root)

	f.Fuzz(func(t *testing.T, path string) {
		// Skip paths with NULs — Linux rejects them at the syscall
		// boundary before the gofer ever sees them, so enforcing the
		// invariant here would be testing filesystem libc, not us.
		if strings.ContainsRune(path, 0) {
			return
		}
		real, ok := g.resolveHost(path)
		if !ok {
			return // negative result — acceptable, no invariant to enforce
		}
		// Invariant: resolved path is a child of the resolved root.
		rel, err := filepath.Rel(resolvedRoot, real)
		if err != nil {
			t.Fatalf("resolve %q: unable to relate %q to root %q: %v",
				path, real, resolvedRoot, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("resolve %q: ESCAPED root (real=%q, rel=%q)",
				path, real, rel)
		}
	})
}

// FuzzGoferProtocol throws arbitrary byte streams at the gofer's wire
// format. The decoder must never panic — malformed frames come back as
// errors and the server walks off the connection cleanly.
func FuzzGoferProtocol(f *testing.F) {
	// Build a few valid frames so the corpus includes well-formed starts.
	goodFrames := [][]byte{
		encodeFrame(&GoferRequest{Op: OpOpen, Path: "/etc/hostname"}),
		encodeFrame(&GoferRequest{Op: OpFileCount}),
		encodeFrame(&GoferRequest{Op: OpListDir, Path: "/"}),
	}
	for _, b := range goodFrames {
		f.Add(b)
	}
	// Obviously-bad inputs.
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})     // huge length header
	f.Add([]byte{0, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7})
	f.Add(append([]byte{0, 0, 0, 100}, bytes.Repeat([]byte{0xaa}, 100)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input (%d bytes): %v", len(data), r)
			}
		}()

		// 1. Framed decoder must error, not panic.
		var req GoferRequest
		_ = readFramed(bytes.NewReader(data), &req)

		// 2. handle() must accept any GoferRequest without panicking.
		//    Even if the request has huge offsets / unknown ops / nil paths.
		g := newGoferServer("")
		seedDefaults(g.addFile)
		_ = g.handle(&req)
	})
}

// encodeFrame produces a valid 4-byte-length + gob frame for seeding.
func encodeFrame(req *GoferRequest) []byte {
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(req)
	out := make([]byte, 4+buf.Len())
	binary.BigEndian.PutUint32(out[:4], uint32(buf.Len()))
	copy(out[4:], buf.Bytes())
	return out
}

// FuzzSyscallArgs feeds random syscall numbers and arguments to
// HandleSyscall. The Sentry must never panic: every call returns either
// a valid number, a negative errno, or sets ActionPassthrough — but we
// skip passthrough so we don't invoke the real kernel against the
// fuzz test binary.
func FuzzSyscallArgs(f *testing.F) {
	// Seed with the syscall numbers we know the Sentry emulates.
	seeds := []uint64{0, 1, 2, 3, 4, 5, 20, 60, 79, 89, 99, 101, 158, 231, 267, 450, ^uint64(0)}
	for _, nr := range seeds {
		f.Add(nr, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
	}
	// A couple of "bad pointer" args.
	f.Add(uint64(20), uint64(1), uint64(0xdeadbeef), uint64(1), uint64(0), uint64(0), uint64(0))

	sentry := newFuzzSentry()
	self := os.Getpid()

	f.Fuzz(func(t *testing.T, nr, a0, a1, a2, a3, a4, a5 uint64) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: nr=%d args=[%x %x %x %x %x %x]: %v",
					nr, a0, a1, a2, a3, a4, a5, r)
			}
		}()
		sc := SyscallArgs{
			Number: nr,
			Args:   [6]uint64{a0, a1, a2, a3, a4, a5},
		}
		// Look up first so we can skip passthrough — executing arbitrary
		// passthroughs (clone, exit_group, mmap, …) would wreck the
		// fuzz process.
		entry, ok := sentry.syscalls[nr]
		if ok && entry.passthrough {
			return
		}
		// Skip emulated handlers that still touch the host on behalf of
		// the tracee. sysKill/sysTkill/sysTgkill rewrite self-targeted
		// calls (pid in {1, 0, -1}) into a real syscall.Kill on the
		// tracee's host PID — which, under this fuzz harness, *is* the
		// fuzz process. A random kill(0, SIGQUIT) would terminate the
		// fuzz runner before it could report.
		switch nr {
		case unix.SYS_KILL, unix.SYS_TKILL, unix.SYS_TGKILL:
			return
		}
		_, _ = sentry.HandleSyscall(self, self, sc)
	})
}

// newFuzzSentry builds a Sentry backed by an in-memory VFS. We avoid
// the out-of-process gofer so each fuzz iteration stays in-process
// and deterministic.
func newFuzzSentry() *Sentry {
	mem := NewInMemoryVFS()
	seedDefaults(mem.AddFile)
	return NewSentry(mem)
}
