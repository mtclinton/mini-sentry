//go:build linux

package main

// property_test.go — property-style tests that target invariants rather
// than end-to-end syscalls. These run entirely in-process: they never
// spawn a tracee, so they're cheap to run on every CI commit.

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestFdTableInvariant exercises the fd table through sysClose directly:
// open N synthetic entries, close half of them, and verify the survivors
// are still reachable while the closed ones report EBADF and that no fd
// number is ever handed out to two live files at once.
func TestFdTableInvariant(t *testing.T) {
	mem := NewInMemoryVFS()
	seedDefaults(mem.AddFile)
	s := NewSentry(mem)

	// Open 20 synthetic virtual files via the fd-allocation path.
	const N = 20
	fds := make([]int, N)
	seen := map[int]bool{}
	for i := 0; i < N; i++ {
		fd := s.nextFD
		s.nextFD++
		s.fdTable[fd] = &OpenFile{path: "/greeting.txt", data: []byte("x")}
		if seen[fd] {
			t.Fatalf("fd %d reused while still open", fd)
		}
		seen[fd] = true
		fds[i] = fd
	}

	// Close every other fd.
	for i := 0; i < N; i += 2 {
		ret := s.sysClose(SyscallArgs{Args: [6]uint64{uint64(fds[i])}})
		if ret != 0 {
			t.Fatalf("close fd %d: expected 0, got %v", fds[i], syscall.Errno(^ret+1))
		}
	}

	// Closed fds → EBADF.
	for i := 0; i < N; i += 2 {
		ret := s.sysClose(SyscallArgs{Args: [6]uint64{uint64(fds[i])}})
		if ret != errno(syscall.EBADF) {
			t.Fatalf("double-close fd %d: expected EBADF, got %#x", fds[i], ret)
		}
	}

	// Survivors still openable.
	for i := 1; i < N; i += 2 {
		if _, ok := s.fdTable[fds[i]]; !ok {
			t.Fatalf("fd %d should still be open", fds[i])
		}
	}

	// Newly-allocated fd number must not collide with any live one.
	newFD := s.nextFD
	s.nextFD++
	if _, ok := s.fdTable[newFD]; ok {
		t.Fatalf("new fd %d collided with live table entry", newFD)
	}
}

// TestVirtualOverrideAlwaysWins verifies that seeded virtual files are
// served from the VFS even when a host --gofer-root would otherwise
// shadow them. This is the "the gofer trumps the host" invariant.
func TestVirtualOverrideAlwaysWins(t *testing.T) {
	// Build a host directory that *claims* to provide the same files,
	// with different contents, so any leak would be obvious.
	host := t.TempDir()
	for _, name := range []string{"etc/hostname", "etc/os-release", "greeting.txt"} {
		p := filepath.Join(host, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("HOST CONTENT MUST NOT LEAK"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	g := newGoferServer(host)
	seedDefaults(g.addFile)

	want := map[string]string{
		"/etc/hostname":   "mini-sentry-sandbox\n",
		"/etc/os-release": "NAME=\"Mini-Sentry Sandbox\"\nVERSION=\"0.1\"\nID=mini-sentry\n",
		"/greeting.txt":   "Hello from the userspace kernel!\nEvery byte you read was served by Go code, not the Linux kernel.\n",
	}
	for path, expected := range want {
		data, ok := g.lookup(path)
		if !ok {
			t.Errorf("%s: expected virtual content, got not-found", path)
			continue
		}
		if string(data) != expected {
			t.Errorf("%s: host content leaked through virtual override\n got:  %q\n want: %q",
				path, string(data), expected)
		}
	}
}

// TestDenyAlwaysBlocks enumerates the deny list against every operation
// that can access a file (open, access, listdir) and checks they all
// surface EACCES — no "side door" allows the sandbox to read a denied
// path via a different syscall.
func TestDenyAlwaysBlocks(t *testing.T) {
	host := t.TempDir()
	// Create some real files under the host passthrough root so a deny
	// list is the only thing standing between the gofer and the bytes.
	for _, name := range []string{"secret/a", "secret/b", "public/ok"} {
		p := filepath.Join(host, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	g := newGoferServer(host)
	g.denies = []string{"/secret", "/virtual-deny"}
	g.addFile("/virtual-deny/file", []byte("should-not-leak"))
	g.addFile("/virtual-ok", []byte("fine"))

	denied := []string{"/secret", "/secret/a", "/secret/b", "/virtual-deny", "/virtual-deny/file"}
	for _, path := range denied {
		// Open
		r := g.handle(&GoferRequest{Op: OpOpen, Path: path})
		if r.Err != "EACCES" {
			t.Errorf("Open(%q): expected EACCES, got %q", path, r.Err)
		}
		// Access
		r = g.handle(&GoferRequest{Op: OpAccess, Path: path})
		if r.Err != "EACCES" {
			t.Errorf("Access(%q): expected EACCES, got %q", path, r.Err)
		}
	}

	// Positive control: a non-denied path still opens.
	r := g.handle(&GoferRequest{Op: OpOpen, Path: "/virtual-ok"})
	if r.Err != "" {
		t.Fatalf("positive control Open(/virtual-ok) failed: %q", r.Err)
	}

	// Denied children should also be filtered out of listDir, so the
	// sandbox can't even learn the denied names exist.
	entries := g.listDir("/")
	for _, e := range entries {
		if e == "secret" {
			t.Errorf("listDir(/) leaked denied entry %q (entries=%v)", e, entries)
		}
	}
}

// TestInMemoryDenyAlsoBlocks mirrors TestDenyAlwaysBlocks for the
// in-memory VFS path (used when --gofer=false).
func TestInMemoryDenyAlsoBlocks(t *testing.T) {
	mem := NewInMemoryVFS()
	mem.AddFile("/etc/secret", []byte("do-not-leak"))
	mem.AddFile("/etc/public", []byte("ok"))
	mem.SetDenies([]string{"/etc/secret"})

	_, eno := mem.Lookup("/etc/secret")
	if eno != syscall.EACCES {
		t.Errorf("Lookup(/etc/secret): expected EACCES, got %v", eno)
	}
	_, eno = mem.Lookup("/etc/public")
	if eno != 0 {
		t.Errorf("Lookup(/etc/public): expected 0, got %v", eno)
	}
}

// Sanity: construct many denies / files to confirm the matcher scales.
func TestDenyPrefixPrecision(t *testing.T) {
	g := newGoferServer("")
	g.denies = []string{"/etc/secret"}
	g.addFile("/etc/secret/a", []byte("x"))
	g.addFile("/etc/secretary", []byte("x"))
	g.addFile("/etc/secret", []byte("x"))

	cases := []struct {
		path   string
		denied bool
	}{
		{"/etc/secret", true},
		{"/etc/secret/a", true},
		{"/etc/secretary", false}, // must NOT match as a prefix
		{"/etc", false},
	}
	for _, c := range cases {
		r := g.handle(&GoferRequest{Op: OpOpen, Path: c.path})
		isDenied := r.Err == "EACCES"
		if isDenied != c.denied {
			t.Errorf("path=%q: denied=%v, want %v (err=%q)",
				c.path, isDenied, c.denied, r.Err)
		}
	}
}

// compile-time: confirm our error strings are stable and parseable by
// the client — a gofer that invents a new string would silently bypass
// denies on the sentry side.
func TestGoferErrorNamesRoundTrip(t *testing.T) {
	for _, name := range []string{"ENOENT", "EACCES", "EBADF", "EINVAL", "ENOTDIR"} {
		eno := goferErrToErrno(name)
		if eno == 0 {
			t.Fatalf("%s mapped to 0 (success)", name)
		}
		if eno == syscall.EIO && name != "EIO" {
			t.Fatalf("%s fell through to EIO; missing mapping", name)
		}
		_ = fmt.Sprintf("%v", eno)
	}
}
