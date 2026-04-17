//go:build linux

package main

// vfs_test.go — pure-logic tests for the in-memory VFS.
//
// These tests exercise the Lookup / ListDir / isDenied logic without
// going near a tracee or the gofer RPC layer. A test that spawns no
// child runs in a few milliseconds and can be part of every commit.

import (
	"sort"
	"syscall"
	"testing"
)

func TestInMemoryVFSLookup(t *testing.T) {
	v := NewInMemoryVFS()
	v.AddFile("/greeting.txt", []byte("hello"))
	v.AddFile("/etc/hostname", []byte("box"))
	v.SetDenies([]string{"/secret"})
	v.AddFile("/secret/pw", []byte("hunter2"))

	cases := []struct {
		path    string
		data    string
		errno   syscall.Errno
		wantErr bool
	}{
		{"/greeting.txt", "hello", 0, false},
		{"/etc/hostname", "box", 0, false},
		// filepath.Clean("/etc/./hostname") → "/etc/hostname".
		{"/etc/./hostname", "box", 0, false},
		// Missing file → ENOENT.
		{"/nope", "", syscall.ENOENT, true},
		// Under a denied prefix → EACCES, even though the file exists.
		{"/secret/pw", "", syscall.EACCES, true},
		// Exact match of a denied path is also EACCES.
		{"/secret", "", syscall.EACCES, true},
		// Paths that merely share a prefix with a deny entry are NOT denied.
		// "/secretfoo" is not under "/secret/".
		{"/secretfoo", "", syscall.ENOENT, true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			data, errno := v.Lookup(tc.path)
			if tc.wantErr {
				if errno != tc.errno {
					t.Fatalf("errno = %v, want %v", errno, tc.errno)
				}
				if data != nil {
					t.Fatalf("data = %q, want nil on error", data)
				}
				return
			}
			if errno != 0 {
				t.Fatalf("unexpected errno = %v", errno)
			}
			if string(data) != tc.data {
				t.Fatalf("data = %q, want %q", data, tc.data)
			}
		})
	}
}

func TestInMemoryVFSListDir(t *testing.T) {
	v := NewInMemoryVFS()
	v.AddFile("/greeting.txt", []byte("hi"))
	v.AddFile("/etc/hostname", []byte("box"))
	v.AddFile("/etc/os-release", []byte("os"))
	v.AddFile("/usr/bin/cat", []byte("cat"))

	cases := []struct {
		path string
		want []string // sorted, includes "." and ".."
	}{
		{"/", []string{".", "..", "etc", "greeting.txt", "usr"}},
		{"/etc", []string{".", "..", "hostname", "os-release"}},
		{"/usr", []string{".", "..", "bin"}},
		{"/usr/bin", []string{".", "..", "cat"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := v.ListDir(tc.path)
			sort.Strings(got)
			wantSorted := append([]string(nil), tc.want...)
			sort.Strings(wantSorted)
			if len(got) != len(wantSorted) {
				t.Fatalf("len=%d, want %d (got %v want %v)", len(got), len(wantSorted), got, wantSorted)
			}
			for i := range got {
				if got[i] != wantSorted[i] {
					t.Fatalf("entry %d: %q, want %q (full got=%v, want=%v)",
						i, got[i], wantSorted[i], got, wantSorted)
				}
			}
		})
	}

	// Non-directory returns nil so getdents64 can ENOTDIR.
	if got := v.ListDir("/does/not/exist"); got != nil {
		t.Fatalf("ListDir on missing path = %v, want nil", got)
	}
}

func TestInMemoryVFSAddFileIdempotent(t *testing.T) {
	v := NewInMemoryVFS()
	v.AddFile("/a", []byte("1"))
	v.AddFile("/a", []byte("2")) // re-add: data replaced, no duplicate dirent
	if v.FileCount() != 1 {
		t.Fatalf("FileCount = %d, want 1", v.FileCount())
	}
	data, _ := v.Lookup("/a")
	if string(data) != "2" {
		t.Fatalf("after re-add, Lookup = %q, want %q", data, "2")
	}
	entries := v.ListDir("/")
	count := 0
	for _, e := range entries {
		if e == "a" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("dir has %d copies of 'a', want 1", count)
	}
}

// TestInMemoryVFSDenyPrefix pins the prefix-matching semantics that
// isDenied implements: it must match the path exactly or with a "/"
// separator, not a string prefix. "/etc" must not cover "/etcetera".
func TestInMemoryVFSDenyPrefix(t *testing.T) {
	v := NewInMemoryVFS()
	v.SetDenies([]string{"/etc"})
	v.AddFile("/etc/hostname", []byte("box"))
	v.AddFile("/etcetera/readme", []byte("ok"))

	if _, err := v.Lookup("/etc/hostname"); err != syscall.EACCES {
		t.Fatalf("inside /etc should be EACCES, got %v", err)
	}
	if data, err := v.Lookup("/etcetera/readme"); err != 0 || string(data) != "ok" {
		t.Fatalf("/etcetera/readme should NOT be denied; got err=%v data=%q", err, data)
	}
}

func TestSeedDefaults(t *testing.T) {
	v := NewInMemoryVFS()
	seedDefaults(v.AddFile)

	want := []string{"/etc/hostname", "/etc/os-release", "/greeting.txt", "/proc/self/status"}
	for _, p := range want {
		data, err := v.Lookup(p)
		if err != 0 {
			t.Fatalf("seeded %q not found: %v", p, err)
		}
		if len(data) == 0 {
			t.Fatalf("seeded %q is empty", p)
		}
	}
	if v.FileCount() != len(want) {
		t.Fatalf("FileCount = %d, want %d", v.FileCount(), len(want))
	}
}
