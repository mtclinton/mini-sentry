package main

// vfs.go — Virtual Filesystem (maps to gVisor's Gofer + VFS2)
//
// In gVisor, the filesystem architecture has two major components:
//
//   1. Gofer — A separate process that mediates all host filesystem access.
//      The Sentry communicates with the Gofer over a protocol called LISAFS
//      (previously 9P). The Sentry says "open /etc/hostname" and the Gofer
//      decides whether to allow it and returns the file contents. This
//      separation means even if the Sentry is compromised, it can't open
//      arbitrary files — it can only ask the Gofer, which has its own
//      allowlist of paths.
//
//   2. VFS2 — The virtual filesystem layer inside the Sentry that manages
//      mount points, file descriptor tables, path resolution, and dispatches
//      operations to the appropriate filesystem implementation (tmpfs, proc,
//      devfs, gofer-backed, overlay, etc.).
//
// mini-sentry ships two implementations of the VFS interface:
//
//   * InMemoryVFS — all state lives inside the Sentry process as a map of
//                    path → bytes. Cheap and simple; used with --gofer=false.
//
//   * GoferVFS    — a thin client that issues RPCs to a separate Gofer
//                    process over a Unix socket (see gofer.go / vfs_gofer.go).
//                    This is the real gVisor-style architecture: the Sentry
//                    can only see files the Gofer chooses to serve.

import (
	"path/filepath"
	"strings"
	"syscall"
)

// VFS is the abstract virtual-filesystem the Sentry calls into. Both the
// in-memory implementation and the gofer-backed client satisfy this.
//
// Lookup returns (data, 0) on success and (nil, errno) on failure so the
// Sentry can surface ENOENT vs EACCES accurately to the guest.
type VFS interface {
	AddFile(path string, data []byte)
	Lookup(path string) ([]byte, syscall.Errno)
	ListDir(path string) []string
	FileCount() int
}

// InMemoryVFS holds the virtual filesystem entirely inside the Sentry.
// Maps to gVisor's tmpfs, roughly — no external gofer involved.
type InMemoryVFS struct {
	// files maps absolute paths to file contents.
	files map[string][]byte

	// dirs tracks which directories exist (for getdents64).
	dirs map[string][]string

	// denies is a list of path prefixes that always return EACCES.
	// Matches the --gofer-deny flag semantics even though there's no
	// gofer in this mode.
	denies []string
}

func NewInMemoryVFS() *InMemoryVFS {
	return &InMemoryVFS{
		files: make(map[string][]byte),
		dirs:  make(map[string][]string),
	}
}

// SetDenies configures a list of path prefixes the VFS treats as EACCES.
func (v *InMemoryVFS) SetDenies(denies []string) {
	v.denies = denies
}

func (v *InMemoryVFS) isDenied(path string) bool {
	p := filepath.Clean(path)
	for _, d := range v.denies {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// AddFile adds a file to the virtual filesystem.
func (v *InMemoryVFS) AddFile(path string, data []byte) {
	path = filepath.Clean(path)
	v.files[path] = data

	dir := filepath.Dir(path)
	name := filepath.Base(path)
	if v.dirs[dir] == nil {
		v.dirs[dir] = []string{}
	}
	for _, existing := range v.dirs[dir] {
		if existing == name {
			return
		}
	}
	v.dirs[dir] = append(v.dirs[dir], name)
}

// Lookup resolves a path to file contents.
func (v *InMemoryVFS) Lookup(path string) ([]byte, syscall.Errno) {
	path = filepath.Clean(path)
	if v.isDenied(path) {
		return nil, syscall.EACCES
	}
	data, ok := v.files[path]
	if !ok {
		return nil, syscall.ENOENT
	}
	return data, 0
}

// ListDir returns the entries in a directory, or nil if the path is not a
// directory. Merges explicit entries (direct children registered by
// AddFile) with implicit entries (subdirectories inferred from files
// deeper in the tree), so "/" lists both /greeting.txt and /etc.
func (v *InMemoryVFS) ListDir(path string) []string {
	path = filepath.Clean(path)

	var entries []string
	seen := make(map[string]bool)
	for _, n := range v.dirs[path] {
		if !seen[n] {
			entries = append(entries, n)
			seen[n] = true
		}
	}
	prefix := path
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	for filePath := range v.files {
		if strings.HasPrefix(filePath, prefix) {
			rest := filePath[len(prefix):]
			parts := strings.SplitN(rest, "/", 2)
			name := parts[0]
			if !seen[name] {
				entries = append(entries, name)
				seen[name] = true
			}
		}
	}

	if len(entries) == 0 {
		return nil
	}
	result := make([]string, 0, len(entries)+2)
	result = append(result, ".", "..")
	result = append(result, entries...)
	return result
}

// FileCount returns the number of files in the VFS.
func (v *InMemoryVFS) FileCount() int {
	return len(v.files)
}

// seedDefaults populates the standard fake files the guest tests expect.
// Used by main.go against whichever VFS implementation is in play, and by
// the gofer bootstrap against its internal store.
func seedDefaults(add func(path string, data []byte)) {
	add("/etc/hostname", []byte("mini-sentry-sandbox\n"))
	add("/etc/os-release", []byte("NAME=\"Mini-Sentry Sandbox\"\nVERSION=\"0.1\"\nID=mini-sentry\n"))
	add("/greeting.txt", []byte("Hello from the userspace kernel!\nEvery byte you read was served by Go code, not the Linux kernel.\n"))
	add("/proc/self/status", []byte("Name:\tguest\nState:\tR (running)\nPid:\t1\nUid:\t0\t0\t0\t0\n"))
}
