//go:build linux

package main

// handlers_test.go — pure-logic tests for parsers, mount matching, and
// the linux_dirent64 packer. These are the per-function building blocks
// the syscall handlers compose out of; keeping them honest in isolation
// pays off when a compound bug would otherwise be hard to localise.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseMount(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	cases := []struct {
		name      string
		in        string
		wantHost  string
		wantGuest string
		wantRO    bool
		wantErr   bool
	}{
		{"basic rw", "/lib:/lib", "/lib", "/lib", false, false},
		{"explicit rw", "/tmp:/tmp:rw", "/tmp", "/tmp", false, false},
		{"ro", "/usr/lib:/lib:ro", "/usr/lib", "/lib", true, false},
		{"case-insensitive ro", "/usr/lib:/lib:RO", "/usr/lib", "/lib", true, false},
		// Relative host path resolves via filepath.Abs.
		{"relative host", "rel:/mnt", filepath.Join(cwd, "rel"), "/mnt", false, false},
		{"trailing slash cleaned", "/lib/:/lib/", "/lib", "/lib", false, false},
		// Errors.
		{"no colon", "/lib", "", "", false, true},
		{"too many colons", "/a:/b:ro:x", "", "", false, true},
		{"empty host", ":/mnt", "", "", false, true},
		{"empty guest", "/host:", "", "", false, true},
		{"relative guest", "/host:mnt", "", "", false, true},
		{"bad flag", "/host:/guest:rx", "", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := parseMount(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %+v, want error", m)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m.Host != tc.wantHost || m.Guest != tc.wantGuest || m.ReadOnly != tc.wantRO {
				t.Fatalf("parseMount(%q) = %+v, want host=%q guest=%q ro=%v",
					tc.in, m, tc.wantHost, tc.wantGuest, tc.wantRO)
			}
		})
	}
}

func TestMatchMountLongestPrefix(t *testing.T) {
	mounts := sortMountsByGuestLen([]Mount{
		{Host: "/host/root", Guest: "/"},
		{Host: "/host/usr", Guest: "/usr"},
		{Host: "/host/usr-lib", Guest: "/usr/lib"},
	})

	cases := []struct {
		guest    string
		wantHost string
		wantOk   bool
	}{
		{"/etc/hostname", "/host/root/etc/hostname", true},
		{"/usr/bin/cat", "/host/usr/bin/cat", true},
		{"/usr/lib/libc.so", "/host/usr-lib/libc.so", true},
		// Exact-mount root.
		{"/usr/lib", "/host/usr-lib", true},
		// Cleans up redundant separators before matching.
		{"/usr//lib/ld.so", "/host/usr-lib/ld.so", true},
	}
	for _, tc := range cases {
		t.Run(tc.guest, func(t *testing.T) {
			host, _, ok := matchMount(mounts, tc.guest)
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOk)
			}
			if host != tc.wantHost {
				t.Fatalf("host = %q, want %q", host, tc.wantHost)
			}
		})
	}

	// No covering mount → ok=false.
	empty := []Mount{{Host: "/host/usr", Guest: "/usr"}}
	if _, _, ok := matchMount(empty, "/etc/hostname"); ok {
		t.Fatalf("unexpected match for /etc/hostname against /usr-only mount list")
	}
}

func TestSerializeRoundTripsMounts(t *testing.T) {
	in := []Mount{
		{Host: "/host/root", Guest: "/", ReadOnly: false},
		{Host: "/host/lib", Guest: "/lib", ReadOnly: true},
	}
	out := deserializeMounts(serializeMounts(in))
	if len(out) != len(in) {
		t.Fatalf("len=%d, want %d (s=%q)", len(out), len(in), serializeMounts(in))
	}
	for i, m := range in {
		if out[i] != m {
			t.Fatalf("entry %d: got %+v, want %+v", i, out[i], m)
		}
	}
	// Empty list round-trips to empty.
	if got := serializeMounts(nil); got != "" {
		t.Fatalf("empty serialize = %q, want \"\"", got)
	}
	if got := deserializeMounts(""); len(got) != 0 {
		t.Fatalf("empty deserialize = %+v, want empty", got)
	}
}

func TestParseRlimit(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantRes  int
		wantSoft uint64
		wantHard uint64
		wantErr  bool
	}{
		{"nofile soft only", "nofile=64", unix.RLIMIT_NOFILE, 64, 0, false},
		{"cpu with hard", "cpu=5:10", unix.RLIMIT_CPU, 5, 10, false},
		{"case-insensitive name", "NOFILE=64", unix.RLIMIT_NOFILE, 64, 0, false},
		{"whitespace tolerant", "  nofile = 64 ", unix.RLIMIT_NOFILE, 64, 0, false},
		// Errors.
		{"no equals", "nofile", 0, 0, 0, true},
		{"unknown name", "pirates=1", 0, 0, 0, true},
		{"bad soft", "nofile=abc", 0, 0, 0, true},
		{"bad hard", "nofile=1:abc", 0, 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parseRlimit(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %+v, want error", spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if spec.Resource != tc.wantRes {
				t.Fatalf("Resource = %d, want %d", spec.Resource, tc.wantRes)
			}
			if spec.Soft != tc.wantSoft {
				t.Fatalf("Soft = %d, want %d", spec.Soft, tc.wantSoft)
			}
			if spec.Hard != tc.wantHard {
				t.Fatalf("Hard = %d, want %d", spec.Hard, tc.wantHard)
			}
		})
	}
}

// TestRlimitNameListIsSorted pins the deterministic-error-message
// invariant the CLI depends on. Users see this string when they type
// a bad rlimit name; flip-flopping order makes it hard to grep docs.
func TestRlimitNameListIsSorted(t *testing.T) {
	s := rlimitNameList()
	parts := strings.Split(s, ", ")
	for i := 1; i < len(parts); i++ {
		if parts[i-1] >= parts[i] {
			t.Fatalf("rlimitNameList not sorted: %q vs %q (full=%q)",
				parts[i-1], parts[i], s)
		}
	}
}

func TestPackDirent64(t *testing.T) {
	cases := []struct {
		name  string
		ino   uint64
		file  string
		dtype byte
	}{
		{"empty name", 1, "", 8},
		{"short name", 2, "a", 8},
		{"7 chars", 3, "readme!", 8},
		{"exactly 8 chars before NUL", 4, "abcdefgh", 8},
		{"12 chars", 5, "twelvechars!", 8},
		{"DT_DIR type", 6, "subdir", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := packDirent64(tc.ino, tc.file, tc.dtype)
			if len(d)%8 != 0 {
				t.Fatalf("len %d not 8-aligned", len(d))
			}
			// Minimum layout: 8 ino + 8 off + 2 reclen + 1 type + NUL + pad.
			if len(d) < 24 {
				t.Fatalf("len %d below minimum 24", len(d))
			}
			// NUL-terminated name lives at [19..].
			nul := 19 + len(tc.file)
			if nul >= len(d) || d[nul] != 0 {
				t.Fatalf("missing NUL terminator at index %d", nul)
			}
			if d[18] != tc.dtype {
				t.Fatalf("d_type = %d, want %d", d[18], tc.dtype)
			}
		})
	}
}

func TestStripEnv(t *testing.T) {
	in := []string{"PATH=/usr/bin", "HOME=/root", "LANG=C", "PS1=$ "}
	out := stripEnv(in, "HOME", "PS1")

	if len(out) != 2 {
		t.Fatalf("len=%d, want 2 (got %v)", len(out), out)
	}
	for _, e := range out {
		if strings.HasPrefix(e, "HOME=") || strings.HasPrefix(e, "PS1=") {
			t.Fatalf("stripped name leaked: %q", e)
		}
	}
	// Non-matching call returns all entries.
	if len(stripEnv(in, "NONEXISTENT")) != len(in) {
		t.Fatalf("non-match should return original length")
	}
}
