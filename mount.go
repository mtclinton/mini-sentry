//go:build linux

package main

// mount.go — Parse --mount host:guest[:ro] flags and carry them into
// the Gofer as a list of mount points. Phase 2 (dynamic linker support)
// will teach the Gofer to serve multiple host trees; for now the Gofer
// accepts the list but only honors the first one (backwards-compatible
// with --gofer-root).

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Mount is one --mount entry: a host-directory subtree made visible at
// a guest path, optionally read-only.
type Mount struct {
	Host     string // host path (absolute after cleaning)
	Guest    string // guest path (absolute, filepath.Clean'd)
	ReadOnly bool
}

// parseMount parses "host:guest[:ro|:rw]".
//
// Examples:
//
//	/lib:/lib:ro           → bind-mount /lib at /lib, read-only
//	/home/alice/out:/out   → rw by default
//	/tmp/scratch:/tmp      → rw
//
// The guest path is always filepath.Clean'd; the host path is made
// absolute (we don't resolve symlinks here — the Gofer does that on
// every lookup, so an adversary swapping the host target can't escape).
func parseMount(s string) (Mount, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return Mount{}, fmt.Errorf("expected HOST:GUEST[:ro|:rw], got %q", s)
	}
	host := strings.TrimSpace(parts[0])
	guest := strings.TrimSpace(parts[1])
	if host == "" || guest == "" {
		return Mount{}, fmt.Errorf("empty host or guest path in %q", s)
	}
	if !filepath.IsAbs(host) {
		abs, err := filepath.Abs(host)
		if err != nil {
			return Mount{}, fmt.Errorf("resolve host %q: %w", host, err)
		}
		host = abs
	}
	if !filepath.IsAbs(guest) {
		return Mount{}, fmt.Errorf("guest path must be absolute: %q", guest)
	}
	m := Mount{
		Host:  filepath.Clean(host),
		Guest: filepath.Clean(guest),
	}
	if len(parts) == 3 {
		switch strings.ToLower(strings.TrimSpace(parts[2])) {
		case "ro":
			m.ReadOnly = true
		case "rw", "":
			m.ReadOnly = false
		default:
			return Mount{}, fmt.Errorf("unknown mount flag %q (want ro or rw)", parts[2])
		}
	}
	return m, nil
}

// parseMounts is a batch parser for --mount repeats.
func parseMounts(specs []string) ([]Mount, error) {
	out := make([]Mount, 0, len(specs))
	for _, s := range specs {
		m, err := parseMount(s)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// sortMountsByGuestLen returns a copy sorted by guest-path length
// descending, so longest-prefix-wins during lookup. /usr/lib beats /usr
// which beats /. Ties (unlikely: same guest path mounted twice) keep
// input order so the user can see "last wins" if they want.
func sortMountsByGuestLen(mounts []Mount) []Mount {
	out := append([]Mount(nil), mounts...)
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].Guest) > len(out[j].Guest)
	})
	return out
}

// serialize turns a mount list into the wire format the Gofer bootstrap
// consumes via env var. Format: "HOST\x1fGUEST\x1fRO\x1e..." — record
// separator between entries, unit separator between fields. Using
// non-printable ASCII avoids colliding with legitimate path chars.
func serializeMounts(mounts []Mount) string {
	if len(mounts) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, m := range mounts {
		if i > 0 {
			sb.WriteByte(0x1e)
		}
		sb.WriteString(m.Host)
		sb.WriteByte(0x1f)
		sb.WriteString(m.Guest)
		sb.WriteByte(0x1f)
		if m.ReadOnly {
			sb.WriteString("ro")
		} else {
			sb.WriteString("rw")
		}
	}
	return sb.String()
}

func deserializeMounts(s string) []Mount {
	if s == "" {
		return nil
	}
	recs := strings.Split(s, "\x1e")
	out := make([]Mount, 0, len(recs))
	for _, r := range recs {
		fields := strings.Split(r, "\x1f")
		if len(fields) != 3 {
			continue
		}
		out = append(out, Mount{
			Host:     fields[0],
			Guest:    fields[1],
			ReadOnly: fields[2] == "ro",
		})
	}
	return out
}

// matchMount finds the best (longest-prefix) mount for the given guest
// path. Returns the host path that the guest path maps to and whether
// the mount was read-only. ok=false means no mount covers the path.
func matchMount(mounts []Mount, guestPath string) (hostPath string, readOnly bool, ok bool) {
	guest := filepath.Clean(guestPath)
	for _, m := range mounts {
		rel, err := filepath.Rel(m.Guest, guest)
		if err != nil {
			continue
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return filepath.Join(m.Host, rel), m.ReadOnly, true
	}
	return "", false, false
}
