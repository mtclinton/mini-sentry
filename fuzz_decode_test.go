//go:build linux

package main

// fuzz_decode_test.go — fuzz targets for the per-arch kernel_sigaction
// decoder, the sigset_t bitmap helpers, and in-memory VFS path handling.
//
// Contract: these functions run on every guest syscall that touches
// signals or the filesystem, so a panic is a guest-triggered crash of
// the Sentry. The targets assert "never panic" and that range-guarded
// helpers don't mutate state for invalid signums.

import (
	"encoding/binary"
	"strings"
	"testing"
)

// FuzzDecodeSigaction throws arbitrary byte buffers at the per-arch
// kernel_sigaction layout. The decoder must never panic regardless of
// buffer length; short buffers should just bail without reading past
// the end. This is the same decode sysRtSigaction performs on every
// guest rt_sigaction call, so a panic here is a remote crash vector.
func FuzzDecodeSigaction(f *testing.F) {
	// Canonical valid buffer: all zeros, correct length.
	f.Add(make([]byte, kernelSigactionSize))
	// Handler=SIG_IGN, flags=SA_RESTART, mask=0.
	good := make([]byte, kernelSigactionSize)
	l := kernelSigactionLayout
	binary.LittleEndian.PutUint64(good[l.handlerOff:l.handlerOff+8], uint64(sigIGN))
	binary.LittleEndian.PutUint64(good[l.flagsOff:l.flagsOff+8], 0x10000000)
	f.Add(good)
	// Too short: 0, 1, size-1 bytes.
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add(make([]byte, kernelSigactionSize-1))
	// Oversize: fuzz body must only read the first kernelSigactionSize.
	big := make([]byte, kernelSigactionSize*4)
	for i := range big {
		big[i] = byte(i)
	}
	f.Add(big)

	f.Fuzz(func(t *testing.T, buf []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on %d-byte input: %v", len(buf), r)
			}
		}()
		if len(buf) < kernelSigactionSize {
			return // matches sysRtSigaction: short buffer is a skip, not a decode
		}
		layout := kernelSigactionLayout
		act := SigAction{
			handler: binary.LittleEndian.Uint64(buf[layout.handlerOff : layout.handlerOff+8]),
			flags:   binary.LittleEndian.Uint64(buf[layout.flagsOff : layout.flagsOff+8]),
			mask:    sigset(binary.LittleEndian.Uint64(buf[layout.maskOff : layout.maskOff+8])),
		}
		if layout.hasRestorer {
			act.restorer = binary.LittleEndian.Uint64(buf[layout.restorerOff : layout.restorerOff+8])
		}
		// String() walks act.handler / flags / mask — make sure formatters
		// don't panic on wild bit patterns.
		_ = act.String()
	})
}

// FuzzParseSigset feeds arbitrary 8-byte windows as the serialized
// sigset_t and exercises has/add/del across every valid signum. The
// helpers must never panic and must respect the 1..64 bounds regardless
// of input bit pattern.
func FuzzParseSigset(f *testing.F) {
	f.Add(uint64(0))
	f.Add(^uint64(0))
	f.Add(uint64(0x0102040810204080))
	f.Add(uint64(1))
	f.Add(uint64(1) << 63)

	f.Fuzz(func(t *testing.T, raw uint64) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on raw=0x%x: %v", raw, r)
			}
		}()
		s := sigset(raw)
		// Walk every signum incl. out-of-range. has/add/del must not
		// index out of bounds and must agree: (add then has)==true,
		// (del then has)==false.
		for sig := -1; sig <= 66; sig++ {
			_ = s.has(sig)
			added := s.add(sig)
			deld := s.del(sig)
			if sig >= 1 && sig < nSig {
				if !added.has(sig) {
					t.Fatalf("add(%d) on 0x%x: has=false", sig, raw)
				}
				if deld.has(sig) {
					t.Fatalf("del(%d) on 0x%x: has=true", sig, raw)
				}
			} else {
				// Out-of-range signals must be a no-op rather than
				// rolling over and corrupting state.
				if added != s {
					t.Fatalf("add(%d) mutated on out-of-range: 0x%x -> 0x%x",
						sig, raw, uint64(added))
				}
				if deld != s {
					t.Fatalf("del(%d) mutated on out-of-range: 0x%x -> 0x%x",
						sig, raw, uint64(deld))
				}
			}
		}
	})
}

// FuzzVFSPath feeds arbitrary guest paths to the in-memory VFS's
// Lookup / ListDir / isDenied. These run on every openat / stat /
// getdents64 call, so a panic here is a guest-triggered DoS.
func FuzzVFSPath(f *testing.F) {
	seeds := []string{
		"/",
		"/greeting.txt",
		"/etc/../etc/hostname",
		"../escape",
		"",
		"/proc/self/status",
		"/a/b/c/d/e",
		"//double//slash",
		"/with spaces/ok",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on path=%q: %v", path, r)
			}
		}()
		if strings.ContainsRune(path, 0) {
			return // kernel rejects NUL in paths; not our invariant to enforce
		}
		v := NewInMemoryVFS()
		seedDefaults(v.AddFile)
		v.SetDenies([]string{"/secret", "/etc"})

		_, _ = v.Lookup(path)
		_ = v.ListDir(path)
		_ = v.isDenied(path)
	})
}
