//go:build linux

package main

// cross_check_test.go — ABI cross-checks.
//
// These are tiny tests whose only job is to catch *layout* bugs — the
// class of mistakes where our hand-rolled struct offsets drift out of
// sync with what the kernel actually expects. A byte-off mistake on
// kernel_sigaction would silently install the wrong handler, and a
// drift in sigset_t size would mask the wrong signals. Neither shows
// up in functional tests until a guest actually raises a signal.
//
// Everything here runs in-process, takes microseconds, and has zero
// dependencies on a tracee.

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestSigsetSizeIs8 locks our canonical sigset form to 8 bytes. The
// kernel sigset_t for rt_sigaction / rt_sigprocmask is exactly one
// 64-bit word on Linux. Userspace glibc pads it to 128 bytes, but the
// *syscall* expects 8 — the sigsetsize argument enforces that. If
// someone widens sigset, every packed kernel_sigaction struct we
// build or decode breaks.
func TestSigsetSizeIs8(t *testing.T) {
	var s sigset
	if got := unsafe.Sizeof(s); got != 8 {
		t.Fatalf("sigset size = %d, want 8 (kernel sigset_t is one uint64)", got)
	}
}

// TestKernelSigactionLayout asserts the per-arch layout constants are
// self-consistent. Each named offset must fit an 8-byte field inside
// kernelSigactionSize, and the fields must not overlap. arm64 omits
// sa_restorer; we enforce that hasRestorer matches the size.
func TestKernelSigactionLayout(t *testing.T) {
	l := kernelSigactionLayout

	// handler is always at offset 0 (matches struct kernel_sigaction
	// in the kernel source — sa_handler is the first member).
	if l.handlerOff != 0 {
		t.Fatalf("handlerOff = %d, want 0", l.handlerOff)
	}
	// flags follows the 8-byte handler pointer on both arches.
	if l.flagsOff != 8 {
		t.Fatalf("flagsOff = %d, want 8", l.flagsOff)
	}

	// mask is the last field; it must fit in the struct.
	if l.maskOff < 0 || l.maskOff+8 > kernelSigactionSize {
		t.Fatalf("maskOff=%d does not fit in size %d", l.maskOff, kernelSigactionSize)
	}

	// Restorer invariant. amd64: present, at offset 16, size 32.
	// arm64: absent, size 24.
	if l.hasRestorer {
		if kernelSigactionSize != 32 {
			t.Fatalf("hasRestorer=true but size=%d (amd64 must be 32)", kernelSigactionSize)
		}
		if l.restorerOff != 16 {
			t.Fatalf("restorerOff=%d, want 16 on amd64", l.restorerOff)
		}
		if l.maskOff != 24 {
			t.Fatalf("maskOff=%d, want 24 on amd64 (after restorer)", l.maskOff)
		}
	} else {
		if kernelSigactionSize != 24 {
			t.Fatalf("hasRestorer=false but size=%d (arm64 must be 24)", kernelSigactionSize)
		}
		if l.maskOff != 16 {
			t.Fatalf("maskOff=%d, want 16 on arm64 (after flags)", l.maskOff)
		}
	}

	// Roundtrip: encode a known SigAction and decode it back. Any
	// offset drift will corrupt one field.
	buf := make([]byte, kernelSigactionSize)
	want := SigAction{handler: 0xdead_beef, flags: 0xcafe, mask: 0x1234, restorer: 0xaa55}
	binary.LittleEndian.PutUint64(buf[l.handlerOff:l.handlerOff+8], want.handler)
	binary.LittleEndian.PutUint64(buf[l.flagsOff:l.flagsOff+8], want.flags)
	binary.LittleEndian.PutUint64(buf[l.maskOff:l.maskOff+8], uint64(want.mask))
	if l.hasRestorer {
		binary.LittleEndian.PutUint64(buf[l.restorerOff:l.restorerOff+8], want.restorer)
	}

	got := SigAction{
		handler: binary.LittleEndian.Uint64(buf[l.handlerOff : l.handlerOff+8]),
		flags:   binary.LittleEndian.Uint64(buf[l.flagsOff : l.flagsOff+8]),
		mask:    sigset(binary.LittleEndian.Uint64(buf[l.maskOff : l.maskOff+8])),
	}
	if l.hasRestorer {
		got.restorer = binary.LittleEndian.Uint64(buf[l.restorerOff : l.restorerOff+8])
	} else {
		want.restorer = 0 // not encoded, so not decoded
	}
	if got != want {
		t.Fatalf("roundtrip mismatch:\n got  %+v\n want %+v", got, want)
	}
}

// TestGetdents64RecordWalk walks a buffer of packed linux_dirent64
// records the way a guest libc would and verifies every field.
//
// This catches:
//   - wrong d_reclen (walker would desync and mis-read the next entry)
//   - wrong field offsets inside the record
//   - wrong padding / alignment
func TestGetdents64RecordWalk(t *testing.T) {
	type entry struct {
		ino  uint64
		name string
	}
	input := []entry{
		{1001, "a"},
		{1002, "hello"},
		{1003, "twelvechars!"},
		{1004, ""}, // empty string is legal; d_name is just "\0"
	}

	var packed []byte
	for _, e := range input {
		packed = append(packed, packDirent64(e.ino, e.name, 8)...)
	}

	// Walk exactly like a guest would: pull d_reclen, step forward.
	var walked []entry
	off := 0
	for off < len(packed) {
		if off+19 > len(packed) {
			t.Fatalf("buffer truncated at offset %d (need 19 bytes for header)", off)
		}
		ino := binary.LittleEndian.Uint64(packed[off : off+8])
		dOff := binary.LittleEndian.Uint64(packed[off+8 : off+16])
		reclen := int(binary.LittleEndian.Uint16(packed[off+16 : off+18]))
		dtype := packed[off+18]

		if reclen%8 != 0 {
			t.Fatalf("record at offset %d has reclen=%d, not 8-byte aligned", off, reclen)
		}
		if off+reclen > len(packed) {
			t.Fatalf("record at offset %d claims reclen=%d but buffer is %d", off, reclen, len(packed))
		}
		if dtype != 8 {
			t.Fatalf("record at offset %d d_type=%d, want 8 (DT_REG)", off, dtype)
		}
		if dOff != 0 {
			t.Fatalf("record at offset %d d_off=%d, want 0 (we don't seek)", off, dOff)
		}

		// d_name is a NUL-terminated string starting at offset 19.
		nameEnd := off + 19
		for nameEnd < off+reclen && packed[nameEnd] != 0 {
			nameEnd++
		}
		name := string(packed[off+19 : nameEnd])
		walked = append(walked, entry{ino: ino, name: name})
		off += reclen
	}

	if off != len(packed) {
		t.Fatalf("walk ended at offset %d, expected %d", off, len(packed))
	}
	if len(walked) != len(input) {
		t.Fatalf("walked %d entries, packed %d", len(walked), len(input))
	}
	for i, e := range input {
		if walked[i] != e {
			t.Fatalf("entry %d: got %+v, want %+v", i, walked[i], e)
		}
	}
}

// TestSigprocmaskHowConstants pins the three SIG_* how values our
// SetMask switch uses. The kernel ABI is 0/1/2; if an unrelated change
// ever remaps these values by accident, mask state would quietly drift.
// Cross-check against golang.org/x/sys/unix so we catch divergence from
// any upstream renaming too.
func TestSigprocmaskHowConstants(t *testing.T) {
	// Case 0: SIG_BLOCK should OR set into mask.
	ss := NewSignalState()
	ss.mask = 0x0
	ss.SetMask(0, sigset(0b0011))
	if got := ss.GetMask(); got != 0b0011 {
		t.Fatalf("SIG_BLOCK: mask=0b%04b, want 0b0011", got)
	}
	ss.SetMask(0, sigset(0b0100))
	if got := ss.GetMask(); got != 0b0111 {
		t.Fatalf("SIG_BLOCK adds: mask=0b%04b, want 0b0111", got)
	}

	// Case 1: SIG_UNBLOCK should clear bits.
	ss.SetMask(1, sigset(0b0001))
	if got := ss.GetMask(); got != 0b0110 {
		t.Fatalf("SIG_UNBLOCK: mask=0b%04b, want 0b0110", got)
	}

	// Case 2: SIG_SETMASK replaces wholesale.
	ss.SetMask(2, sigset(0xff))
	if got := ss.GetMask(); got != 0xff {
		t.Fatalf("SIG_SETMASK: mask=0x%x, want 0xff", got)
	}

	// Unknown "how" must be a no-op (kernel returns EINVAL; we just
	// preserve state). Guard against a future switch growing a
	// surprise default.
	ss.SetMask(99, sigset(0))
	if got := ss.GetMask(); got != 0xff {
		t.Fatalf("unknown how mutated mask: got 0x%x, want 0xff", got)
	}

	// Cross-check against unix package — if these ever change, our
	// case numbers need to change with them.
	if unix.SIG_BLOCK != 0 || unix.SIG_UNBLOCK != 1 || unix.SIG_SETMASK != 2 {
		t.Fatalf("unix SIG_* constants drifted: BLOCK=%d UNBLOCK=%d SETMASK=%d",
			unix.SIG_BLOCK, unix.SIG_UNBLOCK, unix.SIG_SETMASK)
	}
}

// TestPtraceRegsSize locks the kernel's user_regs_struct size on amd64
// (27 × 8 = 216 bytes). We depend on unix.PtraceRegs having the same
// layout as the kernel — if it doesn't, PTRACE_GETREGS/SETREGS would
// read or write past the struct. A size check is a cheap proxy for
// layout correctness.
//
// On arm64, user_pt_regs is 34 × 8 = 272 bytes (31 x-regs + sp + pc +
// pstate). Split the constant per arch so this still compiles on both.
func TestPtraceRegsSize(t *testing.T) {
	var r unix.PtraceRegs
	got := unsafe.Sizeof(r)
	if got != wantPtraceRegsSize {
		t.Fatalf("PtraceRegs size = %d, want %d for this arch", got, wantPtraceRegsSize)
	}
}
