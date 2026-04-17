//go:build linux && amd64

package main

// fuzz_sigframe_amd64_test.go — fuzz target for DecodeRtSigframe.
//
// Contract: DecodeRtSigframe runs on every guest rt_sigreturn (Phase
// 3b commit 2) against a 1032-byte buffer read out of guest memory.
// A malicious guest can stuff arbitrary bytes into that buffer, so
// the decoder must never panic — bad lengths become errors, wild bit
// patterns become register values the platform's SETREGS will
// faithfully apply.
//
// We do NOT assert anything about decoded field values; the test is
// "never panic, never read out of bounds."

import "testing"

func FuzzDecodeRtSigframe(f *testing.F) {
	// Canonical valid seed: all zeros, correct length.
	f.Add(make([]byte, RtSigframeSize))

	// Correct length, ascending bytes — exercises every offset in the
	// mcontext / ucontext layout.
	ascending := make([]byte, RtSigframeSize)
	for i := range ascending {
		ascending[i] = byte(i)
	}
	f.Add(ascending)

	// Length errors.
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add(make([]byte, RtSigframeSize-1))
	f.Add(make([]byte, RtSigframeSize+1))

	f.Fuzz(func(t *testing.T, buf []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on %d-byte input: %v", len(buf), r)
			}
		}()
		_, _, _, _, _ = DecodeRtSigframe(buf)
	})
}
