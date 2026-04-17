//go:build linux && amd64

package main

// wantPtraceRegsSize is the expected size of unix.PtraceRegs on amd64.
// The kernel's struct user_regs_struct has 27 u64 fields (r15..gs),
// so 27 × 8 = 216 bytes.
const wantPtraceRegsSize = 216
