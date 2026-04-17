//go:build linux && arm64

package main

// wantPtraceRegsSize is the expected size of unix.PtraceRegs on arm64.
// The kernel's struct user_pt_regs has 31 x-registers + sp + pc +
// pstate = 34 u64 fields, so 34 × 8 = 272 bytes.
const wantPtraceRegsSize = 272
