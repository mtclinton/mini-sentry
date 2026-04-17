// guest — A test program to run inside the mini-sentry sandbox.
//
// This program exercises the syscalls that mini-sentry implements:
//   - write (stdout)
//   - openat + read + close (virtual files)
//   - getpid (identity spoofing)
//   - stat (file metadata)
//   - getdents64 (directory listing via os.ReadDir)
//
// Build with static linking so it has no shared library dependencies:
//   CGO_ENABLED=0 go build -o guest .
//
// Then run it inside the sandbox:
//   ./mini-sentry ./cmd/guest/guest

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║  Hello from inside the sandbox!                  ║")
	fmt.Println("║  Every syscall I make is handled by Go code.     ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()

	// Test 1: Identity — are we "root" inside the sandbox?
	fmt.Printf("Test 1 — Identity\n")
	fmt.Printf("  PID:  %d (should be 1 — we're 'init' in the sandbox)\n", syscall.Getpid())
	fmt.Printf("  UID:  %d (should be 0 — fake root)\n", syscall.Getuid())
	fmt.Printf("  GID:  %d (should be 0 — fake root)\n", syscall.Getgid())
	fmt.Println()

	// Test 2: Read a virtual file — this file only exists in the sandbox's VFS.
	fmt.Printf("Test 2 — Read virtual file /greeting.txt\n")
	data, err := os.ReadFile("/greeting.txt")
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  Contents: %s\n", string(data))
	}

	// Test 3: Read /etc/hostname — overridden by the sandbox.
	fmt.Printf("Test 3 — Read /etc/hostname (sandboxed)\n")
	data, err = os.ReadFile("/etc/hostname")
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  Hostname: %s\n", string(data))
	}

	// Test 4: Read /etc/os-release — fake OS identity.
	fmt.Printf("Test 4 — Read /etc/os-release (sandboxed)\n")
	data, err = os.ReadFile("/etc/os-release")
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  OS Release:\n")
		for _, line := range splitLines(string(data)) {
			if line != "" {
				fmt.Printf("    %s\n", line)
			}
		}
	}
	fmt.Println()

	// Test 5: Try to read a file that doesn't exist in the sandbox.
	fmt.Printf("Test 5 — Read /etc/passwd (not in sandbox)\n")
	_, err = os.ReadFile("/etc/passwd")
	if err != nil {
		fmt.Printf("  Correctly blocked: %v\n", err)
	} else {
		fmt.Printf("  WARNING: this should have failed!\n")
	}
	fmt.Println()

	// Test 6: Read /proc/self/status — faked by the sandbox.
	fmt.Printf("Test 6 — Read /proc/self/status (sandboxed)\n")
	data, err = os.ReadFile("/proc/self/status")
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  Process status:\n")
		for _, line := range splitLines(string(data)) {
			if line != "" {
				fmt.Printf("    %s\n", line)
			}
		}
	}
	fmt.Println()

	// Test 7: Exercise Sentry-side signal delivery (Phase 3b commit 3)
	// via the SIG_IGN drop path. Go's runtime installs its own handler
	// for SIGURG with SA_ONSTACK — which commit 3 can't emulate yet
	// (ADR 001 punts alt-stack awareness to 3c). So we bypass Go's
	// os/signal machinery and raw-syscall rt_sigaction(SIG_IGN) for
	// SIGUSR1, then kill(self, SIGUSR1). The Sentry's pending queue
	// drain sees the mirrored SIG_IGN disposition and drops the entry
	// quietly — kill() returns 0 and execution continues.
	fmt.Printf("Test 7 — Signals (SIG_IGN drop via Sentry queue)\n")
	if err := installSigIgn(syscall.SIGUSR1); err != nil {
		fmt.Printf("  ERROR: rt_sigaction(SIGUSR1, SIG_IGN): %v\n", err)
	} else {
		before := time.Now()
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
			fmt.Printf("  ERROR: kill(self, SIGUSR1): %v\n", err)
		} else {
			fmt.Printf("  kill(self, SIGUSR1) returned cleanly after %v\n",
				time.Since(before))
		}
	}
	fmt.Println()

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║  All tests complete!                             ║")
	fmt.Println("║  The host kernel never saw any of our syscalls.  ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
}

// sigactionKernel matches the 8-byte-sigset kernel ABI for
// rt_sigaction — distinct from glibc's padded struct.
type sigactionKernel struct {
	Handler  uintptr
	Flags    uint64
	Restorer uintptr
	Mask     uint64
}

// installSigIgn raw-issues rt_sigaction to set SIG_IGN for sig,
// bypassing Go's os/signal machinery (which would re-register a
// SA_ONSTACK handler the Sentry can't yet forge onto the alt stack).
// The Sentry's rt_sigaction handler mirrors the disposition so the
// pending-queue drain will short-circuit to the SIG_IGN branch.
func installSigIgn(sig syscall.Signal) error {
	act := sigactionKernel{Handler: 1} // SIG_IGN
	_, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION,
		uintptr(sig),
		uintptr(unsafe.Pointer(&act)),
		0,
		8, // sigsetsize
		0, 0)
	if e != 0 {
		return e
	}
	return nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
