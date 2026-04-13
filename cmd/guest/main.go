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

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║  All tests complete!                             ║")
	fmt.Println("║  The host kernel never saw any of our syscalls.  ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
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
