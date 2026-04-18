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
	"runtime"
	"sync"
	"sync/atomic"
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

	// Test 7 (ADR 002 §5.1) — real SIGUSR1 handler round-trip. Install a
	// pure-asm handler via raw rt_sigaction (bypassing os/signal and its
	// gsignal routing), kill(self, SIGUSR1), observe the handler bump
	// sigCounter. Proves Phase 3c's per-thread routing lands a
	// group-directed kill on an eligible thread AND Phase 3b's
	// BuildRtSigframe + sysRtSigreturn round-trip works end-to-end.
	//
	// Scoped to the ptrace platform: under seccomp, sendSelfSignal
	// falls back to a real host kill because there is no Sentry-side
	// drain, and the self-kill path returns EINTR on the USER_NOTIF
	// round-trip the moment the kernel delivers the signal we just
	// raised. That's a seccomp-platform property, not a Phase 3c bug.
	fmt.Printf("Test 7 — SIGUSR1 handler round-trip (raw rt_sigaction)\n")
	if !realSigSupported {
		fmt.Printf("  skipped: real handler is amd64-only in Phase 3c\n")
	} else if os.Getenv("MINI_SENTRY_PLATFORM") == "seccomp" {
		fmt.Printf("  skipped: Sentry-side delivery is ptrace-only in Phase 3c\n")
	} else if err := installRealSigUsr1(); err != nil {
		fmt.Printf("  ERROR: rt_sigaction(SIGUSR1): %v\n", err)
	} else {
		before := atomic.LoadInt32(&sigCounter)
		start := time.Now()
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
			fmt.Printf("  ERROR: kill(self, SIGUSR1): %v\n", err)
		} else {
			after := atomic.LoadInt32(&sigCounter)
			if after != before+1 {
				fmt.Printf("  MISMATCH: counter %d -> %d, want +1\n", before, after)
			} else {
				fmt.Printf("  handler ran (counter %d -> %d) in %v\n",
					before, after, time.Since(start))
			}
		}
	}
	fmt.Println()

	// Test 8: sigaltstack(2) mirror round-trip (Phase 3c commit 1).
	// Install an altstack via raw syscall, read it back, compare sp/size.
	// The Sentry intercepts both the write and (via passthrough) the
	// read; a mismatch means our mirror diverged from what the kernel
	// stored.
	fmt.Printf("Test 8 — sigaltstack mirror round-trip\n")
	var altBuf [16384]byte
	want := stackT{sp: uintptr(unsafe.Pointer(&altBuf[0])), size: uint64(len(altBuf))}
	if err := setAltStack(&want, nil); err != nil {
		fmt.Printf("  ERROR: sigaltstack install: %v\n", err)
	} else {
		var got stackT
		if err := setAltStack(nil, &got); err != nil {
			fmt.Printf("  ERROR: sigaltstack query: %v\n", err)
		} else if got.sp != want.sp || got.size != want.size {
			fmt.Printf("  MISMATCH: installed sp=0x%x size=%d, readback sp=0x%x size=%d\n",
				want.sp, want.size, got.sp, got.size)
		} else {
			fmt.Printf("  round-trip OK: sp=0x%x size=%d\n", got.sp, got.size)
		}
	}
	fmt.Println()

	// Test 9 (ADR 002 §5.4) — multi-thread tkill stress. Spawn 4
	// goroutines, each locks its own OS thread and tgkills itself with
	// SIGUSR1. Per-thread routing (§3) must send each signal to the
	// caller's own queue; TRACECLONE (§2) must have each worker
	// attached so its syscalls reach the Sentry at all. Assert all 4
	// handler runs land by checking sigCounter delta. A missed thread
	// hangs at wg.Wait (the goroutine never resumes from tgkill).
	fmt.Printf("Test 9 — multi-thread tkill stress (4 goroutines)\n")
	if !realSigSupported {
		fmt.Printf("  skipped: real handler is amd64-only in Phase 3c\n")
	} else if os.Getenv("MINI_SENTRY_PLATFORM") == "seccomp" {
		fmt.Printf("  skipped: Sentry-side delivery is ptrace-only in Phase 3c\n")
	} else {
		const workers = 4
		before := atomic.LoadInt32(&sigCounter)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				// Pin this goroutine to a dedicated OS thread so its
				// tgkill routes via a stable host tid. Without the
				// lock the runtime might migrate the goroutine between
				// Ms mid-syscall.
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				// tgkill(tgid=1, tid=1, SIGUSR1). Both ids are the
				// spoofed values the Sentry serves via getpid/gettid;
				// sysTgkill routes by the calling thread's host tid
				// (handlers.go:sysTgkill → callerThread(pid)).
				_, _, e := syscall.RawSyscall(syscall.SYS_TGKILL,
					1, 1, uintptr(syscall.SIGUSR1))
				if e != 0 {
					fmt.Printf("  goroutine %d: tgkill errno=%d\n", n, e)
				}
			}(i)
		}
		wg.Wait()
		after := atomic.LoadInt32(&sigCounter)
		delivered := after - before
		if delivered != int32(workers) {
			fmt.Printf("  MISMATCH: delivered=%d, want=%d (counter %d -> %d)\n",
				delivered, workers, before, after)
		} else {
			fmt.Printf("  all %d handlers fired (counter %d -> %d)\n",
				workers, before, after)
		}
	}
	fmt.Println()

	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║  All tests complete!                             ║")
	fmt.Println("║  The host kernel never saw any of our syscalls.  ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
}

// stackT is the kernel-ABI sigaltstack layout: sp(u64), flags(i32) +
// 4 bytes pad, size(u64). Matches the StackT the Sentry mirror uses.
type stackT struct {
	sp    uintptr
	flags int32
	_     int32
	size  uint64
}

// setAltStack wraps raw sigaltstack(2). Either arg may be nil.
func setAltStack(ss, old *stackT) error {
	var ssp, oldp uintptr
	if ss != nil {
		ssp = uintptr(unsafe.Pointer(ss))
	}
	if old != nil {
		oldp = uintptr(unsafe.Pointer(old))
	}
	_, _, e := syscall.RawSyscall(syscall.SYS_SIGALTSTACK, ssp, oldp, 0)
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
