//go:build linux && amd64

package main

// platform_signals_amd64.go — amd64 wait4 signal-stop handler.
//
// When the host kernel hands the Sentry a ptrace signal-delivery-stop
// (the tracee is parked at the edge of signal delivery and we get to
// decide what happens), the amd64 platform enqueues the signal onto
// SignalState.pending and lets the top-of-loop drain build the frame.
// See ADR 001 §3 for the "queue on generation, deliver on resume"
// invariant this half of the machinery satisfies.

import (
	"fmt"
	"syscall"
)

// handleSignalStop on amd64 reads the kernel-held siginfo and
// enqueues the signal. It never forwards via ptraceSysemu(pid, sig):
// the whole point of 3b is that the Sentry builds the frame. Returns
// (code=0, terminated=false, err=nil) on the normal path — the main
// loop's drain on the next iteration picks up the work.
func (p *PtracePlatform) handleSignalStop(pid int, sig syscall.Signal) (int, bool, error) {
	info := ptraceGetsiginfo(pid)
	// AttachThread is idempotent — the stopping tid went through
	// SIGSTOP/EVENT_CLONE registration already, but a brand-new thread
	// whose first observable stop IS a signal-delivery stop (rare but
	// legal) would otherwise miss its ThreadState. Enqueue lands on
	// the thread-directed queue so the drain only looks at it when
	// resuming this specific tid.
	ts := p.sentry.signals.AttachThread(pid)
	ts.Enqueue(int(sig), info)
	_, _ = fmt.Fprintf(logWriter(),
		"  [platform] signal-stop %s (%d) on tid=%d → enqueue\n",
		signalName(int(sig)), int(sig), pid)
	return 0, false, nil
}
