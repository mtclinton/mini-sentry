//go:build linux && arm64

package main

// platform_signals_arm64.go — arm64 wait4 signal-stop handler.
//
// Phase 3b's authoritative delivery path lives on amd64 only (see
// ADR 001 §2: the arm64 rt_sigreturn trampoline is in the vDSO, which
// the Sentry doesn't parse yet). arm64 therefore keeps Phase 3a
// routing: consult the Sentry mirror, decide forward vs. swallow, and
// let the kernel do the actual delivery when we forward.

import (
	"fmt"
	"syscall"
)

// handleSignalStop on arm64 mirrors the Phase 3a behavior that lived
// inline in interceptLoop before commit 3 existed. It returns
// (code, terminated, err) so the main loop can bail out if the tracee
// died during the forward-and-wait cycle.
func (p *PtracePlatform) handleSignalStop(pid int, sig syscall.Signal) (int, bool, error) {
	act := p.sentry.signals.GetAction(int(sig))
	forward := true
	var reason string
	switch act.handler {
	case sigIGN:
		forward = false
		reason = "SIG_IGN"
		p.sentry.signals.countIgnored(int(sig))
	case sigDFL:
		reason = "SIG_DFL"
	default:
		reason = fmt.Sprintf("handler=0x%x", act.handler)
	}
	if forward {
		p.sentry.signals.countDelivered(int(sig))
	}
	decision := "swallow"
	if forward {
		decision = "forward"
	}
	_, _ = fmt.Fprintf(logWriter(),
		"  [platform] signal-stop %s (%d) → %s (%s)\n",
		signalName(int(sig)), int(sig), decision, reason)
	if !forward {
		return 0, false, nil
	}
	if err := ptraceSysemu(pid, int(sig)); err != nil {
		return -1, false, fmt.Errorf("signal forward failed: %w", err)
	}
	var ws2 syscall.WaitStatus
	_, _ = syscall.Wait4(pid, &ws2, 0, nil)
	if ws2.Exited() {
		return ws2.ExitStatus(), true, nil
	}
	if ws2.Signaled() {
		return 128 + int(ws2.Signal()), true, nil
	}
	return 0, false, nil
}
