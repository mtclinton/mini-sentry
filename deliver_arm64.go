//go:build linux && arm64

package main

// deliver_arm64.go — arm64 stub for the pending-queue drain.
//
// Phase 3b's authoritative delivery lives on amd64 only (ADR 001 §2).
// sendSelfSignal still enqueues cross-arch — that's how the fd-leak
// cleanup from Phase 3a's syscall.Kill fast path gets removed — but
// arm64 falls back to kernel-delivered semantics: for each pending
// entry we issue a host kill(2), and the kernel's own
// signal-delivery path builds the frame and runs the handler. The
// wait4 signal-stop branch on arm64 (platform_signals_arm64.go)
// still forwards external signals via ptraceSysemu(pid, sig), so the
// only queue entries on arm64 are self-generated kill/tkill/tgkills.

import (
	"fmt"
	"syscall"
)

// deliveryResult mirrors the amd64 shape so platform.go can be
// arch-generic. arm64 never terminates the tracee through this path —
// the kernel decides what to do with a kill() — so terminate stays 0.
type deliveryResult struct {
	terminate int
}

// deliverPending drains the pending queue by issuing a real host
// kill(2) per signal. The kernel then builds the frame and runs the
// handler on the tracee's next resume. Unblocked-only dequeue keeps
// the mask check point consistent with amd64.
func (p *PtracePlatform) deliverPending(pid int) (deliveryResult, error) {
	ts := p.sentry.signals.FindThread(pid)
	if ts == nil {
		ts = p.sentry.signals.ThreadState
	}
	for {
		sig, ok := ts.DequeueUnblocked()
		if !ok {
			return deliveryResult{}, nil
		}
		if err := syscall.Kill(pid, syscall.Signal(sig.signo)); err != nil {
			return deliveryResult{}, fmt.Errorf(
				"arm64 deliverPending kill(%d, %d): %w",
				pid, sig.signo, err)
		}
		p.sentry.signals.countDelivered(sig.signo)
	}
}
