# ADR 001: Phase 3b — Authoritative Signal Delivery

- Status: **Proposed** (awaiting review)
- Date: 2026-04-16
- Deciders: Max Clinton
- Supersedes: Phase 3a design (commits f31e299..3e0a3de)

## Context

Phase 3a put a signal *mirror* next to the host kernel. `rt_sigaction`
and `rt_sigprocmask` update `SignalState` and then passthrough, so the
kernel still actually installs the handler and still enforces the
mask. `kill`/`tkill`/`tgkill` with a self-target are short-circuited
in the Sentry — we send via `syscall.Kill` to the tracee's real PID —
but every other signal, including the actual handler invocation, is
built and delivered by the kernel.

This was deliberate: it bought us observability (we log every handler
installation) and a clean routing hook in the platform wait loop (we
see every signal-stop and can decide to forward or swallow before the
kernel delivers). What it did *not* buy us is control. The Sentry is a
passive spectator of the kernel's delivery path. If the kernel ever
stopped cooperating — a seccomp filter that rejects `rt_sigaction`, a
future platform where we can't register host handlers on behalf of the
tracee, or simply a desire to understand how a real kernel *builds*
the frame — we'd be stuck.

Phase 3b removes the passthrough and makes the Sentry authoritative
for signal *delivery*. The mirror stops being advisory and becomes the
source of truth: we construct the `rt_sigframe` ourselves, write it to
the tracee's stack with `process_vm_writev`, redirect the tracee's RIP
to the handler, and emulate `rt_sigreturn` so control comes back to
us. The project gains the piece of the gVisor-like architecture that
was most conspicuously absent — the Sentry as a faithful emulator of
kernel delivery semantics, tested against a kernel-generated oracle.

This ADR records the scope, the design trade-offs, and — most
importantly — the testing strategy. Without the golden-file harness
described in §5, Phase 3b is implement-by-reading-docs, which is how
sigframe bugs historically get shipped and stay shipped.

## Decision

Implement fully authoritative signal delivery for mini-sentry on amd64
only. Construct `rt_sigframe` in Go, deliver via ptrace, emulate
`rt_sigreturn`, enforce the signal mask in the Sentry. Scope the flag
matrix tightly and validate the frame byte-for-byte against a
captured kernel reference.

## Reasoning

### 1. Scope boundary: fully authoritative, not hybrid

Two directions were considered. The *hybrid* option keeps Phase 3a's
passthrough for `rt_sigaction`/`rt_sigprocmask` and only adds a Sentry
emulation of `rt_sigreturn`. The *full* option flips everything: the
Sentry builds frames, enforces the mask, decides what to deliver, and
the kernel is no longer in the loop at all.

The hybrid option is worse than it sounds. `rt_sigreturn` on its own
is trivial — it's a register restore, forty lines of code. It only
has value if *someone* built the frame it's unwinding, and if that
someone is still the kernel then the Sentry's `rt_sigreturn` has to
accept a frame format it didn't produce and doesn't own. We'd write a
decoder for the kernel's layout, find that the fields we care about
are already restored before our handler runs (because the kernel's
delivery path set them), and discover that our emulation is doing
nothing the kernel wasn't already doing. The educational yield is
zero, and the control we gain is zero.

The full option is expensive — frame construction is the hard part of
signal delivery, and the kernel gets it right because it's been doing
it since 1994 — but it's the only version where the Sentry actually
knows what a signal *is* in the kernel-ABI sense. Rejecting hybrid
costs us a few weeks of engineering and forces us to stare at the
AMD64 psABI until we understand it. That's exactly the kind of cost
this project exists to pay.

One important concession: we keep passthrough for `rt_sigaction`
itself. The kernel needs to know about handlers for *synchronous*
signals (SIGSEGV from a real page fault on the tracee, SIGBUS from a
misaligned load) because those signals originate inside the tracee's
execution and the kernel delivers them before the Sentry is ever
consulted. If we stopped calling the real `rt_sigaction`, the tracee
would die silently on its first nil deref. So the Sentry mirror stays
authoritative *in parallel* with the kernel's copy. The decision the
Sentry takes over in 3b is *delivery*, not *registration*.

### 2. Frame layout

On amd64 the kernel writes, from high address down: the siginfo
(128 bytes), then the ucontext (512 bytes including an embedded
`struct _fpstate`), then — if `SA_SIGINFO` is off — an integer
frame instead, which we don't support. Below the ucontext sits an
8-byte slot holding the return address, which is the `sa_restorer`
pointer from the sigaction. The handler sees `(int signo, siginfo_t*,
void*)` in RDI, RSI, RDX and returns into the restorer, which is
libc's `__restore_rt` calling syscall 15.

We populate the integer general-purpose registers faithfully from
`PTRACE_GETREGS`: R8–R15, RDI, RSI, RBP, RBX, RDX, RAX, RCX, RSP, RIP,
and EFLAGS. We zero the segment registers (CS, GS, FS, SS) — the
kernel writes them too but userspace never inspects them on modern
x86-64. We zero Err, Trapno, and CR2 for asynchronous signals; for a
forwarded SIGSEGV we'd populate Cr2 with the fault address, but Phase
3b only delivers *generated* signals (via kill/tkill), so this path
doesn't arise. We zero Oldmask (deprecated; the ucontext's Sigset is
what restore reads anyway).

The floating-point state is the largest single field (512 bytes of
FXSAVE, optionally extended by XSAVE to 2 KiB+). The initial draft of
this ADR proposed zero-filling the fpstate slot on the reasoning that
"most handlers don't touch FP." That reasoning is wrong for
mini-sentry specifically.

Go's runtime installs a preemption handler on SIGURG — which Test 7
already exercises end-to-end — and the runtime's signal-entry and
signal-exit paths read and write xmm registers through the
`ucontext_t`'s fpstate on every invocation. If we zero the fpstate
target, the first `rt_sigreturn` restores xmm0..xmm15 as zero and
corrupts whatever the tracee was computing. This does not crash
immediately; it produces non-deterministic float drift, which is the
worst class of bug to debug because it shows up far from its cause
and is invisible to integer-only tests. Any guest written in Go, any
guest using a libc that stores TLS canaries in xmm, or any handler
that happens to take an FP branch via inlined memcpy (glibc
occasionally uses SSE for large copies inside handlers) will hit it.

**Decision: populate the 512-byte FXSAVE area from
`PTRACE_GETFPREGS`.** This is the older, simpler ioctl — one
syscall, fixed-size buffer, no XSAVE header, no XCR0 discovery, no
variable-length extended state. The 512-byte layout matches
`struct _fpstate` at the head of the kernel's fpstate exactly, which
is the only part of the frame that `rt_sigreturn` restores on CPUs
without `_UC_FP_XSTATE` set in the ucontext Flags. We clear the
`_UC_FP_XSTATE` bit so the kernel doesn't try to consume an XSAVE
magic trailer we didn't write.

AVX/AVX-512 state beyond the FXSAVE area is silently not preserved
across signal delivery in this scheme. This is a real limitation — a
SIGURG that lands while the tracee is holding ymm0 will restore with
only xmm0's low 128 bits intact — but it's a limitation the tracee
would only notice if it were actively vectorising across the signal
boundary, which neither Go's runtime preemption nor our test guest
does. Upgrade to `PTRACE_GETREGSET(NT_X86_XSTATE)` is deferred to
Phase 3c and tracked as a separate concern. The corresponding test
lives alongside the frame-builder commit: install a SIGURG handler,
store a known pattern in xmm0 in the non-handler context, raise the
signal, verify xmm0 is unchanged on return.

On arm64 the frame is an `rt_sigframe` containing a 128-byte siginfo
and a `struct ucontext` whose `mcontext` holds 31 x-registers plus SP,
PC, PSTATE, plus a tail of variable-length "reserved" records —
FPSIMD context (528 bytes) being the most important, followed by ESR
and optional SVE. The arm64 restorer is not `sa_restorer`: the
`struct kernel_sigaction` on arm64 has no restorer field (see
`regs_arm64.go`), and the kernel instead jumps to
`__kernel_rt_sigreturn` inside the vDSO. To deliver a signal on arm64
we'd need to find the vDSO base in the tracee (read
`/proc/<pid>/auxv` for `AT_SYSINFO_EHDR`, parse the ELF to locate the
symbol) and write that address into the link register. None of that
infrastructure exists. **Phase 3b is amd64-only.** arm64 waits for
Phase 3c and gets its own ADR.

### 3. Mask enforcement point

Three places can plausibly consult the mask: `HandleSyscall` (before
dispatching a syscall that might synthesize a signal), the platform
wait loop (before forwarding a host-delivered signal), or both. We
pick **both, with the mask check pushed all the way to the delivery
boundary.**

The rule is: queue on generation, check mask on delivery. When
`sysKill` decides to raise SIGURG on the tracee, it appends the
signal to a per-task pending queue on `SignalState` and returns 0.
The actual frame construction and handler entry happen at the next
safe resume point — not inside `HandleSyscall`, because delivering a
signal *during* a syscall handler means tearing down the syscall
frame and executing on a transformed stack, and that ordering is
fragile. Instead, `HandleSyscall` finishes, the platform loop
observes pending signals, checks the mask, and delivers any unblocked
signal before calling `ptraceSysemu` again.

**The platform loop needs a concrete new hook for this, and the hook
is the most-forgettable piece of Phase 3b.** Today the loop wakes
up on `wait4` signal-stops (where it already consults the mirror in
3a) and on PTRACE_SYSEMU syscall-entry stops (where it calls
`handleSyscallStop`). Neither of those is the right moment to drain
pending signals we generated ourselves — by the time `wait4` returns
a signal-stop, the signal has already been delivered to the tracee
by the kernel, and by the time we enter a new syscall-entry stop,
the tracee has already executed any userspace code between the
previous syscall's exit and the next syscall's entry, which is
precisely where a preemption signal should have fired.

Phase 3b adds a post-dispatch check: immediately after every
`HandleSyscall` return and *before* the next `ptraceSysemu(pid, 0)`
call, inspect the pending queue. If it's non-empty, drain unblocked
entries against the current mask, construct their frames, and
redirect the tracee's RIP to the handler. Only once the queue is
drained (or everything remaining is blocked) do we resume. This
means **commit 3 — pending queue + mask enforcement — must touch
`platform.go`'s `handleSyscallStop` tail, not just
`signals.go`.** The ADR calls this out explicitly so the commit
doesn't ship with the queue plumbed but never consulted.

The platform-loop check on the `wait4` signal-stop path stays in
place and moves from "consult mirror, decide forward/swallow" to
"enqueue into pending, let the post-dispatch hook drain." The two
call sites converge on the same pending queue and the same delivery
routine.

This keeps the invariant the rest of the code assumes: the Sentry's
view of "am I inside a syscall" is binary. A signal never preempts a
handler mid-execution. Synchronous signals that *logically* belong to
the syscall (write → SIGPIPE when the reader has closed the pipe)
behave correctly because the handler returns `-EPIPE` first, then the
platform loop observes the pending SIGPIPE and delivers it against
the mask that was in effect at syscall entry — no mask-churn window
exists.

External signals — an alarm from the host, a SIGWINCH from a
terminal, anything we didn't generate ourselves — enter through the
same `wait4` signal-stop path, are enqueued identically, and drain
through the same post-dispatch hook. Nothing in the delivery code
cares about origin once the signal is on the queue.

### 4. Flag support matrix

| Flag            | Phase 3b | Rationale                                               |
|-----------------|----------|---------------------------------------------------------|
| `SA_SIGINFO`    | Yes      | Required. We write siginfo unconditionally; the flag    |
|                 |          | selects the handler calling convention (3-arg vs 1-arg).|
| `SA_RESTART`    | Yes      | Honored in spirit — logged and recorded on the mirror.  |
|                 |          | Phase 3b has no blocking syscalls, so no syscall is     |
|                 |          | ever actually restarted. Plumbing lands now so the      |
|                 |          | moment we grow `read`-from-a-pipe it works.             |
| `SA_NODEFER`    | Yes      | One-line change: don't auto-add signo to the mask when  |
|                 |          | entering the handler.                                   |
| `SA_RESETHAND`  | Yes      | After delivery, flip the stored disposition to SIG_DFL. |
|                 |          | Trivial; needed for `signal(2)` compatibility.          |
| `SA_ONSTACK`    | Punt 3c  | Requires `sigaltstack(2)` emulation and a pre-faulted   |
|                 |          | alt-stack; handlers in 3b always run on the main stack. |
| `SA_NOCLDSTOP`  | Out      | No clone, no children.                                  |
| `SA_NOCLDWAIT`  | Out      | Same.                                                   |

The MVP line is "everything that costs <20 lines and doesn't require
a new syscall." `SA_ONSTACK` fails both clauses: we need sigaltstack
infrastructure and we need to fault in a stack before delivery. 3c.
`SA_NOCLD*` flags are permanently out of scope until and unless
mini-sentry grows process creation, which is not on the roadmap.

### 5. Testing strategy: golden-file sigframe oracle

**This is the section that makes or breaks Phase 3b.** Without a way
to compare our frame against a real kernel frame, we're implementing
against `man 2 sigaction` and the kernel source, and every bug will
have the structure "we zeroed a field the kernel populates, and the
handler crashed two instructions later with a register value we can't
relate to anything." With a byte-exact oracle, the failure mode is "we
mismatched byte 72; here it is; the kernel wrote 0x0002, we wrote 0."

The harness is feasible and it's cheap. Sketch:

```c
// testdata/sigframe_capture/main.c
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned char frame_copy[1024];
static size_t frame_size;

static void handler(int signo, siginfo_t *si, void *uc) {
    // The kernel lays the frame out (high → low): ucontext,
    // siginfo, 8-byte return-address slot holding the restorer
    // pointer. RSP on handler entry points at that return-address
    // slot — `si` is 8 bytes *above* it. Back up 8 so the capture
    // includes the restorer slot; it's part of the frame and part
    // of what our builder has to emit.
    unsigned char *frame_bottom = (unsigned char *)si - 8;
    frame_size = 1024 + 8;
    memcpy(frame_copy, frame_bottom, frame_size);
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    // After handler returns, dump captured bytes to stderr as hex.
    for (size_t i = 0; i < frame_size; i++)
        fprintf(stderr, "%02x", frame_copy[i]);
    fputc('\n', stderr);
    return 0;
}
```

Build static, run *outside* mini-sentry, capture stderr as
`testdata/sigframe_amd64_sigusr1.hex`. That's the oracle. Then in
`frame_test.go`:

```go
func TestBuildRtSigframeMatchesKernel(t *testing.T) {
    oracle := loadHex(t, "testdata/sigframe_amd64_sigusr1.hex")
    regs := fakeRegs()       // matches the state the C program was in
    info := fakeSiginfo(SIGUSR1)
    got := BuildRtSigframe(regs, info, sigset(0), /*altstack=*/nil)

    diff := diffMasked(oracle, got, maskedFields{
        // RSP and return address depend on where the kernel placed the
        // frame and where the libc restorer ended up in memory; they
        // drift run-to-run even in the oracle. Everything else should
        // be identical.
        rspOffset, restorerOffset, fpstatePointerOffset,
    })
    if diff != "" {
        t.Fatalf("frame diverges from kernel oracle:\n%s", diff)
    }
}
```

The masked-field list is short and each entry has a reason. RSP is
where-we-put-the-frame, not a semantic difference. The restorer
pointer is libc's copy of `__restore_rt`, which we don't have a fixed
value for. The fpstate pointer is a self-reference back into the
frame — its *target* is what matters, and that's a separate assertion.

Capture once on the primary dev host (maxbox amd64), check in the hex
file, and let CI diff against it forever. If glibc updates change the
restorer ABI someday, the test tells us exactly which byte moved, and
we decide whether to resync or complain.

Fallback if byte-exact capture proves flaky (e.g., across kernel
versions the padding shifts, which happens roughly never on amd64 but
is conceivable): differential testing. Two binaries raising the same
signal, one under the kernel and one under mini-sentry, both with a
handler that memcpys its `ucontext_t` to stderr. Diff the
transcripts. Less strict than byte-exact, but catches the same class
of bugs.

## Non-goals

- **Signals for child processes.** mini-sentry does not `clone`; there
  are no children to receive SIGCHLD. SIGCHLD flags are wired through
  the mirror but never fire.
- **Realtime-signal queuing.** SIGRTMIN..SIGRTMAX are accepted by the
  mask/action APIs but delivered at most once if pending (same as a
  standard signal). Real realtime queuing is Phase 3c.
- **`signalfd(2)` / `sigwaitinfo(2)`.** Not implemented. `sigwait` on
  a blocked signal returns EINVAL until we grow a pending-signal
  wait primitive.
- **Multi-thread signal routing.** One tracee, one task. The gVisor
  concept of "signal belongs to thread group vs a specific thread"
  collapses to "deliver to the one task we have."
- **arm64 delivery.** Frame construction and vDSO restorer lookup are
  arm64-specific work; they get their own phase.
- **`SA_ONSTACK` / `sigaltstack(2)`.** Requires stack provisioning
  that doesn't belong in Phase 3b.

## Rollback plan

Phase 3b lands as four focused commits on top of 3a:

1. `signals: add RtSigframe builder (amd64 only, no FP)`
2. `signals: intercept rt_sigreturn, restore regs from frame`
3. `signals: pending queue, mask enforcement at delivery`
4. `signals: honor SA_SIGINFO / SA_NODEFER / SA_RESETHAND`

Reverting all four with `git revert` (no rebase) returns the tree to
3a. The 3a mirror stays in place and keeps working, because the
mirror was designed to be harmless when the kernel is authoritative.
`rt_sigaction` stays passthrough throughout 3b — we never remove it
— so rolling back doesn't leave the tracee without handlers.

If only one commit goes sideways (say, the frame builder has a
latent FP bug that shows up only on newer CPUs), we can revert that
commit in isolation. The frame builder is the only commit that
touches the `rt_sigframe` wire format; `rt_sigreturn` reads whatever
the builder wrote, so if the builder goes, sigreturn goes with it
and we're back to 3a's kernel-built frames being unwound by the
kernel's own restorer. No partial-state hazard.

The single risky edge case is the pending-queue commit: if we enqueue
a signal but the delivery path has a bug that drops it, the signal is
silently lost. Mitigation: the queue landing includes a test that
enqueues, asserts pending count, triggers delivery, asserts queue
empty and handler ran.

## Estimated size

Rough LOC projection, expecting ±30% reality:

| Commit                                 | Code | Tests |
|----------------------------------------|------|-------|
| Frame builder (amd64)                  | ~180 | ~150  |
| `rt_sigreturn` handler + dispatch hook | ~100 | ~80   |
| Pending queue + mask enforcement       | ~160 | ~120  |
| Flag support (SIGINFO/NODEFER/RESETH)  | ~90  | ~80   |
| **Total**                              | **~530** | **~430** |

Plus `testdata/sigframe_capture/main.c` (~40 lines) and
`testdata/sigframe_amd64_sigusr1.hex` (one line of hex, ~2 KiB).

Four commits over roughly two focused sessions. None individually
rises above the 300-line new-file cap. The golden-file harness is
bought up-front with the frame builder because without it every
subsequent commit is flying blind.

## Open questions for review

1. Is amd64-only acceptable for Phase 3b, or should arm64 land at the
   same time? The cost of arm64 is roughly another full Phase 3b.
2. Is FXSAVE-only (no XSAVE / AVX) an acceptable floor for 3b? The FP
   hazard that motivated PTRACE_GETFPREGS only resurfaces for AVX/
   AVX-512 tracees, which nothing in the current test matrix
   exercises — but a future Go update that preempts while holding ymm
   state would regress silently. Alternative: block 3b on full
   XSAVE support.
3. Does the byte-exact golden-file strategy carry political risk (a
   glibc update could in principle shift the restorer offset and
   break CI) that we should pre-empt with the differential-testing
   fallback from day one?
4. The post-dispatch pending-queue hook (§3) is a behavioural change
   to `handleSyscallStop`'s tail that touches every syscall path, not
   just the signal-generating ones. Worth a separate commit between
   the frame builder and the queue, or OK to land as part of commit
   3 as proposed?
