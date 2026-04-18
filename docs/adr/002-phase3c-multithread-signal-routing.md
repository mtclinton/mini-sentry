# ADR 002: Phase 3c — Multi-Thread Signal Routing

- Status: **Accepted**
- Date: 2026-04-17
- Deciders: Max Clinton
- Relates to: ADR 001 (Phase 3b authoritative signal delivery)

## Context

Phase 3a/3b/3c.1 all assume a single tracee task. Under `PtracePlatform`
we attach to one pid, we track one `SignalState`, and the platform loop
calls `ptraceSysemu(pid, …)` and `wait4(pid, …)` with that single pid
in both slots. The non-goals list in ADR 001 §"Non-goals" called this
out: *"One tracee, one task. The gVisor concept of 'signal belongs to
thread group vs a specific thread' collapses to 'deliver to the one
task we have.'"* That concession was honest but it cost us a live test.

Test 7 in `cmd/guest/main.go` was meant to prove end-to-end signal
delivery: install a real SIGUSR1 handler, `kill(self, SIGUSR1)`, watch
the handler run. It doesn't. The `os/signal.Notify` version of it
timed out during Phase 3b commit 4 integration, and the test was
pinned to `SIG_IGN` as a stopgap. The root cause is structural, not a
bug:

1. Go's runtime installs every signal handler with `SA_SIGINFO |
   SA_ONSTACK` on *every* OS thread it creates, and routes observed
   signals through a dedicated `gsignal` goroutine per M. A raw
   `kill(tgid, SIGUSR1)` enters the kernel, which picks *some* thread
   in the thread group with the signal unblocked to deliver to. Under
   `os/signal.Notify` the receiving thread is a Go worker, not the
   main goroutine's thread — by design, because the main goroutine
   might be in a syscall or a cgo call that can't take signals.
2. `PtracePlatform` only attaches to the tracee's initial thread. The
   worker threads Go creates via `clone(CLONE_THREAD)` exit our view
   the moment they're born — they execute real, un-intercepted
   syscalls, and any signal the kernel routes to them runs outside
   the Sentry. The traced main thread has its own mask and its own
   pending queue, and the kernel's routing choice has no way to land
   on us when another thread is a better candidate (for
   `os/signal.Notify`, always).
3. The only reason the Phase 3b stability loop passes at all is that
   the test guest is effectively sequential — Go stays on one M
   until it has reason to park. Introducing a signal handler breaks
   that assumption, because signal handling itself is the mechanism
   Go uses to switch Ms for preemption.

Test 7's `SIG_IGN` workaround hides the problem: `SIG_IGN` short-
circuits in our `deliverPending` drain before we'd ever try to build a
frame, and the drain only fires for the traced main thread, so a
missed routing decision is invisible. A real handler exposes it
immediately.

Phase 3c commit 2 makes the Sentry trace every thread in the group,
splits `SignalState` along the same seam gVisor does (per-Task vs per-
ThreadGroup), and routes generated/observed signals to the correct
per-thread pending queue. The mirror that was authoritative for
delivery in Phase 3b becomes authoritative for *routing* here.

This ADR records the scope, the gVisor split we're mirroring, and the
platform-loop restructuring. The restructuring is the most dangerous
piece — `interceptLoop` today hardcodes a pid into every ptrace call
and every `Wait4`, and every test in `handlers_test.go` passes a single
pid into `HandleSyscall`. Any half-landed version of this change has
threads running un-traced. The commit plan in §6 is designed so the
tree is never in that state.

## Decision

Implement per-thread signal routing for mini-sentry on amd64 (arm64
inherits the machinery but is gated until arm64 delivery lands in a
follow-up). Attach every thread via `PTRACE_O_TRACECLONE`, split
`SignalState` into a per-thread half and a shared-by-thread-group
half, route `kill`/`tkill`/`tgkill` into the correct per-thread
pending queue, and fix Test 7 to use a real handler as the
end-to-end proof.

## Reasoning

### 1. Mirror the gVisor Task / ThreadGroup split

gVisor's Sentry already answers every design question here. The
relevant facts, confirmed against the vendored gVisor tree under
`../gvisor`:

| State                     | Scope         | gVisor location                                 |
|---------------------------|---------------|-------------------------------------------------|
| sigaction table           | ThreadGroup   | `ThreadGroup.signalHandlers.actions` (signal_handlers.go:31) |
| Signal mask               | **Task**      | `Task.signalMask` (task.go:157)                 |
| Pending queue (targeted)  | **Task**      | `Task.pendingSignals` (task.go:148)             |
| Pending queue (group)     | ThreadGroup   | `ThreadGroup.pendingSignals` (thread_group.go:74) |
| sigaltstack               | **Task**      | `Task.signalStack` (task.go:180)                |
| Routing predicate         | per-Task read | `canReceiveSignalLocked` (task_signals.go:524)  |
| Group-signal receiver     | —             | `findSignalReceiverLocked` (task_signals.go:550)|

**Decision: mirror this split byte-for-byte in mini-sentry.** Rename
the existing `SignalState` into two cooperating structs:

- `ThreadGroup` (new): `actions [nSig]SigAction`, group pending
  queue, shared counters, single `sync.Mutex`.
- `ThreadState` (new, per-tid): `mask sigset`, pending queue,
  `altStack StackT`, a pointer back to the `ThreadGroup`.

This isn't cosmetic. Every routing decision in Phase 3c reads the
mask of a specific thread and writes to a specific thread's pending
queue; a monolithic `SignalState` can't serve that. The split also
pre-pays the cost for any future feature that needs it —
`thread_self_signalfd`, `tgkill` with a non-self target, `ptrace`
attachment emulation — because those are all keyed on a specific tid.

One concrete downgrade: `ss.SetAction` in Phase 3b bumps a shared
`installed[signum]` counter. That counter now lives on `ThreadGroup`
(shared across threads) while the pending queue moves to
`ThreadState`. Callers that used to say `s.signals.Enqueue(...)` on a
blob-wide `SignalState` now say `tg.Thread(tid).Enqueue(...)` or
`tg.EnqueueGroup(...)` depending on whether the signal is targeted or
group-wide. That renaming is commit 2's job.

### 2. Attach all threads via PTRACE_O_TRACECLONE

`PTRACE_O_TRACECLONE` causes the kernel to fire `PTRACE_EVENT_CLONE`
whenever the tracee calls `clone(2)`. The event reports the new tid
via `PTRACE_GETEVENTMSG`. The new thread is automatically traced by
the same tracer (us), arrives in the wait queue stopped at
`PTRACE_EVENT_STOP` with `SIGSTOP`, and inherits our ptrace options
— so `TRACESYSGOOD`/`TRACEEXEC`/`TRACEEXIT`/`TRACECLONE` all carry
over to the child without a second `PtraceSetOptions` call.

**Decision: set `PTRACE_O_TRACECLONE` in the post-exec options block
alongside the three flags we already set.** On the clone-event path,
drain `GETEVENTMSG` to get the new tid, register a fresh
`ThreadState` on the thread group, and PTRACE_CONT the new thread so
it continues with our options inherited. The platform loop's existing
`Wait4` already handles multiple pids (passing -1 returns any
child's status, and the returned pid tells us which thread the event
is for) — we just need to stop hardcoding `pid` into that slot.

**Deliberately out of scope: `fork(2)` / `vfork(2)`.** The
`PTRACE_O_TRACEFORK`/`TRACEVFORK` options exist but mini-sentry has
no story for multi-process guests. If we ever see a clone without
`CLONE_THREAD` we log it and kill the tracee — the same posture
every other unhandled CLONE_* would take. ADR 003 will revisit
process creation when there's a reason to.

### 3. Routing: kill, tkill, tgkill

With the Task/ThreadGroup split in place, routing falls out of the
gVisor semantics:

- **`tkill(tid, sig)`** — the tid is specific. Enqueue on
  `ThreadGroup.Thread(tid).pending`. If `tid` doesn't resolve to a
  traced thread, return `ESRCH` (kernel-accurate).
- **`kill(tgid, sig)`** — thread-group-wide. Enqueue on
  `ThreadGroup.pending`. At drain time,
  `findSignalReceiverLocked` scans the thread list and picks the
  first thread whose mask doesn't block the signal. The group queue
  feeds that thread's drain path; the thread's own queue is
  consulted first so targeted signals don't starve.
- **`tgkill(tgid, tid, sig)`** — same as `tkill` with a tgid
  validation. Since mini-sentry's guest always sees `tgid=1`, the
  check is cheap.

The "first eligible thread" algorithm is what gVisor uses
(`findSignalReceiverLocked`, task_signals.go:550-557). It's not
load-balanced — gVisor explicitly chose not to be — and the kernel
isn't either, so we inherit the familiar userspace semantics.

**Iteration order: deterministic.** gVisor iterates its thread map,
which in Go is intentionally randomized. mini-sentry keeps
`ThreadGroup.threads` as a slice ordered by attach-time (main thread
first, then each clone in arrival order). Determinism costs nothing
at the scales we care about (< 64 threads per guest, realistically),
buys reproducible tests, and makes routing bugs reproduce on the
first attempt instead of the fiftieth. If we ever need randomized
distribution we add a shuffle step; the inverse — recovering
determinism from a random base — is harder.

**ThreadState lifecycle: remove on exit.** Observed
`PTRACE_EVENT_EXIT` unregisters the thread from
`ThreadGroup.threads`. Alternative was to flag exited entries and
skip them in `findSignalReceiverLocked`, but that leaves a growing
graveyard of dead entries for long-running guests and forces every
routing call site to remember the skip. Remove-on-exit matches
gVisor (`ThreadGroup.tasks` is a live set) and keeps routing
branchless.

One place this differs from Phase 3b: `sendSelfSignal` today passes
`pid` as the one tracee pid. In multi-thread world it has to become
"pass the *tgid* and let the drain pick a thread." The call site
sequence is `sysKill` → `sendSelfSignal` → `tg.EnqueueGroup(signo)`,
with `sendSelfSignal` no longer needing the tracee pid at all. The
drain figures out which thread's stack to build the frame on.

### 4. Platform loop restructuring

The `interceptLoop` body today reads roughly:

```
for { drain(pid); sysemu(pid); wait4(pid); dispatch… }
```

That loop has to become:

```
for {
    drainAll()              // visit every thread's drain
    sysemu(activeTid)        // resume the thread we last stopped
    pid, ws := wait4(-1)     // any child
    dispatch(pid, ws)        // route by pid
}
```

Three follow-on consequences:

1. **Resume bookkeeping.** PTRACE_SYSEMU only resumes *one* thread.
   Today we know it's the only thread. In multi-thread world the
   loop has to remember which thread it last stopped and resume that
   one specifically. A naive "resume whatever we stopped last" works
   because the kernel stops one thread at a time in ptrace, but the
   code has to track it explicitly.

2. **Per-thread drain ordering.** `deliverPending` today loops until
   empty or blocked. With per-thread queues we have to decide:
   drain-all-threads-before-resume, or drain-on-observation?
   Draining *all* threads before every resume is cleaner (no
   accidentally-leaked pending signals) but also inefficient
   (O(threads) work per wait cycle). Phase 3c takes the simple path
   — drain every thread in the ready-to-run state before every
   resume — and defers the optimization to a follow-up if it
   measures as a problem.

3. **Handler lookup.** `HandleSyscall` today takes `pid int` as its
   only identifier. The tid now matters for every mask-related
   decision (self-kill masking, sigreturn's mask restore,
   sigaltstack lookup). **Decision: grow `HandleSyscall`'s signature
   to `(tgid, tid int, sc SyscallArgs)`.** All callers are in
   `platform.go`'s loop and the seccomp platform, both of which know
   both values. Tests that pass `pid` have to be updated; there is
   no guest-visible API affected. Because this signature change
   touches ~50 call sites across `handlers.go`, handler tests, and
   both platforms, **it ships as a prep commit (commit 0) before
   the ThreadGroup/ThreadState scaffolding lands** — see §6. That
   keeps commit 1's diff readable and makes any bisect over the
   routing work skip the mechanical rename noise.

### 5. Testing strategy

Unlike ADR 001 §5, this ADR does *not* need a byte-exact oracle.
Routing is a behavioral property — it's either right or the handler
doesn't run — and the test is end-to-end:

1. **Test 7 rewrite (the proof).** Install a real SIGUSR1 handler
   via raw `rt_sigaction` (same raw-syscall path `installSigIgn`
   already uses), `kill(self, SIGUSR1)`, `sigsuspend` on an empty
   mask to block for delivery, assert a handler-side counter
   incremented. Raw syscalls are the durable test vehicle — they
   exercise exactly the primitive this ADR ships and don't depend
   on Go runtime internals that might shift version-to-version. An
   `os/signal.Notify` variant can come later as a bonus test once
   the primitives are solid; it's the realistic-program shape but
   not what this ADR is *about*.

2. **Per-thread mask.** Unit test: two `ThreadState` instances in
   one `ThreadGroup`, thread A blocks SIGUSR1, thread B doesn't.
   `EnqueueGroup(SIGUSR1)` must dequeue onto thread B's queue when
   drained, not thread A's.

3. **Targeted vs group precedence.** Queue SIGUSR1 on both the
   group queue and thread A's queue. The group entry must dequeue
   for a *different* thread than A, or block behind A's queue if no
   other thread is eligible. This pins the "own queue first, group
   second" invariant.

4. **Thread lifecycle.** Integration test: guest spawns 4
   goroutines, each calls `kill(self, SIGUSR1)` with its own
   per-thread handler. Assert all 4 deliveries land on the correct
   thread. This is the stress test for `PTRACE_O_TRACECLONE`
   attach-and-option-inheritance; if we miss a thread the test
   hangs.

5. **Thread exit.** `ThreadState` entries are removed from
   `ThreadGroup.threads` when `PTRACE_EVENT_EXIT` fires for that
   tid (see §3 — remove-on-exit). Unit test: register a
   `ThreadState`, fire the removal, assert the group's thread list
   shrank and subsequent routing can't land on the stale tid.

6. **Seccomp parity.** The seccomp platform (`platform_seccomp.go`)
   has no ptrace relationship, so `TRACECLONE` is irrelevant there.
   But the `ThreadGroup` split still has to compile and the drain
   still has to function with a single thread. Regression test:
   run the stability loop under seccomp, assert no behavioral
   change.

### 6. Commit plan

Five focused commits on top of the current Phase 3c commit 1 tip.
Commit 0 is pure mechanical prep so the four substantive commits
ship with clean diffs:

0. **`handlers: thread tid/tgid through HandleSyscall`** — grow the
   signature to `(tgid, tid int, sc SyscallArgs)` across
   `sentry.go`, `handlers.go`, `handlers_signals_amd64.go`, both
   platform call sites, and the handler test suite. Every new
   parameter is unused inside handler bodies — the shape change is
   the whole point. Zero behavioral change; existing tests pass
   unmodified.

1. **`signals: add ThreadGroup/ThreadState scaffolding (no routing)`**
   — introduce the two structs, populate from `SignalState`, keep
   every public method working through shim wrappers that route to a
   single implicit thread. Existing tests still pass unmodified.

2. **`platform: TRACECLONE + per-thread attach`** — set the option,
   handle `PTRACE_EVENT_CLONE`, register new `ThreadState`s, switch
   `Wait4` slot to `-1`. No routing changes yet; the group still
   has one eligible thread unless the guest itself clones, which our
   current test guest doesn't.

3. **`signals: per-thread routing (kill/tkill/tgkill/drain)`** —
   split the pending queues, wire `findSignalReceiverLocked` over
   the deterministic slice, remove-on-exit, remove the single-
   implicit-thread shims from commit 1. This is the commit where
   Test 7 flips from `SIG_IGN` to a real handler.

4. **`guest: Test 7 real handler + Test 9 multi-thread stress`** —
   add the integration tests from §5 items 1 and 4. Keeps the docs
   sample aligned with the ADR.

Reverting any prefix returns the tree to a working single-thread
state. The riskiest commit is 3 because it rewires every signal
call site; commit 2 is designed as the "attach works but nothing
routes yet" checkpoint so a bisect over 3's changes only sees
state-management diffs. Commit 0 is bisect-friendly for any bug
that lands in commits 1-4 but has nothing to do with the signature
change itself.

### 7. What we're deliberately *not* doing

- **Signal queuing to a stopped thread.** gVisor's
  `canReceiveSignalLocked` declines threads that are in a stopped
  state. Phase 3c tracks thread state enough to distinguish
  "stopped for ptrace reasons" (us) from "stopped for SIGSTOP"
  (not possible in our guest today — nothing sends SIGSTOP). A
  thread stopped by us is *always* eligible because the Sentry is
  about to resume it. This simplification costs us nothing
  observable.
- **Realtime signal queuing.** Still deferred per ADR 001 non-goals.
  A single pending slot per signo remains our ceiling.
- **Signalfd/sigwaitinfo.** Still deferred.
- **CLONE_VM without CLONE_THREAD.** Process-like semantics; out of
  scope. If seen, kill the tracee with a clear log line.
- **arm64 delivery.** The routing machinery here is arch-neutral;
  `deliver_arm64.go` remains a no-op until its own ADR lands. arm64
  gets the `ThreadGroup`/`ThreadState` types for free — they're in
  the shared `signals.go` — and the build stays green, but the
  routing commit doesn't wire arm64's signal-stop path. Deferring
  arm64 routing keeps commit 3's surface area honest.

## Non-goals

- Multi-process guests (`fork`, `vfork`, `CLONE_VM`-only clone).
- Realtime signal queue depth.
- Per-thread CPU affinity or scheduler interaction.
- `PTRACE_SEIZE` semantics: we stay on `PTRACE_TRACEME` + attach-
  on-clone, which is sufficient and doesn't require changing how we
  bootstrap the tracee.
- Full `setns` / PID namespace handling for the new threads.

## Rollback plan

Each commit is revertable in isolation, but the only "safe
checkpoint" states are:

- After commit 1: shim-preserved monolithic `SignalState`, tests
  unchanged. Revert 2-4 to return here.
- After commit 2: threads attached but routed through a single
  implicit thread. Can revert 3-4, but 2 alone has no observable
  benefit.

Full Phase-3c-commit-1 state is reachable by reverting all four
commits in order. There is no intermediate state where threads are
partially attached — commit 2 lands the option and the event
handling together.

If commit 3 ships with a latent routing bug (say, `findSignalReceiver`
always picks thread 0 so SIGUSR1 to a blocked thread 0 silently
drops), the failure mode is either a hang (Test 7) or a dropped
signal count mismatch in the exit banner. Both are observable within
one stability run, not in the field.

## Estimated size

Rough LOC projection, ±30%:

| Commit                                  | Code  | Tests |
|-----------------------------------------|-------|-------|
| 0: HandleSyscall signature prep         | ~120  | ~40   |
| 1: ThreadGroup/ThreadState scaffolding  | ~220  | ~150  |
| 2: TRACECLONE + per-thread attach       | ~180  | ~120  |
| 3: Per-thread routing (drain + kill/*)  | ~260  | ~200  |
| 4: Guest tests (Test 7 + Test 9)        | ~60   | —     |
| **Total**                               | **~840** | **~510** |

Five commits over roughly three focused sessions. Commit 0 is
mechanically large but intellectually tiny. Commits 1 and 2 fit
under the 300-line new-file cap; commit 3 will grow `signals.go`
past it, which means splitting routing logic into its own file
(`signals_routing.go`, ~200 lines new) rather than expanding the
existing one.

## Decisions resolved during review (2026-04-17)

All five open questions from the initial draft were resolved before
ship and folded into the body above. Recorded here for posterity:

1. **Test 7 vehicle** → raw `rt_sigaction` + `sigsuspend`. Durable,
   doesn't depend on Go runtime internals, exercises the primitive
   this ADR ships. See §5 item 1.
2. **ThreadState lifecycle** → remove on exit. Mirrors gVisor,
   keeps routing branchless. See §3 ("ThreadState lifecycle").
3. **Iteration order** → deterministic slice, attach-time ordered.
   Reproducible tests win the tie. See §3 ("Iteration order").
4. **`HandleSyscall` signature change** → its own prep commit
   (commit 0). Keeps commit 1's diff readable and bisect-friendly.
   See §4.3 and §6.
5. **arm64 lockstep** → no. arm64 gets the types for free via
   shared `signals.go` but routing is amd64-only; arm64 catches up
   when its own delivery ADR lands. See §7 ("arm64 delivery").
