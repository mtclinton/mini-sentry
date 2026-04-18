# ADR 003: Phase 3 closeout — stopping point and remaining backlog

- Status: **Accepted**
- Date: 2026-04-18
- Deciders: Max Clinton
- Relates to: ADR 001 (Phase 3b pure-state signals), ADR 002 (Phase 3c multi-thread routing)

## Context

mini-sentry set out to be a teaching artifact: show how gVisor's
Sentry/Gofer/Platform split actually works, in a tree small enough to
read end-to-end. Three phases of work have landed since the initial
ptrace-SYSEMU prototype:

- **Phase 1** — syscall interception loop, Sentry dispatch, in-memory
  VFS, identity spoofing, the minimum viable handler set
  (`read`/`write`/`openat`/`close`/`stat`/`mmap`/`brk`/`getdents64`/…).
- **Phase 2** — the CLI frontend (`sentry-exec`), mounts with the
  longest-prefix-wins rule, identity-mount passthrough for dynamic
  linking, the out-of-process Gofer over Unix socket, the
  `--platform=seccomp` path (`SECCOMP_RET_USER_NOTIF` + the seccomp
  bootstrap shim), outbound CIDR:port network policy, rlimits, user/
  group, cwd, extra env, and the statx/statfs/prctl/pread64/pwrite64/
  fadvise64/copy_file_range handler set.
- **Phase 3** — signals. 3a mirrored disposition (sigaction table,
  per-thread mask, pending queues) without owning delivery; 3b moved
  delivery into the Sentry on amd64 by building `rt_sigframe`s and
  emulating `rt_sigreturn`; 3c split state along gVisor's
  Task/ThreadGroup seam, attached every thread via
  `PTRACE_O_TRACECLONE`, and routed `kill`/`tkill`/`tgkill` into the
  correct per-thread pending queue. Guest Tests 7 and 9 prove the
  end-to-end handler round-trip and per-thread routing under ptrace.

Between Phase 2 and Phase 3 the tree also grew a test discipline worth
naming: cross-arch ABI checks (`cross_check_*_test.go`), a
golden-file `rt_sigframe` oracle, fuzz harnesses for the sigaction
decoder / sigframe / syscall args, and a GitHub Actions CI run that
covers build, race, and the full test suite on linux/amd64. That's
more infrastructure than a toy needs, but Phase 3b would have been
untethered without the oracle, so it earns its keep.

The project is at a natural pause. This ADR records *why* stopping
here is honest, what the arm64 gap really is, and what the backlog
looks like for anyone who picks it up later.

## Decision

**Stop here, publish, and leave the remaining work as a documented
backlog rather than half-landed code.**

Concretely: push the current `main` branch to GitHub as the
educational reference, mark ADRs 001–003 as the canonical design
trail, and keep the "Extending it" section of the README aligned with
the Backlog table below. No further Phase 3 commits in this cycle.

## Reasoning

### 1. The educational story is complete

Every load-bearing piece of gVisor's architecture has a minimal
counterpart in this tree:

| gVisor concept                  | mini-sentry file(s)                                              |
|---------------------------------|-------------------------------------------------------------------|
| Platform (syscall interception) | `platform.go` (ptrace), `platform_seccomp.go` (USER_NOTIF)        |
| Sentry (userspace kernel)       | `sentry.go` + handlers                                            |
| Syscall table & handlers        | `handlers.go`, `handlers_signals_amd64.go`, `network.go`, …       |
| Gofer (out-of-process VFS)      | `gofer.go`, `vfs_gofer.go`, `vfs.go` (in-mem stand-in)            |
| Task / ThreadGroup split        | `signals_threadgroup.go`, `signals_pending.go`                    |
| Signal disposition + delivery   | `signals.go`, `frame_amd64.go`, `deliver_amd64.go`                |
| Network policy                  | `network.go` (CIDR:port allow/deny)                               |

A reader can walk from `main.go` into any of these and have a full
gVisor concept land in one or two files. That was the goal. Shipping
more without a pedagogical reason would dilute it.

### 2. The arm64 gap is an honest stop, not an implementation gap

ADR 001 §2 deferred arm64 signal frame delivery because the arm64
`rt_sigreturn` trampoline lives in the vDSO, which the Sentry doesn't
parse. ADR 002 §"arm64 lockstep" confirmed that state survives: the
ThreadGroup/ThreadState scaffolding is shared, but Sentry-side frame
delivery and `rt_sigreturn` emulation are amd64-only.

What the arm64 path *does* have today:

- Full disposition mirror — `rt_sigaction`, `rt_sigprocmask`,
  `sigaltstack` all track state the same way amd64 does, and
  `sysRtSigaction` passes the act through to the kernel so the
  kernel's copy is synced.
- Per-thread routing via TRACECLONE — clone events are handled and
  `ThreadState` is materialised per tid identically to amd64.
- Kernel-delivered handlers — `deliverPending` on arm64
  (`deliver_arm64.go`) calls `syscall.Kill(pid, sig)` per queued
  entry, and `handleSignalStop` (`platform_signals_arm64.go`)
  forwards external signals via `ptraceSysemu(pid, sig)`. Because the
  kernel has the right sigaction (via §1 above), it runs the guest's
  handler and then itself decodes the vDSO-built frame on
  `rt_sigreturn`.

What it does not have:

- Sentry-owned frame delivery — no arm64 equivalent of
  `frame_amd64.go` / `deliver_amd64.go` / `handlers_signals_amd64.go`.
- The guest's Tests 7 and 9 — gated on `realSigSupported`, which is
  false on arm64 (`cmd/guest/sig_other.go`).

In the kernel-delivered strategy both should actually work end-to-end;
what's missing is the arm64 asm SIGUSR1 handler + install shim to
exercise them, plus runtime validation on arm64 Linux hardware. The
author has amd64 Linux (maxbox) and Apple-Silicon macOS but no arm64
Linux host, so shipping the code without a validated run crosses from
"completion" to "untested feature." That's a worse state than the
documented gap.

### 3. Pedagogy has a scope ceiling

Everything below is gVisor territory, not mini-sentry territory.
Adding them would make the tree harder to read, not easier:

- Real TCP/IP stack (netstack equivalent)
- KVM platform
- memfd-backed memory tracking with COW and demand paging
- System V IPC, POSIX message queues, pid/mount/net namespaces,
  cgroup integration
- The remaining ~200 syscalls gVisor implements

The README's "How gVisor Does It (For Real)" section already lists
these as out of scope; this ADR ratifies that.

## Backlog

Prioritised by "how much does landing this clarify the educational
story," not "how hard is it."

| Item | Size | Rationale |
|---|---|---|
| arm64 signal delivery — asm handler + install shim + Tests 7/9 ungating | ~80 LOC + arm64 Linux hw for validation | Fills the one documented platform gap. Kernel-delivered strategy means no frame-building work; just a pure-asm handler (LL/SC atomic on `sigCounter`), a 24-byte `kernel_sigaction` installer (no `sa_restorer` on arm64), and the same GLOBL/DATA ABI0-entry trick amd64 uses. |
| Timers — `nanosleep`, `clock_gettime`, `clock_nanosleep`, `setitimer`, `timer_create` | ~400 LOC + a Sentry timer wheel | Today `nanosleep` passes through. A Sentry-driven virtual clock would let the guest observe skewed/sped-up time and match gVisor's `ktime` package educationally. |
| Dynamic ELF loader polish — file-backed `mmap` for the identity-mount path | ~250 LOC | Identity-mount works for glibc dynamic binaries in practice, but `mmap(MAP_SHARED \| MAP_FILE)` is still an approximation. Real file-backed mmap would let us drop the "static binaries only, for now" caveat in the README. |
| Syscall filtering policy — per-spec allow/deny beyond the platform BPF filter | ~150 LOC | Demonstrates defense-in-depth. Small, independent, good first contribution. |
| Real program coverage — `epoll`, `eventfd`, `inotify`, `pidfd_*` | ~600 LOC across several handlers | Unlocks Python, Node, redis-server inside the sandbox. High-value but high-scope. |
| ADR-level writeup of the seccomp platform | doc-only | ADR 001/002/003 cover Phase 3 in depth but the seccomp bootstrap/USER_NOTIF lifecycle has no ADR. Would help a future reader. |

## Non-goals

Explicitly NOT in any future cycle of this project:

- **Production hardening** — this is teaching code. No Sentry-side
  seccomp lockdown, no landlock, no memory-safety audits. If someone
  is reading this with an eye on running real workloads, they want
  gVisor, not mini-sentry.
- **Windows / macOS support** — ptrace SYSEMU and
  `SECCOMP_RET_USER_NOTIF` are Linux primitives. Portability shims
  would obscure the architecture instead of teaching it.
- **Platform drift from gVisor** — if gVisor adds a new platform
  (e.g. TDX / SEV-SNP enclaves), we don't. Pedagogy wants stability.

## Consequences

- The README's "Extending it" list is now the user-facing mirror of
  the Backlog table above. Keep them in sync if either changes.
- arm64 contributors: the kernel-delivered path should Just Work for
  handler round-trips once `cmd/guest/sig_arm64.{s,go}` lands, and
  the Sentry side needs no changes. If runtime delivery hangs, suspect
  either (a) `rt_sigaction` not syncing to the kernel (check the
  passthrough at `handlers.go:sysRtSigaction`) or (b) `deliverPending`
  on arm64 not dequeuing (check the mask logic in `signals_pending.go`).
- Issues and PRs filed against this tree are out of scope unless they
  close a row in the Backlog table or fix a bug in shipped code.
  "Please implement ${feature gVisor has}" closes with a pointer to
  gVisor.

## Decisions resolved during review (2026-04-18)

1. **Publish vs. hold for arm64** — publish now. The arm64 gap is
   documented in this ADR and in the README syscall-table footnote;
   holding indefinitely for hardware access we don't have is the
   worse failure mode.
2. **ADR 003 format** — closeout, not design. Half the length of
   001/002 is the right weight for a "we stopped here" doc.
3. **Future ADRs** — only if someone takes a backlog item and needs
   to justify a non-obvious design choice. Shipping a timer wheel
   doesn't need an ADR; deciding whether timers are Sentry-driven or
   VDSO-intercepted does.
