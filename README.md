# mini-sentry

A minimal userspace kernel in Go, inspired by [gVisor](https://github.com/google/gvisor).

This program intercepts every system call from a sandboxed process and handles them in userspace Go code — the Linux kernel never sees the application's syscalls. This is the core architectural pattern behind gVisor, Google's container sandbox that powers Cloud Run, Cloud Functions, App Engine, and GKE Sandbox.

## Quick Start

This is a **Linux-only** project (ptrace SYSEMU doesn't exist on macOS). Build from source on a Linux box:

```bash
# Debian/Ubuntu: install gcc + static glibc for building the sample binaries
sudo apt-get update
sudo apt-get install -y gcc libc6-dev

# Build sentry-exec and the guest
make build             # produces ./sentry-exec (+ ./mini-sentry symlink) and ./cmd/guest/guest

# Run the guest in the sandbox
make run               # build + run the guest
make verbose           # same but with full syscall tracing
```

You should see the guest program read files, check its identity, and interact with a virtual filesystem — all mediated by Go code, not the Linux kernel.

### Try with real binaries

Most distros ship `/bin/echo`, `/bin/cat`, `/bin/ls`, `/bin/pwd` as **dynamically** linked ELFs — running those inside mini-sentry would require loading the host's `ld-linux-x86-64.so.2` + `libc.so.6` through the VFS and supporting file-backed `mmap`, which this project deliberately doesn't do. Check with `file /bin/echo`. If they say "dynamically linked", build equivalent **static** binaries first:

```bash
# Requires gcc and static glibc (installed above)
make samples       # builds static echo/cat/ls/pwd into ./samples/
```

Then run them in the sandbox:

```bash
./sentry-exec ./samples/echo hello from sandbox
./sentry-exec ./samples/cat /etc/hostname      # → "mini-sentry-sandbox"
./sentry-exec ./samples/ls /                   # → greeting.txt  etc  proc
./sentry-exec ./samples/pwd                    # → "/"
```

### Pick a platform

mini-sentry ships two interception platforms, selectable with `--platform`:

- **`ptrace`** (default) — `PTRACE_SYSEMU` stops the guest on *every* syscall and round-trips it to the Sentry. Simple and correct, but every `getpid` pays a full ptrace context-switch.
- **`seccomp`** — a seccomp-BPF filter routes emulated syscalls to the Sentry via `SECCOMP_RET_USER_NOTIF` and lets everything else (getpid, mmap, futex, …) hit the real kernel directly. This is the same architectural pattern gVisor's **systrap** platform uses. Much faster, at the cost of a more complex bootstrap.

```bash
./sentry-exec --platform=seccomp ./samples/cat /etc/os-release
./sentry-exec --platform=seccomp --benchmark ./cmd/guest/guest   # getpid() hot loop
```

Signal delivery (Phase 3) is ptrace-only today — the Sentry-side signal frame path needs `PTRACE_GETREGS`/`SETREGS` to rewrite the tracee's stack. Under seccomp the tests that exercise real handlers skip cleanly.

If your distro provides `busybox-static` (`sudo apt-get install -y busybox-static` on Debian/Ubuntu) that works as well:

```bash
./sentry-exec /bin/busybox echo hello
./sentry-exec /bin/busybox cat /greeting.txt
```

### CLI knobs

`sentry-exec` is intended to be called the same way you'd call `firejail`, `bubblewrap`, or `runsc do` — pass the target as trailing arguments, configure the sandbox with flags:

| Flag | Description |
|---|---|
| `--platform ptrace\|seccomp` | Interception mechanism (default: `ptrace`) |
| `--gofer=false` | Use an in-memory VFS inside the Sentry instead of a separate Gofer process |
| `--mount HOST:GUEST[:ro\|:rw]` | Bind-mount a host subtree into the guest; repeatable; longest guest prefix wins |
| `--gofer-root DIR` | Legacy shorthand for serving a single host tree read-only at `/` |
| `--gofer-deny PATH` | Guest path prefix that always returns EACCES (repeatable) |
| `--net-allow CIDR:PORT` | Outbound allowlist entry (repeatable) |
| `--net-deny CIDR:PORT` | Outbound denylist entry (deny beats allow; port `0` = all) |
| `--env KEY=VAL` | Extra env var for the guest (repeatable, last wins per key) |
| `--cwd DIR` | Guest working directory (default: inherit) |
| `--user NAME\|UID` | Drop to this uid before exec |
| `--group NAME\|GID` | Drop to this gid before exec |
| `--rlimit NAME=SOFT[:HARD]` | Override a guest rlimit (repeatable). Names: `as`, `core`, `cpu`, `data`, `fsize`, `memlock`, `msgqueue`, `nice`, `nofile`, `nproc`, `rss`, `rtprio`, `sigpending`, `stack` |
| `--benchmark` | Run a getpid() hot loop inside the guest for platform-timing numbers |

Examples:

```bash
# Run an untrusted script with tight resource limits + scrubbed env.
./sentry-exec \
    --rlimit nofile=64 --rlimit cpu=5 --rlimit fsize=1048576 \
    --env PATH=/usr/bin --env HOME=/tmp \
    ./untrusted.sh

# Drop privileges and pin the working directory.
./sentry-exec --user nobody --group nogroup --cwd / ./samples/pwd

# Expose a writable scratch directory and block everything else.
./sentry-exec \
    --mount /tmp/scratch:/tmp:rw \
    --gofer-deny /etc \
    ./samples/cat /tmp/input
```

A couple of caveats worth naming outright:

- **Static binaries only, for now.** Dynamic ELFs need file-backed `mmap` and a working `ld-linux-x86-64.so.2` — that's Phase 2. Use `make samples` or `busybox-static` until then.
- **`RLIMIT_STACK` and `RLIMIT_AS` are imperfect.** Both are read by the kernel *during* `execve`. We apply limits via `prlimit64` on the child PID right after `ForkExec` returns, which is already past the initial address-space sizing. They'll clamp post-exec behaviour (further `mmap` failures) but won't shrink the initial mapping. A later pre-exec bootstrap step will close this gap.

## Architecture → gVisor Mapping

The core files map directly to gVisor's architecture:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        mini-sentry                                  │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  platform.go  │    │  sentry.go   │    │  vfs.go              │  │
│  │              │    │  handlers.go │    │                      │  │
│  │  Intercepts  │───▶│  Handles     │───▶│  Serves files from   │  │
│  │  syscalls    │    │  syscalls in │    │  virtual filesystem  │  │
│  │  via ptrace  │    │  userspace   │    │                      │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│        ▲                                                            │
│        │ PTRACE_SYSEMU                                              │
│  ┌─────┴────────────────────────────────────────────────────────┐  │
│  │  Sandboxed Process (guest)                                    │  │
│  │  Thinks it's talking to the Linux kernel, but every syscall  │  │
│  │  is handled by Go code above.                                 │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

| mini-sentry | gVisor | What it does |
|---|---|---|
| `platform.go` / `platform_seccomp.go` | `pkg/sentry/platform/` | Intercepts syscalls. We ship both ptrace and seccomp (`SECCOMP_RET_USER_NOTIF`); gVisor ships ptrace, systrap, and KVM |
| `regs_amd64.go` / `regs_arm64.go` | `pkg/sentry/arch/` | Architecture-specific register layout for reading syscall args |
| `sentry.go` | `pkg/sentry/kernel/` | The userspace kernel — dispatches syscalls to handlers |
| `handlers.go` | `pkg/sentry/syscalls/linux/` | Individual syscall implementations (read, write, open, etc.) |
| `signals.go` / `signals_threadgroup.go` / `signals_pending.go` | `pkg/sentry/kernel/signal*.go` | Signal disposition mirror, per-thread masks + pending queues, thread-group routing |
| `frame_amd64.go` / `deliver_amd64.go` / `handlers_signals_amd64.go` | `pkg/sentry/arch/signal_amd64.go` + kernel | Build/decode `rt_sigframe`, deliver handlers by rewriting the tracee stack, emulate `rt_sigreturn` |
| `vfs.go` / `vfs_gofer.go` / `gofer.go` | `pkg/sentry/vfs/` + Gofer | Virtual filesystem — in-memory or out-of-process gofer serving a restricted view of the host |
| `network.go` | `pkg/sentry/socket/` + netstack | Outbound CIDR:port allow/deny policy applied to `connect`/`sendto` |

## How It Works

### The Syscall Interception Loop

```
1. Platform forks child with PTRACE_TRACEME
2. Child execs the target program
3. Platform calls PTRACE_SYSEMU to resume child
4. Child attempts a syscall (e.g., write(1, "hello", 5))
5. SYSEMU stops the child BEFORE the kernel executes the syscall
6. Platform reads registers: RAX=1 (write), RDI=1 (fd), RSI=ptr, RDX=5
7. Platform passes these to Sentry.HandleSyscall()
8. Sentry runs sysWrite() — writes "hello" to real stdout via host fd
9. Sentry returns 5 (bytes written)
10. Platform writes 5 into child's RAX register
11. Platform calls PTRACE_SYSEMU again → goto step 4
```

The critical insight: **step 5**. `PTRACE_SYSEMU` is different from `PTRACE_SYSCALL` — it stops the child on syscall entry and **skips** the actual kernel syscall. The kernel never executes `write()`. Our Go code does. We are the kernel.

### Why This Matters (Security)

In a normal container (runc), when your application calls `write()`, the actual Linux kernel executes it. If there's a kernel vulnerability in the `write()` code path, the container can exploit it and escape.

With gVisor (and mini-sentry), `write()` hits our Go code. Go is memory-safe — no buffer overflows, no use-after-free, no stack smashing. The kernel vulnerability doesn't apply because the kernel never runs `write()`.

The attack surface shrinks from ~350 Linux syscalls to the ~68 host syscalls that gVisor's Sentry actually makes (and those are locked down by seccomp-bpf).

### The Virtual Filesystem (Gofer)

In gVisor, the Gofer is a **separate process** that mediates filesystem access:

```
Container App  →  Sentry  →(LISAFS protocol)→  Gofer  →  Host Filesystem
```

Even if an attacker compromises the Sentry, they can't open arbitrary files — they can only ask the Gofer, which has its own restricted view of the host filesystem.

Our `vfs.go` combines both roles: it's the Sentry's in-memory map of "what files exist." When the guest calls `open("/etc/hostname")`, our handler checks this map — not the host's `/etc/hostname`. The guest sees `mini-sentry-sandbox`, not your real hostname.

### The Signal Machinery (Phase 3)

Getting signals right means the Sentry, not the kernel, owns handler dispatch — otherwise a guest handler would see the *host's* register state, not the emulated one. We do this in three layers:

- **3a — the disposition mirror.** `signals.go` / `signals_threadgroup.go` / `signals_pending.go` mirror everything the kernel would normally own: the 64-entry sigaction table, per-thread signal masks, and a per-thread pending queue. `rt_sigaction`, `rt_sigprocmask`, and `sigaltstack` are intercepted and mutate the mirror only — the kernel's view stays untouched.
- **3b — Sentry-side frame delivery.** `frame_amd64.go` builds an x86_64 `rt_sigframe` (ucontext + fpstate + siginfo + pretcode) on the guest's stack via `process_vm_writev`; `deliver_amd64.go` rewrites `RIP` to the handler and `RSP` to the frame; `handlers_signals_amd64.go` emulates `rt_sigreturn` by reading the frame back and restoring `PTRACE_SETREGS` + `SETFPREGS` + the saved mask. The kernel never sees the handler run.
- **3c — per-thread routing.** `PTRACE_O_TRACECLONE` attaches every guest thread as it's spawned so the Sentry tracks a full `ThreadGroup` / `ThreadState` pair. `kill`/`tkill`/`tgkill` route by spoofed tgid/tid but resolve to the *caller's* host tid for self-sends; group-directed kills pick the first thread whose mask accepts the signal.

`cmd/guest/main.go` Tests 7 and 9 prove the round-trip end-to-end: a raw `rt_sigaction`-installed pure-asm SIGUSR1 handler that atomically bumps a counter, driven by `kill(self, SIGUSR1)` and by four goroutines racing `tgkill` from dedicated OS threads.

## Implemented Syscalls

| Syscall | Handler | Notes |
|---|---|---|
| **File I/O** | | |
| `read` / `pread64` | sysRead / sysPread64 | Serves data from VFS or passes through for stdio |
| `write` / `pwrite64` | sysWrite / sysPwrite64 | Passes through to host stdout/stderr |
| `openat` | sysOpenat | Opens files from VFS or gofer-served mounts |
| `close` | sysClose | Closes virtual file descriptors |
| `lseek` | sysLseek | Seeks within virtual files |
| `fstat` / `statx` | sysStat / sysStatx | Returns fabricated stat structures |
| `statfs` | sysStatfs | Returns fabricated filesystem stats |
| `faccessat` | sysFaccessat | VFS-aware access check |
| `getdents64` | sysGetdents64 | Lists virtual directory contents |
| `ioctl` / `fcntl` | sysIoctl / sysFcntl | TCGETS → ENOTTY, basic fd flag ops |
| `fadvise64` / `copy_file_range` | — | Accepted no-ops for sequential readers |
| **Memory & process** | | |
| `brk` / `mmap` | sysBrk / sysMmap | Program break + anonymous mappings |
| `mprotect` / `munmap` | — | Accepted (no-op) |
| `arch_prctl` / `prctl` | sysArchPrctl / sysPrctl | TLS setup (x86_64), PR_SET_NAME, etc. |
| `prlimit64` | sysPrlimit64 | Mirrors `--rlimit` overrides |
| `getrandom` | sysGetrandom | Fills buffer from crypto/rand |
| `getpid` / `gettid` | — | Returns 1 (sandbox init / sole thread from guest's view) |
| `getuid` / `getgid` / `geteuid` / `getegid` | — | Returns 0 (fake root) |
| `clone` | — | Passthrough with `PTRACE_O_TRACECLONE` so new threads attach to the Sentry |
| **Signals (Phase 3, x86_64)** | | |
| `rt_sigaction` | sysRtSigaction | Mirrors the 64-entry sigaction table inside the Sentry |
| `rt_sigprocmask` | sysRtSigprocmask | Per-thread signal mask, mirror-only |
| `sigaltstack` | sysSigaltstack | Mirrors alternate signal stack per thread |
| `rt_sigreturn` | sysRtSigreturn | Decodes rt_sigframe and restores tracee regs + fp + mask |
| `kill` / `tkill` / `tgkill` | sysKill / sysTkill / sysTgkill | Route by spoofed (tgid, tid) → caller's host tid |
| **Network policy** | | |
| `socket` / `connect` / `sendto` | sysSocket / sysConnect / sysSendto | `--net-allow` / `--net-deny` CIDR:port filter |
| **Everything else** | — | Returns `ENOSYS` |

> arm64 currently mirrors disposition but skips Sentry-side frame delivery — signals pass through to the host kernel. x86_64 is the reference path.

## Extending It

Some ideas for making this more educational:

1. **Add verbose mode** — Change `logWriter()` in `sentry.go` to return `os.Stderr` to see every intercepted syscall
2. **arm64 signal delivery** — Port `frame_amd64.go` / `deliver_amd64.go` / `handlers_signals_amd64.go` to arm64. The ucontext layout + SVE state is the tricky part; disposition + routing already work.
3. **Timers** — `nanosleep`, `clock_gettime`, `setitimer`, `timer_create`. Today `nanosleep` passes through; a Sentry-driven timer wheel would let the guest observe a virtual clock.
4. **Dynamic ELF loader** — File-backed `mmap` + a real `ld-linux-x86-64.so.2` identity-mount path would lift the "static binaries only" caveat.
5. **Syscall filtering policy** — Extend `sentry.go` with per-spec allow/deny rules (like seccomp profiles) to prove out defense-in-depth beyond the platform's BPF filter.
6. **Run real programs** — Handle more syscalls (`epoll`, `eventfd`, `inotify`, `pidfd_*`) to support Python, Node, redis-server, etc.

## Requirements

- **Target:** Linux (ptrace SYSEMU is Linux-only). Works on both x86_64 and arm64 (kernel 5.3+ for arm64 SYSEMU support)
- **Build:** Go 1.22+ on a Linux host. For the sample binaries: `gcc` and static glibc headers (`libc6-dev` on Debian/Ubuntu)
- **Run:** Any Linux box

## How gVisor Does It (For Real)

gVisor's production implementation adds layers we skip:

- **Seccomp on the Sentry itself** — The Sentry is restricted to ~68 host syscalls by its own seccomp filter. Even if the Sentry has a bug, it can't call arbitrary kernel syscalls. (We ship `--platform=seccomp` to intercept the *guest*, not to lock down the Sentry — that's a separate filter gVisor applies.)
- **Full memory management** — gVisor tracks every page of application memory using a host memfd, with proper COW, demand paging, and NUMA awareness.
- **Complete networking stack** — gVisor's netstack implements TCP/IP from scratch in Go, so the sandbox never opens a real socket. Ours enforces an outbound CIDR:port policy but still opens real host sockets.
- **IPC, pidns, cgroups** — fork/clone/threads/signals work here, but System V IPC, POSIX message queues, namespaces, and cgroup integration are all gVisor-only.
- **237 syscalls** — We implement ~35 emulated + a handful of passthroughs. gVisor implements 237.

But the architecture is identical. This is how it works, just at a smaller scale.

## Design Notes

The signal subsystem has enough moving parts (Sentry-side frame building, per-thread routing via TRACECLONE, the Task/ThreadGroup split) that it earned its own ADR trail:

- [ADR 001 — Phase 3b pure-state signals](docs/adr/001-phase3b-pure-state-signals.md) — Sentry-owned `rt_sigframe` and `rt_sigreturn` (amd64).
- [ADR 002 — Phase 3c multi-thread routing](docs/adr/002-phase3c-multithread-signal-routing.md) — `PTRACE_O_TRACECLONE` + per-thread pending queues, mirroring gVisor's Task/ThreadGroup seam.
- [ADR 003 — Phase 3 closeout](docs/adr/003-phase3-closeout.md) — where the project stops, the arm64 gap, and the remaining backlog.

## License

MIT
