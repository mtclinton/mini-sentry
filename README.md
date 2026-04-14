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

Everything works under `--platform=seccomp` too:

```bash
./sentry-exec --platform=seccomp ./samples/cat /etc/os-release
```

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

This project has 5 files that map directly to gVisor's architecture:

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
| `platform.go` | `pkg/sentry/platform/` | Intercepts syscalls. We use ptrace; gVisor uses systrap (seccomp+SIGSYS), ptrace, or KVM |
| `regs_amd64.go` / `regs_arm64.go` | `pkg/sentry/arch/` | Architecture-specific register layout for reading syscall args |
| `sentry.go` | `pkg/sentry/kernel/` | The userspace kernel — dispatches syscalls to handlers |
| `handlers.go` | `pkg/sentry/syscalls/linux/` | Individual syscall implementations (read, write, open, etc.) |
| `vfs.go` | `pkg/sentry/vfs/` + Gofer | Virtual filesystem that controls what files the sandbox can see |

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

## Implemented Syscalls

| Syscall | Handler | Notes |
|---|---|---|
| `read` | sysRead | Serves data from VFS or passes through for stdio |
| `write` | sysWrite | Passes through to host stdout/stderr |
| `openat` | sysOpenat | Opens files from virtual filesystem only |
| `close` | sysClose | Closes virtual file descriptors |
| `fstat` | sysStat | Returns fabricated stat structures |
| `lseek` | sysLseek | Seeks within virtual files |
| `brk` | sysBrk | Manages the program break (heap) |
| `mmap` | sysMmap | Handles anonymous memory mappings |
| `mprotect` | — | Accepted (no-op) |
| `munmap` | — | Accepted (no-op) |
| `ioctl` | sysIoctl | TCGETS → ENOTTY (not a terminal) |
| `fcntl` | sysFcntl | Basic fd flag operations |
| `getdents64` | sysGetdents64 | Lists virtual directory contents |
| `arch_prctl` | sysArchPrctl | TLS setup (x86_64) |
| `prlimit64` | sysPrlimit64 | Returns permissive resource limits |
| `getrandom` | sysGetrandom | Fills buffer from crypto/rand |
| `getpid` | — | Returns 1 (sandbox init) |
| `getuid/gid` | — | Returns 0 (fake root) |
| Everything else | — | Returns `ENOSYS` (not implemented) |

## Extending It

Some ideas for making this more educational:

1. **Add verbose mode** — Change `logWriter()` in `sentry.go` to return `os.Stderr` to see every intercepted syscall
2. **Add a seccomp platform** — Replace ptrace with `SECCOMP_RET_USER_NOTIF` (the modern approach, similar to gVisor's systrap)
3. **Add network interception** — Implement `socket`, `connect`, `sendto`, `recvfrom` using gVisor's netstack concepts
4. **Add a real Gofer** — Split the VFS into a separate process communicating over a pipe (like gVisor's LISAFS)
5. **Add syscall filtering** — Block specific syscalls (like `ptrace` itself) to prevent sandbox escape
6. **Run real programs** — Handle more syscalls to support `ls`, `cat`, `python3`, etc.

## Requirements

- **Target:** Linux (ptrace SYSEMU is Linux-only). Works on both x86_64 and arm64 (kernel 5.3+ for arm64 SYSEMU support)
- **Build:** Go 1.22+ on a Linux host. For the sample binaries: `gcc` and static glibc headers (`libc6-dev` on Debian/Ubuntu)
- **Run:** Any Linux box

## How gVisor Does It (For Real)

gVisor's production implementation adds layers we skip:

- **Seccomp on the Sentry itself** — The Sentry is restricted to ~68 host syscalls by its own seccomp filter. Even if the Sentry has a bug, it can't call arbitrary kernel syscalls.
- **Separate Gofer process** — Filesystem access goes through an isolated process with minimal permissions.
- **Full memory management** — gVisor tracks every page of application memory using a host memfd, with proper COW, demand paging, and NUMA awareness.
- **Complete networking stack** — gVisor's netstack implements TCP/IP from scratch in Go, so the sandbox never opens a real socket.
- **Multi-process support** — fork(), clone(), threads, signals, IPC — the full Linux process model.
- **237 syscalls** — We implement ~20. gVisor implements 237.

But the architecture is identical. This is how it works, just at a smaller scale.

## License

MIT
