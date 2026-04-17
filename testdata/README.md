# testdata

## sigframe_amd64_sigusr1.hex

A byte-exact oracle of the Linux kernel's 1032-byte `rt_sigframe` for
SIGUSR1 on amd64, captured from a statically-linked C program.  It is
the ground truth `frame_test.go :: TestBuildRtSigframeMatchesKernel`
diffs `BuildRtSigframe`'s output against (with a small set of
documented masks — see the test for the full list).

Layout, low -> high:

    [  0..  8)  pretcode          (glibc __restore_rt pointer)
    [  8.. 16)  uc.flags          (kernel sets UC_FP_XSTATE|UC_SIGCONTEXT_SS|UC_STRICT_RESTORE_SS)
    [ 16.. 24)  uc.link
    [ 24.. 48)  uc.stack          (stack_t: sp, flags, size)
    [ 48..304)  uc.mcontext       (sigcontext: r8..r15, rdi..rcx, rsp, rip, eflags, cs/gs/fs/ss, err, trapno, oldmask, cr2, fpstate_ptr, reserved[8])
    [304..312)  uc.sigmask        (low 8 bytes of kernel sigset_t)
    [312..440)  siginfo           (signo, errno, code, pid, uid, ...)
    [440..456)  padding
    [456..968)  fpstate (FXSAVE)
    [968..1032) fpstate (XSAVE header tail — magic, xstate_bv, ...)

### Regeneration

**Do not regenerate without an explanation.**  This oracle pins the
kernel ABI contract the signal-delivery path depends on.  If it
changes, that's a real-world divergence worth understanding — usually
a kernel or glibc upgrade that shifted layout (extremely rare for
this struct) or a host-property change (e.g. XCR0 bits) that needs
to ride into the ADR.

If you've verified a regeneration is legitimate:

    make regen-oracle

This rebuilds `testdata/sigframe_capture/sigframe_capture` and runs
it.  The binary installs a SIGUSR1 handler with `SA_SIGINFO`, raises
SIGUSR1, and in the handler `memcpy`s 1032 bytes starting at
`(unsigned char *)uc - 8` — that is, the pretcode slot just below
the ucontext argument — into a static buffer.  After returning, main
writes the captured bytes to stderr as one line of lowercase hex.
See `sigframe_capture/main.c` for the exact layout note.

### Captured on

```
Linux maxbox 6.12.74+deb13+1-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.74-2 (2026-03-08) x86_64 GNU/Linux
ldd (Debian GLIBC 2.41-12+deb13u2) 2.41
gcc (Debian 14.2.0-19) 14.2.0
```
