// sig_amd64.s — pure-asm SIGUSR1 handler + rt_sigreturn trampoline.
//
// Why pure asm? The kernel (and our Sentry's BuildRtSigframe) enters
// the handler with the SysV C ABI: rdi=signo, rsi=&siginfo,
// rdx=&ucontext. The Go ABIInternal expects R14 to hold the current
// g (goroutine) pointer; at signal-delivery entry R14 is whatever the
// interrupted user code had, which is NOT guaranteed to be a valid g.
// A Go-level handler that touches any runtime-provided primitive
// would explode. Pure asm with no runtime contact sidesteps that.
//
// The handler atomically bumps sigCounter and returns via RET — RET
// pops the pretcode slot (the Sentry wrote act.restorer there in
// BuildRtSigframe, which is &restoreRT below) and lands in restoreRT.
// restoreRT issues SYS_rt_sigreturn so sysRtSigreturn decodes the
// frame and restores pre-signal register state.

#include "textflag.h"

// func sigusr1Handler()
// Entry point registered as sa_handler for SIGUSR1. No Go frame, no
// stack growth probe: this runs in signal context on whatever stack
// the Sentry's deliverOne picked.
TEXT ·sigusr1Handler(SB),NOSPLIT|NOFRAME,$0-0
	LEAQ	·sigCounter(SB), AX
	MOVL	$1, BX
	LOCK
	XADDL	BX, (AX)
	RET

// func restoreRT()
// sa_restorer installed alongside sigusr1Handler. The handler's RET
// pops the pretcode slot the Sentry wrote (which is &restoreRT) and
// lands here. SYS_rt_sigreturn on x86_64 is 15; the syscall traps to
// our emulated sysRtSigreturn which owns the unwind.
TEXT ·restoreRT(SB),NOSPLIT|NOFRAME,$0-0
	MOVQ	$15, AX
	SYSCALL

// sigusr1HandlerPC / restoreRTPC — data symbols holding the raw ABI0
// entry addresses of the two asm funcs. Needed because the Go
// compiler emits an ABIInternal wrapper (PUSHQ BP / CALL abi0 / POPQ
// BP / RET) whenever Go code takes the address of an asm func via a
// Go declaration. reflect.ValueOf(fn).Pointer() returns the wrapper
// entry; the wrapper's PUSHQ BP + CALL shifts RSP by 16 before the
// real handler runs, which breaks the kernel's C-ABI signal-entry
// contract and leaves rt_sigreturn reading the frame 16 bytes below
// where it was written. These DATA symbols resolve to the bare TEXT
// entries (ABI0) inside this .s file, so Go code can install them
// directly into the kernel_sigaction struct.
GLOBL ·sigusr1HandlerPC(SB), RODATA, $8
DATA ·sigusr1HandlerPC(SB)/8, $·sigusr1Handler(SB)

GLOBL ·restoreRTPC(SB), RODATA, $8
DATA ·restoreRTPC(SB)/8, $·restoreRT(SB)
