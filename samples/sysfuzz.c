/* sysfuzz.c — syscall fuzzer for mini-sentry.
 *
 * Issues 10,000 raw syscalls with random numbers, fds, pointers, and
 * sizes from inside the sandbox. The point is to prove that no input
 * (however wild) can crash or hang mini-sentry: every call must return
 * something and the Sentry must not panic.
 *
 * Caveat: under --platform=seccomp, syscalls that aren't in mini-sentry's
 * emulated set pass straight through to the real kernel — where a random
 * invocation can block forever (poll, futex, wait4, msgrcv, …) or alter
 * our own process state (exit, mprotect, clone, …). So rather than
 * picking wholly arbitrary syscall numbers in [0, 450] — which would
 * hang us under seccomp — we draw from a whitelist of syscalls that
 * either (a) the Sentry emulates, so every call traps to Go code, or
 * (b) don't exist on this kernel, so we exercise the ENOSYS path. The
 * arguments (fds, pointers, sizes) are still fully random, which is
 * where the interesting crash surface lives.
 *
 * alarm(30) is a belt-and-braces self-kill if anything slips through.
 *
 * Prints "sysfuzz: ... PASS" and exits 0 on completion.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* whitelist of syscall numbers we'll hand to random args. Everything
 * here traps to the Sentry (emulated) or returns ENOSYS (unimplemented)
 * regardless of platform, so neither ptrace nor seccomp can deadlock
 * on a real-kernel invocation. */
static const long FUZZ_NUMBERS[] = {
	/* — emulated file ops — */
	0,   /* read         */
	1,   /* write        */
	2,   /* open         */
	3,   /* close        */
	4,   /* stat         */
	5,   /* fstat        */
	6,   /* lstat        */
	8,   /* lseek        */
	16,  /* ioctl        */
	20,  /* writev       */
	21,  /* access       */
	32,  /* dup          */
	72,  /* fcntl        */
	78,  /* getdents     */
	79,  /* getcwd       */
	89,  /* readlink     */
	99,  /* sysinfo      */
	137, /* statfs       */
	138, /* fstatfs      */
	217, /* getdents64   */
	257, /* openat       */
	262, /* newfstatat   */
	267, /* readlinkat   */
	269, /* faccessat    */
	302, /* prlimit64    */
	318, /* getrandom    */

	/* — emulated identity/thread setup — */
	63,  /* uname        */
	102, /* getuid       */
	104, /* getgid       */
	107, /* geteuid      */
	108, /* getegid      */
	218, /* set_tid_address */
	273, /* set_robust_list */
	334, /* rseq         */

	/* — a few "definitely ENOSYS on this kernel" numbers to exercise
	 *   the unknown-syscall path. Picked above the current syscall
	 *   table ceiling (~450). — */
	500, 600, 700, 900, 1234,
};
#define NR_FUZZ_NUMBERS ((int)(sizeof(FUZZ_NUMBERS) / sizeof(FUZZ_NUMBERS[0])))

/* rand_arg returns a mix of interesting integer values: edges (0, -1,
 * INT_MAX), small ints, and occasional random 64-bit garbage. */
static unsigned long rand_arg(void) {
	switch (rand() % 9) {
	case 0: return 0UL;
	case 1: return 1UL;
	case 2: return (unsigned long)-1;
	case 3: return (unsigned long)0x7fffffffUL;
	case 4: return (unsigned long)(rand() & 0xff);
	case 5: return 0xdeadbeefUL;
	case 6: return 999UL;    /* bad fd */
	case 7: return 0x1000UL; /* suspiciously-small addr */
	default: {
		unsigned long x = (unsigned long)rand() << 32 | (unsigned)rand();
		return x;
		}
	}
}

int main(void) {
	srand((unsigned)time(NULL) ^ (unsigned)getpid());

	/* Self-kill if anything blocks longer than this. Default SIGALRM
	 * action is terminate, which is what we want. */
	alarm(30);

	const int N = 10000;
	long issued = 0;

	for (int i = 0; i < N; i++) {
		long nr = FUZZ_NUMBERS[rand() % NR_FUZZ_NUMBERS];
		unsigned long a = rand_arg();
		unsigned long b = rand_arg();
		unsigned long c = rand_arg();
		unsigned long d = rand_arg();
		unsigned long e = rand_arg();
		unsigned long f = rand_arg();
		/* Raw syscall. We don't check the return value — any return
		 * (including -ENOSYS / -EINVAL / -EFAULT) is a success for
		 * the fuzzer. The failure mode we're looking for is "no
		 * return at all". */
		(void)syscall(nr, a, b, c, d, e, f);
		issued++;
	}

	printf("sysfuzz: N=%d issued=%ld PASS\n", N, issued);
	return 0;
}
