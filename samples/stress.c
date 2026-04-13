/* stress.c — fuzz-style stress test for mini-sentry.
 *
 * Hammers the handlers with repetitive operations to smoke-test state
 * management, fd-table correctness, and zero-length edge cases under
 * load. Prints a count for each phase and exits non-zero if anything
 * behaves unexpectedly.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *virtual_files[] = {
	"/etc/hostname",
	"/etc/os-release",
	"/greeting.txt",
	"/proc/self/status",
};

int main(void) {
	int fails = 0;

	/* Phase 1: open + read + close every virtual file 100 times. */
	{
		int reads = 0;
		for (int iter = 0; iter < 100; iter++) {
			for (size_t i = 0; i < sizeof(virtual_files) / sizeof(virtual_files[0]); i++) {
				int fd = open(virtual_files[i], O_RDONLY);
				if (fd < 0) { fails++; continue; }
				char buf[256];
				ssize_t n = read(fd, buf, sizeof(buf));
				if (n <= 0) fails++;
				reads++;
				close(fd);
			}
		}
		printf("phase1 reads=%d fails=%d\n", reads, fails);
	}

	/* Phase 2: identity + getcwd x 1000. */
	{
		int f2 = 0;
		for (int i = 0; i < 1000; i++) {
			if (getpid() != 1) f2++;
			if (getuid() != 0) f2++;
			char cwd[64];
			if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/") != 0) f2++;
		}
		printf("phase2 checks=3000 fails=%d\n", f2);
		fails += f2;
	}

	/* Phase 3: tight open/close loop 1000 times — fd-table should not leak. */
	{
		int f3 = 0;
		for (int i = 0; i < 1000; i++) {
			int fd = open("/greeting.txt", O_RDONLY);
			if (fd < 0) f3++;
			if (close(fd) < 0) f3++;
		}
		printf("phase3 iters=1000 fails=%d\n", f3);
		fails += f3;
	}

	/* Phase 4: zero-byte read and write. */
	{
		int fd = open("/greeting.txt", O_RDONLY);
		char b;
		ssize_t n1 = read(fd, &b, 0);
		close(fd);
		ssize_t n2 = write(1, "", 0);
		int f4 = (n1 == 0 && n2 == 0) ? 0 : 1;
		printf("phase4 zero-len fails=%d\n", f4);
		fails += f4;
	}

	/* Phase 5: read from fd 999 (must be EBADF). */
	{
		char b;
		errno = 0;
		ssize_t n = read(999, &b, 1);
		int f5 = (n == -1 && errno == EBADF) ? 0 : 1;
		printf("phase5 bad-fd fails=%d\n", f5);
		fails += f5;
	}

	printf("TOTAL fails=%d\n", fails);
	return fails ? 1 : 0;
}
