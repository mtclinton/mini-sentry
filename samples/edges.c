/* edges.c — adversarial edge cases for mini-sentry.
 *
 * Each check prints "CASE name: PASS" or "CASE name: FAIL ..." so the
 * harness can grep results. Exits non-zero if anything failed so
 * scripts can detect regressions.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failed = 0;

static void check(const char *name, int ok, const char *why) {
	if (ok) {
		printf("CASE %s: PASS\n", name);
	} else {
		printf("CASE %s: FAIL (%s)\n", name, why);
		failed = 1;
	}
}

int main(void) {
	/* double-close: second close must return EBADF, not crash. */
	{
		int fd = open("/etc/hostname", O_RDONLY);
		int r1 = close(fd);
		int r2 = close(fd);
		int e = errno;
		check("double-close",
		      r1 == 0 && r2 == -1 && e == EBADF,
		      "second close should be EBADF");
	}

	/* read-from-closed-fd: reading a closed fd is EBADF. */
	{
		int fd = open("/etc/hostname", O_RDONLY);
		close(fd);
		char buf[8];
		errno = 0;
		ssize_t n = read(fd, buf, sizeof(buf));
		int e = errno;
		check("read-closed-fd",
		      n == -1 && e == EBADF,
		      "expected EBADF");
	}

	/* zero-length read: success, returns 0. */
	{
		int fd = open("/etc/hostname", O_RDONLY);
		char buf[1];
		ssize_t n = read(fd, buf, 0);
		close(fd);
		check("zero-len-read", n == 0, "expected 0");
	}

	/* zero-length write to stdout: success. */
	{
		ssize_t n = write(1, "", 0);
		check("zero-len-write", n == 0, "expected 0");
	}

	/* two open fds for the same virtual file should be independent. */
	{
		int fd1 = open("/etc/hostname", O_RDONLY);
		int fd2 = open("/etc/hostname", O_RDONLY);
		char b1[32] = {0}, b2[32] = {0};
		ssize_t n1 = read(fd1, b1, sizeof(b1) - 1);
		ssize_t n2 = read(fd2, b2, sizeof(b2) - 1);
		close(fd1);
		close(fd2);
		check("dual-open-independent",
		      fd1 > 0 && fd2 > 0 && fd1 != fd2 && n1 > 0 && n2 > 0 && n1 == n2 && !memcmp(b1, b2, n1),
		      "fds should read same data independently");
	}

	/* read from an obviously-bad fd: EBADF. */
	{
		char buf[1];
		errno = 0;
		ssize_t n = read(999, buf, 1);
		int e = errno;
		check("bad-fd-999", n == -1 && e == EBADF, "expected EBADF");
	}

	return failed ? 1 : 0;
}
