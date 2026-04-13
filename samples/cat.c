/* cat.c — minimal cat(1) for testing mini-sentry.
 *
 * Exercises openat → read → write → close, which validates the whole
 * VFS pipeline: lookup + read go through the gofer, write to stdout
 * passes through to the real kernel.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		int fd = open(argv[i], O_RDONLY);
		if (fd < 0) { perror(argv[i]); return 1; }
		char buf[4096];
		ssize_t n;
		while ((n = read(fd, buf, sizeof(buf))) > 0) {
			if (write(1, buf, n) != n) { perror("write"); return 1; }
		}
		close(fd);
	}
	return 0;
}
