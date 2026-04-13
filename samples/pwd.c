/* pwd.c — minimal pwd(1) for testing mini-sentry.
 *
 * Exercises the getcwd syscall. mini-sentry always returns "/" for
 * getcwd, since there is no real cwd concept in the sandbox.
 */

#include <stdio.h>
#include <unistd.h>

int main(void) {
	char buf[4096];
	if (getcwd(buf, sizeof(buf))) {
		puts(buf);
		return 0;
	}
	perror("getcwd");
	return 1;
}
