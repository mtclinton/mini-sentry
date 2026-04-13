/* echo.c — minimal echo(1) for testing mini-sentry.
 *
 * Prints its arguments space-separated followed by a newline. Built
 * statically so the sandbox doesn't need to load a dynamic linker.
 */

#include <stdio.h>

int main(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		if (i > 1) fputs(" ", stdout);
		fputs(argv[i], stdout);
	}
	fputs("\n", stdout);
	return 0;
}
