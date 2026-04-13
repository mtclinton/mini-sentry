/* ls.c — minimal ls(1) for testing mini-sentry.
 *
 * opendir() → readdir() → closedir(). Exercises openat on a directory
 * (O_DIRECTORY), fstat reporting S_IFDIR, and getdents64 walking the
 * VFS entries.
 */

#include <stdio.h>
#include <dirent.h>
#include <string.h>

int main(int argc, char **argv) {
	const char *path = (argc > 1) ? argv[1] : ".";
	DIR *d = opendir(path);
	if (!d) { perror(path); return 1; }
	struct dirent *e;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
		puts(e->d_name);
	}
	closedir(d);
	return 0;
}
