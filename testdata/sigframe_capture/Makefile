# Capture-harness build.  -static so the binary has no glibc-version
# surprises at runtime; -O0 -g so future investigators reading the
# disassembly aren't fighting the optimiser.  The binary is a build
# artefact and lives in .gitignore — only the committed hex oracle is
# tracked.

CC ?= gcc
CFLAGS ?= -static -O0 -g -Wall -Wextra

sigframe_capture: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sigframe_capture

.PHONY: clean
