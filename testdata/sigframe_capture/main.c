/*
 * sigframe_capture — dump a kernel-generated rt_sigframe as hex.
 *
 * Installs a SIGUSR1 handler with SA_SIGINFO, raises SIGUSR1, and in
 * the handler memcpys the frame bytes to a static buffer.  After the
 * handler returns, main() writes the captured bytes to stderr as a
 * single line of lowercase hex, then a newline.
 *
 * Layout note: on amd64 the kernel writes the frame onto the user
 * stack low->high as { pretcode(8), ucontext(304), siginfo(128),
 * padding, fpstate(~592) } for a total of 1032 bytes.  The 3rd handler
 * argument is a pointer to the ucontext; the kernel writes pretcode
 * in the 8 bytes immediately below it.  Anchoring on `uc - 8` lets us
 * capture the whole frame including the restorer slot and mcontext.
 * (Anchoring on `si` would skip the entire ucontext — that's why the
 * earlier si-8 approach was wrong; si - 8 is just the low 8 bytes of
 * sigmask, not the restorer pointer.)
 */

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>

#define FRAME_SIZE 1032

static unsigned char frame_copy[FRAME_SIZE];
static size_t frame_size;

static void handler(int signo, siginfo_t *si, void *uc) {
    (void)signo;
    (void)si;
    unsigned char *frame_bottom = (unsigned char *)uc - 8;
    frame_size = FRAME_SIZE;
    memcpy(frame_copy, frame_bottom, frame_size);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        return 1;
    }
    raise(SIGUSR1);
    for (size_t i = 0; i < frame_size; i++) {
        fprintf(stderr, "%02x", frame_copy[i]);
    }
    fputc('\n', stderr);
    return 0;
}
