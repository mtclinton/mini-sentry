/* httpget.c — minimal HTTP/1.0 GET for mini-sentry network tests.
 *
 * Opens a TCP socket, connects to a hardcoded IP on port 80, asks for
 * example.com's root, and prints up to 1024 bytes of the response.
 *
 * No DNS — mini-sentry doesn't intercept resolv calls. The IP below is
 * a live example.com A record at the time the sample was added; update
 * if example.com moves.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define EXAMPLE_IP "172.66.147.243"
#define EXAMPLE_PORT 80

int main(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(EXAMPLE_PORT);
	if (inet_pton(AF_INET, EXAMPLE_IP, &sa.sin_addr) != 1) {
		fprintf(stderr, "inet_pton failed\n");
		return 1;
	}

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		perror("connect");
		return 1;
	}

	const char *req =
		"GET / HTTP/1.0\r\n"
		"Host: example.com\r\n"
		"\r\n";
	size_t reqlen = strlen(req);
	ssize_t sent = send(fd, req, reqlen, 0);
	if (sent < 0) {
		perror("send");
		return 1;
	}

	char buf[1024];
	ssize_t total = 0;
	while (total < (ssize_t)sizeof(buf)) {
		ssize_t n = recv(fd, buf + total, sizeof(buf) - total, 0);
		if (n <= 0) break;
		total += n;
	}
	close(fd);

	if (total > 0) {
		fwrite(buf, 1, total, stdout);
	}
	return 0;
}
