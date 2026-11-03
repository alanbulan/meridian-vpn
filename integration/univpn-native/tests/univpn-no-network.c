/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* LGPL-2.1-or-later. TEST ONLY interposition, not a security sandbox. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
int connect(int fd, const struct sockaddr *addr, socklen_t len) { errno=EPERM; return -1; }
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) { return EAI_FAIL; }
