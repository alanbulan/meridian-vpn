/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* UniVPN wire bounds shared by the client and standalone tests.
 * Copyright (C) 2026 UniVPN Connect contributors. LGPL-2.1-or-later. */
#ifndef OPENCONNECT_UNIVPN_CODEC_H
#define OPENCONNECT_UNIVPN_CODEC_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define UV_HEADER 8
#define UV_MAX_PAYLOAD 65535
static inline unsigned uv_be16(const unsigned char *p)
{
	return ((unsigned)p[0] << 8) | p[1];
}
static inline int uv_header(const unsigned char *p, size_t n, unsigned *cmd, unsigned *len)
{
	if (n < UV_HEADER) return 0;
	if (memcmp(p, "\xc1\x92\xa4\xd6\x01", 5)) return -1;
	*cmd = p[5]; *len = uv_be16(p + 6);
	return 1;
}
static inline int uv_tlv(const unsigned char *p, size_t n, size_t *offset,
			 unsigned *type, const unsigned char **value, unsigned *len)
{
	size_t pos = *offset;
	if (pos == n) return 0;
	if (pos > n || n - pos < 4) return -1;
	*type = uv_be16(p + pos); *len = uv_be16(p + pos + 2);
	if (*len > n - pos - 4) return -1;
	*value = p + pos + 4; *offset = pos + 4 + *len;
	return 1;
}
static inline int uv_ipv4(const unsigned char *p, size_t n)
{
	unsigned ihl;
	if (n < 20 || (p[0] >> 4) != 4) return 0;
	ihl = (p[0] & 15) * 4;
	return ihl >= 20 && ihl <= n && uv_be16(p + 2) == n;
}
static inline int uv_route(const unsigned char *p)
{
	uint32_t ip = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		((uint32_t)p[2] << 8) | p[3];
	if (p[4] > 32) return 0;
	return p[4] == 32 || !(ip & (p[4] ? (UINT32_MAX >> p[4]) : UINT32_MAX));
}
#endif
