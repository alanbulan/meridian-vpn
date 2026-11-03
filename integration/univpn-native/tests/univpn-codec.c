/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* LGPL-2.1-or-later */
#include "../univpn-codec.h"
#include <assert.h>
#include <stdio.h>
int main(void)
{
	unsigned cmd, len, type; const unsigned char *value; size_t pos;
	unsigned char h[] = {0xc1,0x92,0xa4,0xd6,1,0x66,0xff,0xff};
	unsigned char t[] = {0,99,0,2,42,43};
	unsigned char ip[20] = {0x45,0,0,20};
	unsigned char route[] = {10,0,0,0,8};
	for (int i = 0; i < 8; i++) assert(uv_header(h,i,&cmd,&len) == 0);
	assert(uv_header(h,8,&cmd,&len) == 1 && cmd == 0x66 && len == 65535);
	h[4] = 2; assert(uv_header(h,8,&cmd,&len) == -1);
	pos = 0; assert(uv_tlv(t,6,&pos,&type,&value,&len) == 1);
	assert(type == 99 && len == 2 && value[1] == 43);
	assert(uv_tlv(t,6,&pos,&type,&value,&len) == 0);
	for (int i = 1; i < 6; i++) { pos = 0; assert(uv_tlv(t,i,&pos,&type,&value,&len) == -1); }
	assert(uv_ipv4(ip,20)); ip[0] = 0x44; assert(!uv_ipv4(ip,20));
	ip[0] = 0x65; assert(!uv_ipv4(ip,20)); ip[0] = 0x46; assert(!uv_ipv4(ip,20));
	assert(uv_route(route)); route[3] = 1; assert(!uv_route(route));
	route[4] = 32; assert(uv_route(route)); route[4] = 33; assert(!uv_route(route));
	route[4] = 0; memset(route,0,4); assert(uv_route(route));
	puts("UniVPN codec tests passed"); return 0;
}
