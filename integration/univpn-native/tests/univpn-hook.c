/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* LGPL-2.1-or-later. Direct hook execution tests; never creates a TUN. */
#include <config.h>
#include "openconnect-internal.h"
#include <assert.h>
static int tun_opens;
int __real_open(const char *, int, ...);
int __wrap_open(const char *path, int flags, ...)
{
 if (!strcmp(path, "/dev/net/tun") || !strcmp(path, "/dev/tun")) {
  tun_opens++; errno = EPERM; return -1;
 }
 if (flags & O_CREAT) {
  va_list ap; va_start(ap, flags); int mode = va_arg(ap,int); va_end(ap);
  return __real_open(path, flags, mode);
 }
 return __real_open(path, flags);
}
static void quiet(void *p, int level, const char *fmt, ...) {}
int main(int argc, char **argv)
{
 if (getenv("reason")) {
  assert(getpgrp() == (pid_t)atoi(getenv("UV_TEST_PGID")));
  return atoi(getenv("UV_TEST_EXIT"));
 }
 struct openconnect_info *v = openconnect_vpninfo_new("hook-test",NULL,NULL,NULL,quiet,NULL);
 assert(v && !openconnect_set_protocol(v,"univpn"));
 char group[32]; snprintf(group,sizeof(group),"%ld",(long)getpgrp());
 setenv("UV_TEST_PGID",group,1);setenv("UV_TEST_EXIT","0",1);
 char path[4096]; assert(realpath(argv[0],path));
 v->vpnc_script=strdup(path);
 assert(script_config_tun(v,"connect")==0);
 setenv("UV_TEST_EXIT","7",1);
 assert(script_config_tun(v,"connect")<0);
 free(v->vpnc_script); v->vpnc_script=strdup("/bin/true; /bin/true");
 assert(script_config_tun(v,"connect")<0); /* literal executable, not shell */
 free(v->vpnc_script); v->vpnc_script=strdup("/bin/false");
 /* Pre-init failure must return before attempting /dev/net/tun. */
 assert(openconnect_setup_tun_device(v,"/bin/false",NULL)<0);
 assert(tun_opens==0);
 openconnect_vpninfo_free(v);
 puts("UniVPN direct hook tests passed (no TUN)");return 0;
}
