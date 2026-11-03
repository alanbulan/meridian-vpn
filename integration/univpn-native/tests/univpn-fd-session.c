/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* LGPL-2.1-or-later. Synthetic credentials; dual TLS + session pipe, NO TUN. */
#include <config.h>
#include "openconnect-internal.h"
#include <assert.h>
static int tun_opens;
int __real_open(const char *, int, ...);
int __wrap_open(const char *path, int flags, ...)
{
 if (!strcmp(path,"/dev/net/tun") || !strcmp(path,"/dev/tun")) { tun_opens++; errno=EPERM; return -1; }
 if (flags&O_CREAT) { va_list ap;va_start(ap,flags);int m=va_arg(ap,int);va_end(ap);return __real_open(path,flags,m); }
 return __real_open(path,flags);
}
static void quiet(void *p,int level,const char *fmt,...) {}
static int auth(void *p, struct oc_auth_form *f)
{
 for (struct oc_form_opt *o=f->opts;o;o=o->next) {
  if (!strcmp(o->name,"username")) assert(!openconnect_set_option_value(o,"mockuser"));
  if (!strcmp(o->name,"password")) assert(!openconnect_set_option_value(o,"mock&+%pass"));
 }
 return 0;
}
int main(int argc,char **argv)
{
 assert(argc==6);
 struct openconnect_info *v=openconnect_vpninfo_new("fd-session-test",NULL,NULL,auth,quiet,NULL);assert(v);
 assert(!openconnect_set_protocol(v,"univpn"));assert(!openconnect_parse_url(v,argv[2]));
 assert(!openconnect_set_cafile(v,argv[1]));v->authgroup=strdup("localhost");
 assert(!meridian_session_fd(v,argv[3]));assert(!meridian_session_id(v,"0123456789abcdef0123456789abcdef"));
 v->univpn_control_fd=atoi(argv[4]);v->univpn_data_fd=atoi(argv[5]);
 assert(!univpn_obtain_cookie(v));assert(!univpn_connect(v));
 assert(v->meridian_live && v->univpn_control_fd==-1 && v->univpn_data_fd==-1 && v->univpn_preconnected_fd==-1);
 assert(tun_opens==0 && !v->meridian_acquired);
 /* Once consumed, reconnect cannot make an outbound connection or resolve. */
 assert(connect_https_socket(v)<0);
 meridian_session_close(v);assert(univpn_connect(v)<0);assert(univpn_obtain_cookie(v)<0);assert(univpn_adopt_fds(v)<0);
 openconnect_vpninfo_free(v);assert(tun_opens==0);
 puts("Combined session pipe + inherited dual TLS passed (zero TUN opens)");return 0;
}
