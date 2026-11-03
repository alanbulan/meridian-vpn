/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* LGPL-2.1-or-later. Actual native lifecycle code, mocked kernel only. */
#include <config.h>
#include "openconnect-internal.h"
#include <assert.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <signal.h>
static int tun_opens, alias_requests, fail_alias, exclusive;
int __real_open(const char *,int,...);
int __wrap_open(const char *path,int flags,...)
{
 if(!strcmp(path,"/dev/net/tun")||!strcmp(path,"/dev/tun")) {tun_opens++;return __real_open("/dev/null",O_RDWR);}
 if(flags&O_CREAT) {va_list ap;va_start(ap,flags);int m=va_arg(ap,int);va_end(ap);return __real_open(path,flags,m);}
 return __real_open(path,flags);
}
int __wrap_ioctl(int fd,unsigned long request,...)
{
 va_list ap;va_start(ap,request);struct ifreq *ifr=va_arg(ap,void *);va_end(ap);
 assert(request==TUNSETIFF);exclusive=!!(ifr->ifr_flags&IFF_TUN_EXCL);strcpy(ifr->ifr_name,"tun-test");return 0;
}
unsigned int __wrap_if_nametoindex(const char *name) {assert(!strcmp(name,"tun-test"));return 17;}
int __wrap_socket(int domain,int type,int proto) {assert(domain==AF_NETLINK&&proto==NETLINK_ROUTE);return __real_open("/dev/null",O_RDWR);}
int __wrap_setsockopt(int fd,int level,int opt,const void *p,socklen_t n) {return 0;}
ssize_t __wrap_sendto(int fd,const void *p,size_t n,int flags,const struct sockaddr *a,socklen_t l)
{
 const struct nlmsghdr *h=p; assert(h->nlmsg_type==RTM_NEWLINK);
 const struct ifinfomsg *i=NLMSG_DATA(h);assert(i->ifi_index==17);
 const struct rtattr *r=(void *)((char *)p+NLMSG_ALIGN(NLMSG_LENGTH(sizeof(*i))));
 assert(r->rta_type==IFLA_IFALIAS);assert(!strcmp(RTA_DATA(r),"meridian-0123456789abcdef0123456789abcdef"));alias_requests++;return n;
}
ssize_t __wrap_recvfrom(int fd,void *p,size_t n,int flags,struct sockaddr *a,socklen_t *l)
{
 struct {struct nlmsghdr h;struct nlmsgerr e;} reply={0};
 reply.h.nlmsg_len=NLMSG_LENGTH(sizeof(reply.e));reply.h.nlmsg_type=NLMSG_ERROR;reply.h.nlmsg_seq=1;reply.e.error=fail_alias?-EPERM:0;
 memcpy(p,&reply,reply.h.nlmsg_len);memset(a,0,*l);((struct sockaddr_nl *)a)->nl_family=AF_NETLINK;*l=sizeof(struct sockaddr_nl);return reply.h.nlmsg_len;
}
static void quiet(void *p,int level,const char *fmt,...) {}
int main(int argc, char **argv)
{
 int fixture=argc==2 && !strcmp(argv[1],"--emit-fixture");
 signal(SIGPIPE,SIG_IGN);
 struct openconnect_info *v=openconnect_vpninfo_new("test",NULL,NULL,NULL,quiet,NULL);assert(v);
 assert(!openconnect_set_protocol(v,"univpn"));
 assert(meridian_session_fd(v,"2")<0);assert(meridian_session_fd(v,"+3")<0);assert(meridian_session_fd(v,"03")<0);assert(meridian_session_fd(v,"999999999999999999999")<0);
 int p[2];assert(!pipe(p));char fd[32];snprintf(fd,sizeof(fd),"%d",p[0]);assert(meridian_session_fd(v,fd)<0);
 snprintf(fd,sizeof(fd),"%d",p[1]);assert(!meridian_session_fd(v,fd));assert(meridian_session_fd(v,fd)<0);assert(fcntl(p[1],F_GETFD)&FD_CLOEXEC);assert(fcntl(p[1],F_GETFL)&O_NONBLOCK);
 assert(meridian_session_validate(v)<0);assert(meridian_session_id(v,"ABC")<0);assert(!meridian_session_id(v,"0123456789abcdef0123456789abcdef"));assert(meridian_session_id(v,"0123456789abcdef0123456789abcdef")<0);assert(!meridian_session_validate(v));
 v->use_tun_script=1;assert(meridian_session_validate(v)<0);v->use_tun_script=0;
 assert(meridian_session_config(v)<0);assert(tun_opens==0);
 v->meridian_live=1;v->univpn=(void *)1;v->ssl_fd=10;v->aux_ssl_fd=11;
 fail_alias=1;assert(os_setup_tun(v)<0);assert(exclusive&&alias_requests==1);assert(meridian_session_config(v)<0);
 fail_alias=0;v->tun_fd=os_setup_tun(v);assert(v->tun_fd>=0&&exclusive&&v->meridian_index==17&&alias_requests==2);
 v->ip_info.addr="10.23.0.2";v->ip_info.netmask="255.255.255.0";
 struct sockaddr_in peer={.sin_family=AF_INET};inet_pton(AF_INET,"127.0.0.1",&peer.sin_addr);v->peer_addr=(void *)&peer;
 struct oc_split_include route={.route="10.24.0.0/16"};v->ip_info.split_includes=&route;
 assert(!meridian_session_config(v));assert(meridian_session_config(v)<0);
 char buf[32768];int n=read(p[0],buf,sizeof(buf)-1);assert(n>0);buf[n]=0;
 if(fixture) fputs(buf,stdout);
 assert(strstr(buf,"\"event\":\"config\"")&&strstr(buf,"\"index\":17")&&strstr(buf,"\"addresses\":[\"10.23.0.2/24\"]")&&strstr(buf,"\"routes\":[\"10.24.0.0/16\"]")&&buf[n-1]=='\n');
 /* Untrusted field cannot inject JSON; bounded route list cannot overflow. */
 v->meridian_emitted=0;v->ip_info.addr="bad\"field";assert(meridian_session_config(v)<0);v->ip_info.addr="10.23.0.2";
 route.next=&route;assert(meridian_session_config(v)<0);route.next=NULL;
 /* Pipe closed => no successful record. */
 close(p[0]);assert(meridian_session_config(v)<0);
 /* Full writer pipe must not block or claim emission. */
 assert(!pipe(p));close(v->meridian_fd);v->meridian_fd=0;snprintf(fd,sizeof(fd),"%d",p[1]);assert(!meridian_session_fd(v,fd));
 memset(buf,'x',sizeof(buf));while(write(p[1],buf,sizeof(buf))>0) {}
 assert(meridian_session_config(v)<0);
 while(read(p[0],buf,sizeof(buf))>0) { if(fcntl(p[0],F_SETFL,O_NONBLOCK)) abort(); }
 meridian_session_close(v);n=read(p[0],buf,sizeof(buf)-1);assert(n>0);buf[n]=0;assert(strstr(buf,"\"event\":\"closed\""));close(p[0]);assert(!v->meridian_fd&&!v->meridian_live);
 close(v->tun_fd);v->tun_fd=-1;v->ssl_fd=-1;v->aux_ssl_fd=-1;v->univpn=NULL;v->peer_addr=NULL;v->ip_info.addr=NULL;v->ip_info.netmask=NULL;v->ip_info.split_includes=NULL;
 openconnect_vpninfo_free(v);
 v=openconnect_vpninfo_new("test",NULL,NULL,NULL,quiet,NULL);assert(v);assert(!openconnect_set_protocol(v,"univpn"));
 assert(!pipe(p));snprintf(fd,sizeof(fd),"%d",p[1]);assert(!meridian_session_fd(v,fd));assert(!meridian_session_id(v,"0123456789abcdef0123456789abcdef"));
 univpn_shutdown(v);assert(v->meridian_fd); /* Initial auth reset preserves channel. */
 meridian_session_close(v);n=read(p[0],buf,sizeof(buf)-1);assert(n>0);buf[n]=0;assert(strstr(buf,"\"event\":\"no-network\""));if(fixture) fputs(buf,stdout);assert(read(p[0],buf,sizeof(buf))==0);close(p[0]);int prior=tun_opens;assert(os_setup_tun(v)<0);assert(tun_opens==prior);assert(meridian_session_config(v)<0);assert(univpn_connect(v)<0);assert(univpn_obtain_cookie(v)<0);assert(univpn_adopt_fds(v)<0);assert(meridian_session_fd(v,fd)<0);openconnect_vpninfo_free(v);fprintf(stderr,"UniVPN native session tests passed (mocked TUN/netlink, pipe only)\n");return 0;
}
