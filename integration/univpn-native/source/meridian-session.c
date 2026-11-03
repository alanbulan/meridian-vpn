/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* Meridian private UniVPN lifecycle pipe. LGPL-2.1-or-later.
 * This is authenticated native configuration, never broker readiness or rollback proof. */
#include <config.h>
#include "openconnect-internal.h"
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/un.h>
#endif
#ifdef __linux__
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <sys/time.h>
#endif

/* A packet relay socket is not a host TUN and conveys no interface ownership. */
int meridian_packet_fd(struct openconnect_info *v, const char *arg)
{
#ifdef __linux__
 unsigned long n=0; struct stat st; struct sockaddr_un peer,local; socklen_t len=sizeof(peer), llen=sizeof(local), ilen=sizeof(int); int type,proto;
 if(v->meridian_closed || v->meridian_packet_mode || !arg || !*arg || arg[0]=='0') return -EINVAL;
 for(const char *p=arg;*p;p++) { if(*p<'0'||*p>'9'||n>(INT_MAX-(unsigned)(*p-'0'))/10) return -EINVAL; n=n*10+(*p-'0'); }
 if(n<3 || n>=FD_SETSIZE || fstat(n,&st) || !S_ISSOCK(st.st_mode) ||
    getsockopt(n,SOL_SOCKET,SO_TYPE,&type,&ilen) || type!=SOCK_SEQPACKET ||
    getsockopt(n,SOL_SOCKET,SO_PROTOCOL,&proto,&ilen) || proto!=0 ||
    getsockname(n,(struct sockaddr *)&local,&llen) || local.sun_family!=AF_UNIX || llen!=sizeof(sa_family_t) ||
    getpeername(n,(struct sockaddr *)&peer,&len) || peer.sun_family!=AF_UNIX || len!=sizeof(sa_family_t)) return -EINVAL;
 if(fcntl(n,F_SETFD,FD_CLOEXEC)) return -EINVAL;
 v->meridian_packet_fd=n;v->meridian_packet_mode=1;return 0;
#else
 return -EOPNOTSUPP;
#endif
}
int meridian_packet_setup(struct openconnect_info *v)
{
#ifdef __linux__
 if(meridian_session_validate(v) || !v->meridian_packet_mode || v->meridian_packet_fd<0 ||
    !v->meridian_live || !v->univpn || v->ssl_fd<0 || v->aux_ssl_fd<0 || v->tun_fd>=0 || v->meridian_emitted) return -EINVAL;
 char *name=strdup("(packet-relay)");if(!name)return -ENOMEM;
 free(v->ifname);v->ifname=name;
 int fd=v->meridian_packet_fd;v->meridian_packet_fd=-1;
 int ret=openconnect_setup_tun_fd(v,fd);
 if(ret) { close(fd);v->tun_fd=-1;return ret; }
 v->meridian_packet_active=1;return 0;
#else
 return -EOPNOTSUPP;
#endif
}

int meridian_session_fd(struct openconnect_info *v, const char *arg)
{
#ifdef __linux__
 unsigned long n = 0; struct stat st; int flags;
 if (v->meridian_closed || v->meridian_fd || !arg || !*arg || (arg[0]=='0' && arg[1])) return -EINVAL;
 for (const char *p=arg; *p; p++) {
  if (*p<'0' || *p>'9' || n>(INT_MAX-(unsigned)(*p-'0'))/10) return -EINVAL;
  n=n*10+(*p-'0');
 }
 if (n<3 || fstat(n,&st) || !S_ISFIFO(st.st_mode)) return -EINVAL;
 flags=fcntl(n,F_GETFL);
 if (flags<0 || (flags&O_ACCMODE)!=O_WRONLY) return -EINVAL;
 if (fcntl(n,F_SETFD,FD_CLOEXEC) || fcntl(n,F_SETFL,flags|O_NONBLOCK)) return -EINVAL;
 v->meridian_fd=n; return 0;
#else
 return -EOPNOTSUPP;
#endif
}
int meridian_session_id(struct openconnect_info *v, const char *arg)
{
 if (v->meridian_session[0] || !arg || strlen(arg)!=32) return -EINVAL;
 for (unsigned i=0;i<32;i++) if (!((arg[i]>='0'&&arg[i]<='9')||(arg[i]>='a'&&arg[i]<='f'))) return -EINVAL;
 memcpy(v->meridian_session,arg,33); return 0;
}
int meridian_session_validate(struct openconnect_info *v)
{
 if (v->meridian_closed) return -EINVAL;
 if(v->meridian_packet_mode && (!v->meridian_fd || !v->meridian_session[0] ||
    (!v->univpn_fd_mode && (v->univpn_control_fd<3 || v->univpn_data_fd<3)) ||
    (v->meridian_packet_fd>=0 && (v->meridian_packet_fd==v->meridian_fd || v->meridian_packet_fd==v->univpn_control_fd || v->meridian_packet_fd==v->univpn_data_fd)))) return -EINVAL;
 if (!v->meridian_fd && !v->meridian_session[0]) return 0;
#ifdef __linux__
 if (!v->meridian_fd || !v->meridian_session[0] || v->proto->proto!=PROTO_UNIVPN || v->use_tun_script) return -EINVAL;
 return 0;
#else
 return -EOPNOTSUPP;
#endif
}
int meridian_session_mark(struct openconnect_info *v)
{
#ifdef __linux__
 struct { struct nlmsghdr h; struct ifinfomsg i; char attr[128]; } req;
 struct sockaddr_nl kernel={.nl_family=AF_NETLINK}, from;
 struct timeval timeout={.tv_sec=1}; char reply[4096], alias[64];
 socklen_t fromlen=sizeof(from); int fd, n, ret=-EIO;
 if (v->meridian_packet_mode || !v->meridian_live || !v->meridian_index || meridian_session_validate(v)) return -EINVAL;
 fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE); if(fd<0) return -errno;
 if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))) goto out;
 memset(&req,0,sizeof(req));
 req.h.nlmsg_len=NLMSG_LENGTH(sizeof(req.i)); req.h.nlmsg_type=RTM_NEWLINK;
 req.h.nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK; req.h.nlmsg_seq=1;
 req.i.ifi_family=AF_UNSPEC; req.i.ifi_index=v->meridian_index;
 snprintf(alias,sizeof(alias),"meridian-%s",v->meridian_session);
 struct rtattr *a=(void *)((char *)&req+NLMSG_ALIGN(req.h.nlmsg_len));
 a->rta_type=IFLA_IFALIAS; a->rta_len=RTA_LENGTH(strlen(alias)+1);
 memcpy(RTA_DATA(a),alias,strlen(alias)+1); req.h.nlmsg_len=NLMSG_ALIGN(req.h.nlmsg_len)+RTA_ALIGN(a->rta_len);
 if(sendto(fd,&req,req.h.nlmsg_len,0,(void *)&kernel,sizeof(kernel))!=(ssize_t)req.h.nlmsg_len) goto out;
 n=recvfrom(fd,reply,sizeof(reply),0,(void *)&from,&fromlen);
 if(n<0 || fromlen!=sizeof(from) || from.nl_pid || from.nl_family!=AF_NETLINK) goto out;
 struct nlmsghdr *h=(void *)reply;
 if(!NLMSG_OK(h,n) || h->nlmsg_seq!=1 || h->nlmsg_type!=NLMSG_ERROR || h->nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr))) goto out;
 ret=((struct nlmsgerr *)NLMSG_DATA(h))->error;
out:
 close(fd); if (!ret) v->meridian_marked=1; return ret;
#else
 return -EOPNOTSUPP;
#endif
}

/* Strict allowlist avoids JSON quoting ambiguities and bounds all native fields. */
static int safe(const char *s)
{
 if(!s || !*s || strlen(s)>255) return 0;
 for(;*s;s++) if(!((*s>='a'&&*s<='z')||(*s>='A'&&*s<='Z')||(*s>='0'&&*s<='9')||strchr("._:/-",*s))) return 0;
 return 1;
}
static int append(char *buf,size_t *used,const char *fmt,...)
{
 va_list ap; int n; va_start(ap,fmt); n=vsnprintf(buf+*used,32768-*used,fmt,ap); va_end(ap);
 if(n<0 || (size_t)n>=32768-*used) return -E2BIG;
 *used+=n; return 0;
}
int meridian_session_config(struct openconnect_info *v)
{
 char buf[32768], endpoint[INET6_ADDRSTRLEN]; size_t used=0; struct in_addr mask;
 unsigned prefix=0; uint32_t bits; int count=0;
 if(meridian_session_validate(v)) return -EINVAL;
 if(!v->meridian_fd) return 0;
 if(meridian_session_validate(v) || !v->meridian_live || !v->univpn || v->ssl_fd<0 || v->aux_ssl_fd<0 || v->tun_fd<0 || v->meridian_emitted || !safe(v->ip_info.addr) || !v->ip_info.netmask || !v->peer_addr) return -EINVAL;
 if(v->meridian_packet_mode) { if(!v->meridian_packet_active)return -EINVAL; }
 else if(v->meridian_index<=0 || !v->meridian_marked || !safe(v->ifname))return -EINVAL;
 if(inet_pton(AF_INET,v->ip_info.netmask,&mask)!=1) return -EINVAL;
 bits=ntohl(mask.s_addr); while(bits&0x80000000u) {prefix++;bits<<=1;} if(bits) return -EINVAL;
 if(v->peer_addr->sa_family==AF_INET) {
  if(!inet_ntop(AF_INET,&((struct sockaddr_in *)v->peer_addr)->sin_addr,endpoint,sizeof(endpoint))) return -EINVAL;
 } else if(v->peer_addr->sa_family==AF_INET6) {
  if(!inet_ntop(AF_INET6,&((struct sockaddr_in6 *)v->peer_addr)->sin6_addr,endpoint,sizeof(endpoint))) return -EINVAL;
 } else return -EINVAL;
#define ADD(...) do { if(append(buf,&used,__VA_ARGS__)) return -E2BIG; } while(0)
 if(v->meridian_packet_mode)
  ADD("{\"version\":2,\"event\":\"offer\",\"session\":\"%s\",\"addresses\":[\"%s/%u\"],\"routes\":[",v->meridian_session,v->ip_info.addr,prefix);
 else
 ADD("{\"version\":1,\"event\":\"config\",\"session\":\"%s\",\"interface\":\"%s\",\"index\":%d,\"alias\":\"meridian-%s\",\"addresses\":[\"%s/%u\"],\"routes\":[",v->meridian_session,v->ifname,v->meridian_index,v->meridian_session,v->ip_info.addr,prefix);
 for(struct oc_split_include *r=v->ip_info.split_includes;r;r=r->next) {
  if(++count>128 || !safe(r->route)) return -E2BIG;
  ADD("%s\"%s\"",count>1?",":"",r->route);
 }
 ADD("],\"dns\":["); count=0;
 for(unsigned i=0;i<3;i++) if(v->ip_info.dns[i]) {
  if(!safe(v->ip_info.dns[i])) return -EINVAL;
  ADD("%s\"%s\"",count++?",":"",v->ip_info.dns[i]);
 }
 ADD("],\"endpoint\":\"%s\"}\n",endpoint);
#undef ADD
 /* One nonblocking bounded write. Partial records, EPIPE, EAGAIN all fail closed. */
 if(write(v->meridian_fd,buf,used)!=(ssize_t)used) return -EIO;
 v->meridian_emitted=1; return 0;
}
void meridian_session_close(struct openconnect_info *v)
{
 if(v->meridian_fd) {
  char buf[128]; int n=snprintf(buf,sizeof(buf),"{\"version\":%d,\"event\":\"%s\",\"session\":\"%s\"}\n",v->meridian_packet_mode?2:1,v->meridian_packet_mode?"relay-closed":(v->meridian_acquired ? "closed" : "no-network"),v->meridian_session);
  if(v->meridian_session[0]) (void)write(v->meridian_fd,buf,n);
  close(v->meridian_fd); v->meridian_fd=0; v->meridian_closed=1;
 }
 v->meridian_live=0;
}
