/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* LGPL-2.1-or-later. TEST ONLY guard; not a production isolation mechanism. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
static void forbidden(void) { abort(); }
int connect(int fd,const struct sockaddr *a,socklen_t n) { forbidden();return -1; }
int getaddrinfo(const char *n,const char *s,const struct addrinfo *h,struct addrinfo **r) { forbidden();return EAI_FAIL; }
int socket(int family,int type,int protocol) {
 if(family==AF_NETLINK || family==AF_INET || family==AF_INET6)forbidden();
 int (*real)(int,int,int)=dlsym(RTLD_NEXT,"socket");return real(family,type,protocol);
}
int open(const char *path,int flags,...) {
 if(!strcmp(path,"/dev/net/tun")||!strcmp(path,"/dev/tun")||!strcmp(path,"/dev/vhost-net"))forbidden();
 int (*real)(const char *,int,...)=dlsym(RTLD_NEXT,"open");
 if(flags&O_CREAT) {va_list ap;va_start(ap,flags);int mode=va_arg(ap,int);va_end(ap);return real(path,flags,mode);}
 return real(path,flags);
}
int unshare(int flags) {forbidden();return -1;}
int setns(int fd,int kind) {forbidden();return -1;}

/* Fault injection only: no named socket is actually bound or listened on. */
int getsockname(int fd,struct sockaddr *addr,socklen_t *len) {
 int type;socklen_t n=sizeof(type);
 if(getenv("UNIVPN_TEST_NAMED_LOCAL") && !getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n) && type==SOCK_SEQPACKET) {
  struct sockaddr_un fake={.sun_family=AF_UNIX};strcpy(fake.sun_path,"test-name");
  socklen_t need=sizeof(sa_family_t)+strlen(fake.sun_path)+1;
  if(*len<need)return -1;memcpy(addr,&fake,need);*len=need;return 0;
 }
 int (*real)(int,struct sockaddr *,socklen_t *)=dlsym(RTLD_NEXT,"getsockname");return real(fd,addr,len);
}
