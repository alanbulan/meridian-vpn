/* Modified version for Meridian; publication notices added 2026-11-03.
 * This file differs from pinned upstream OpenConnect through the documented
 * UniVPN and Meridian patch series. Original authorship and license notices
 * remain unchanged. Earlier patch dates are preserved where recorded; this
 * date identifies the notice addition, not an invented original change date.
 */
/* LGPL-2.1-or-later. Socket-acquisition/allocator fault injection: NO network. */
#include <config.h>
#include "openconnect-internal.h"
#include <openssl/ssl.h>
#include <assert.h>
static int failure, acquired=-1, closes;
SSL_CTX *__real_SSL_CTX_new(const SSL_METHOD *);
SSL *__real_SSL_new(SSL_CTX *);
BIO *__real_BIO_new_socket(int,int);
struct oc_text_buf *__real_buf_alloc(void);
int __real_close(int);
int __wrap_connect_https_socket(struct openconnect_info *v) { acquired=open("/dev/null",O_RDONLY);assert(acquired>=0);return acquired; }
SSL_CTX *__wrap_SSL_CTX_new(const SSL_METHOD *m) { return failure==1?NULL:__real_SSL_CTX_new(m); }
struct oc_text_buf *__wrap_buf_alloc(void) { return failure==2?NULL:__real_buf_alloc(); }
SSL *__wrap_SSL_new(SSL_CTX *c) { return failure==3?NULL:__real_SSL_new(c); }
BIO *__wrap_BIO_new_socket(int fd,int mode) { return failure==4?NULL:__real_BIO_new_socket(fd,mode); }
int __wrap_close(int fd) { if(fd==acquired)closes++;return __real_close(fd); }
static void quiet(void *p,int level,const char *fmt,...) {}
int main(void)
{
 for(int i=1;i<=4;i++) {
  failure=0;closes=0;
  struct openconnect_info *v=openconnect_vpninfo_new("cleanup-test",NULL,NULL,NULL,quiet,NULL);assert(v);
  assert(!openconnect_set_protocol(v,"univpn"));assert(!openconnect_parse_url(v,"https://broker-only.invalid"));
  failure=i;assert(openconnect_open_https(v)<0);failure=0;
  assert(acquired>=0&&fcntl(acquired,F_GETFD)==-1&&errno==EBADF&&closes==1);
  acquired=-1;openconnect_vpninfo_free(v);
 }
 puts("TLS allocation-failure descriptor cleanup: 4/4 passed (no network)");return 0;
}
