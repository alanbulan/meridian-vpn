/* SPDX-License-Identifier: MIT
 * Unprivileged authentication-only libopenconnect process. No tunnel API,
 * scripts, browser, certificate exceptions, disk output or diagnostics.
 * Protocol specification and trust boundary: README.md.
 */
#define _POSIX_C_SOURCE 200809L
#include <openconnect.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <arpa/inet.h>

#if !OPENCONNECT_CHECK_VER(5,9)
#error "libopenconnect API 5.9 (OpenConnect 9.12) or newer is required"
#endif
#define MAX_FRAME 65536
#define MAX_FIELDS 16
#define MAX_CHOICES 32
#define MAX_ROUNDS 8
struct frame { unsigned char data[MAX_FRAME]; size_t len, pos; int failed; };
struct state { char session[33]; unsigned int round; char *group; int group_applied; };
static void erase(void *p, size_t n) { volatile unsigned char *q=p; while(n--) *q++=0; }
static int transfer(int fd, void *p, size_t n, int writing) {
    unsigned char *q=p;
    while(n) { ssize_t k=writing?write(fd,q,n):read(fd,q,n);
        if(k<0 && errno==EINTR) continue;
        if(k<=0) return -1;
        q+=k; n-=(size_t)k;
    } return 0;
}
static void put(struct frame *f, const void *p, size_t n) {
    if(f->failed || n>MAX_FRAME-f->len) { f->failed=1; return; }
    memcpy(f->data+f->len,p,n); f->len+=n;
}
static void byte(struct frame *f, unsigned char n) { put(f,&n,1); }
static void u16(struct frame *f, unsigned int n) { unsigned char b[2]={(unsigned char)(n>>8),(unsigned char)n}; put(f,b,2); }
static unsigned int get16(struct frame *f) {
    if(f->failed || f->len-f->pos<2) { f->failed=1; return 0; }
    unsigned int n=((unsigned int)f->data[f->pos]<<8)|f->data[f->pos+1];f->pos+=2;return n;
}
static int valid_text(const char *s,size_t max,int multiline) {
    if(!s) return 1;
    size_t n=strnlen(s,max+1); if(n>max) return 0;
    for(size_t i=0;i<n;i++) { unsigned char c=(unsigned char)s[i];
        if((c<32 && !(multiline && (c=='\n'||c=='\t'))) || c==127) return 0;
    } return 1;
}
static void text(struct frame *f,const char *s,size_t max,int multiline) {
    if(!s) s="";
    if(!valid_text(s,max,multiline)) { f->failed=1; return; }
    size_t n=strlen(s); u16(f,(unsigned int)n); put(f,s,n);
}
static char *get_text(struct frame *f,size_t max) {
    unsigned int n=get16(f);
    if(f->failed || n>max || f->len-f->pos<n) { f->failed=1; return NULL; }
    char *s=calloc((size_t)n+1,1);if(!s) {f->failed=1;return NULL;}
    memcpy(s,f->data+f->pos,n);f->pos+=n;
    if(memchr(s,0,n) || !valid_text(s,max,0)) { erase(s,n);free(s); f->failed=1;return NULL; }
    return s;
}
static void free_secret(char *s) { if(s) { erase(s,strlen(s));free(s); } }
static void header(struct frame *f,const struct state *s,unsigned char type) {
    memset(f,0,sizeof(*f));byte(f,1);byte(f,type);put(f,s->session,32);u16(f,s->round);
}
static int send_frame(struct frame *f) {
    if(f->failed || f->len<36) return -1;
    uint32_t n=(uint32_t)f->len;
    unsigned char b[4]={(unsigned char)(n>>24),(unsigned char)(n>>16),(unsigned char)(n>>8),(unsigned char)n};
    return transfer(STDOUT_FILENO,b,4,1)||transfer(STDOUT_FILENO,f->data,f->len,1)?-1:0;
}
static int recv_frame(struct frame *f) {
    unsigned char b[4];memset(f,0,sizeof(*f));
    if(transfer(STDIN_FILENO,b,4,0)) return -1;
    uint32_t n=((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
    if(n<36||n>MAX_FRAME)return -1;
    f->len=n;return transfer(STDIN_FILENO,f->data,n,0);
}
static int check_header(struct frame *f,const struct state *s,int type) {
    if(f->len<36 || f->data[0]!=1 || f->data[1]!=type || memcmp(f->data+2,s->session,32))return -1;
    f->pos=34;return get16(f)==s->round?0:-1;
}
static int reject_certificate(void *priv,const char *reason) { (void)priv;(void)reason;return -1; }
static int reject_browser(struct openconnect_info *vpn,const char *uri,void *priv) { (void)vpn;(void)uri;(void)priv;_exit(2); }
static void discard_progress(void *priv,int level,const char *fmt,...) { (void)priv;(void)level;(void)fmt; }

static int process_form(void *priv,struct oc_auth_form *form) {
    struct state *s=priv;
    struct oc_form_opt *opts[MAX_FIELDS];unsigned int count=0, total=0;
    struct frame out,in;
    int rc=OC_FORM_RESULT_ERR,newgroup=0;
    if(!form || s->round>=MAX_ROUNDS) return OC_FORM_RESULT_ERR;
    // libopenconnect v9.12 can continue into its SSO handler even after a
    // callback returns an error. Terminate this isolated auth-only process
    // before that path, not merely return an overridable form error.
    for(struct oc_form_opt *o=form->opts;o;o=o->next) {
        if(++total>64)return OC_FORM_RESULT_ERR;
        if(o->type==OC_FORM_OPT_SSO_TOKEN || o->type==OC_FORM_OPT_SSO_USER)_exit(2);
    }
    // A configured group is matched exactly to server-provided id or label.
    if(form->authgroup_opt && s->group && *s->group) {
        struct oc_form_opt_select *g=form->authgroup_opt; int found=-1;
        if(g->nr_choices<1||g->nr_choices>MAX_CHOICES)return OC_FORM_RESULT_ERR;
        for(int i=0;i<g->nr_choices;i++) {
            if(!g->choices[i])return OC_FORM_RESULT_ERR;
            if((g->choices[i]->name && !strcmp(g->choices[i]->name,s->group)) || (g->choices[i]->label && !strcmp(g->choices[i]->label,s->group))) { if(found!=-1)return OC_FORM_RESULT_ERR; found=i; }
        }
        if(found<0)return OC_FORM_RESULT_ERR;
        int previously_applied=s->group_applied;
        s->group_applied=1;
        if(openconnect_set_option_value(&g->form,g->choices[found]->name))return OC_FORM_RESULT_ERR;
        if(found!=form->authgroup_selection)return previously_applied?OC_FORM_RESULT_ERR:OC_FORM_RESULT_NEWGROUP;
    }
    for(struct oc_form_opt *o=form->opts;o;o=o->next) {
        if(o->type==OC_FORM_OPT_HIDDEN || (o->flags&OC_FORM_OPT_IGNORE))continue;
        if(s->group_applied && form->authgroup_opt && o==&form->authgroup_opt->form)continue;
        if(count==MAX_FIELDS || !o->name || !*o->name || !valid_text(o->name,128,0))return OC_FORM_RESULT_ERR;
        if(o->type!=OC_FORM_OPT_TEXT && o->type!=OC_FORM_OPT_PASSWORD && o->type!=OC_FORM_OPT_SELECT && o->type!=OC_FORM_OPT_TOKEN)return OC_FORM_RESULT_ERR;
        for(unsigned int j=0;j<count;j++)if(!strcmp(o->name,opts[j]->name))return OC_FORM_RESULT_ERR;
        opts[count++]=o;
    }
    if(!count)return OC_FORM_RESULT_ERR;
    s->round++;header(&out,s,2);
    text(&out,form->auth_id?form->auth_id:"Authentication",2048,1);
    // No HTML rendering. Keep banner, message, and retry error visible as text.
    char message[4097];size_t used=0;message[0]=0;
    const char *parts[]={form->banner,form->message,form->error};
    for(unsigned int i=0;i<3;i++)if(parts[i]&&*parts[i]) {
        if(!valid_text(parts[i],4096,1))goto done;
        size_t n=strlen(parts[i]);if(used+n+(used?1:0)>4096)goto done;
        if(used) { message[used++]='\n'; }
        memcpy(message+used,parts[i],n);used+=n;message[used]=0;
    }
    text(&out,message,4096,1);u16(&out,count);
    for(unsigned int i=0;i<count;i++) {
        struct oc_form_opt *o=opts[i];text(&out,o->name,128,0);text(&out,o->label?o->label:o->name,2048,1);
        byte(&out,o->type==OC_FORM_OPT_TEXT?1:o->type==OC_FORM_OPT_SELECT?3:2);
        if(o->type!=OC_FORM_OPT_SELECT) { u16(&out,0);continue; }
        struct oc_form_opt_select *sel=(struct oc_form_opt_select *)o;
        if(sel->nr_choices<1||sel->nr_choices>MAX_CHOICES)goto done;
        u16(&out,(unsigned int)sel->nr_choices);
        for(int j=0;j<sel->nr_choices;j++) {
            struct oc_choice *choice=sel->choices[j];if(!choice || !choice->name || !*choice->name)goto done;
            for(int k=0;k<j;k++)if(!strcmp(choice->name,sel->choices[k]->name))goto done;
            text(&out,choice->name,128,0);text(&out,choice->label?choice->label:choice->name,2048,1);
        }
    }
    if(send_frame(&out) || recv_frame(&in) || check_header(&in,s,3))goto done;
    if(get16(&in)!=count)goto done;
    for(unsigned int i=0;i<count;i++) {
        char *id=get_text(&in,128),*value=get_text(&in,4096);
        if(!id || !value || strcmp(id,opts[i]->name)) { free_secret(id);free_secret(value);goto done; }
        if(opts[i]->type==OC_FORM_OPT_SELECT) {
            struct oc_form_opt_select *sel=(struct oc_form_opt_select *)opts[i];int found=-1;
            for(int j=0;j<sel->nr_choices;j++)if(!strcmp(value,sel->choices[j]->name))found=j;
            if(found<0){free_secret(id);free_secret(value);goto done;}
            if(sel==form->authgroup_opt && found!=form->authgroup_selection)newgroup=1;
        }
        int result=openconnect_set_option_value(opts[i],value);free_secret(id);free_secret(value);
        if(result)goto done;
    }
    if(in.failed || in.pos!=in.len)goto done;
    rc=newgroup?OC_FORM_RESULT_NEWGROUP:OC_FORM_RESULT_OK;
 done:
    erase(&in,sizeof(in));erase(&out,sizeof(out));return rc;
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--protocol-version")) { puts("meridian-auth-helper/1");return 0; }
    if(argc!=1 || geteuid()==0)return 2;
    struct rlimit core={0,0};if(setrlimit(RLIMIT_CORE,&core))return 2;
    signal(SIGPIPE,SIG_IGN);alarm(180);
    struct state s={0};struct frame in,out;
    struct openconnect_info *vpn=NULL;int rc=2;
    char *gateway=NULL,*ca=NULL,*proxy=NULL,*cert=NULL,*key=NULL,*pass=NULL;
    if(recv_frame(&in) || in.data[0]!=1 || in.data[1]!=1)goto done;
    memcpy(s.session,in.data+2,32);s.session[32]=0;
    for(int i=0;i<32;i++)if(!((s.session[i]>='0'&&s.session[i]<='9')||(s.session[i]>='a'&&s.session[i]<='f')))goto done;
    if(check_header(&in,&s,1))goto done;
    gateway=get_text(&in,2048);ca=get_text(&in,4096);proxy=get_text(&in,2048);cert=get_text(&in,4096);key=get_text(&in,4096);pass=get_text(&in,4096);s.group=get_text(&in,256);
    if(in.failed || in.pos!=in.len || !gateway || strncmp(gateway,"https://",8))goto done;
    if(openconnect_init_ssl())goto done;
    vpn=openconnect_vpninfo_new("Meridian auth-only",reject_certificate,NULL,process_form,discard_progress,&s);if(!vpn)goto done;
    openconnect_set_loglevel(vpn,0);
    openconnect_set_external_browser_callback(vpn,reject_browser);
    openconnect_set_webview_callback(vpn,reject_browser);
    // CSD is disabled by libopenconnect unless setup_csd is called. Never call it.
    // No HTTP/proxy integrated credentials, token generators, SSO, or tunnel APIs.
    if(openconnect_set_protocol(vpn,"anyconnect") || openconnect_set_http_auth(vpn,"none") || openconnect_set_proxy_auth(vpn,"none") || (*proxy && openconnect_set_http_proxy(vpn,proxy)) || openconnect_parse_url(vpn,gateway))goto done;
    if(*ca && openconnect_set_cafile(vpn,ca))goto done;
    if(*cert && openconnect_set_client_cert(vpn,cert,*key?key:NULL))goto done;
    if(*pass && openconnect_set_key_password(vpn,pass))goto done;
    free_secret(pass);pass=NULL;erase(&in,sizeof(in));
    if(openconnect_obtain_cookie(vpn))goto done;
    header(&out,&s,4);
    text(&out,openconnect_get_cookie(vpn),16384,0);
    text(&out,openconnect_get_connect_url(vpn),16384,0);
    text(&out,openconnect_get_peer_cert_hash(vpn),16384,0);
    // Preserve the authenticated endpoint and the original TLS/SNI hostname.
    const char *dns=openconnect_get_dnsname(vpn), *host=openconnect_get_hostname(vpn);
    char resolve[1024]="", address[INET6_ADDRSTRLEN];unsigned char numeric[16];
    if(dns && host && strcmp(dns,host)) {
        size_t n=strnlen(host,sizeof(address));
        if(n>=sizeof(address))goto done;
        if(n>=2 && host[0]=='[' && host[n-1]==']') { memcpy(address,host+1,n-2);address[n-2]=0; }
        else { memcpy(address,host,n+1); }
        if(inet_pton(AF_INET,address,numeric)==1 || inet_pton(AF_INET6,address,numeric)==1) {
            if(!valid_text(dns,253,0) || strchr(dns,':'))goto done;
            int length=snprintf(resolve,sizeof(resolve),"%s:%s",dns,address);
            if(length<0 || (size_t)length>=sizeof(resolve))goto done;
        }
    }
    text(&out,resolve,1023,0);
    if(send_frame(&out))goto done;
    rc=0;
 done:
    erase(&in,sizeof(in));erase(&out,sizeof(out));
    free_secret(gateway);free_secret(ca);free_secret(proxy);free_secret(cert);free_secret(key);free_secret(pass);free_secret(s.group);
    if(vpn)openconnect_vpninfo_free(vpn);
    erase(&s,sizeof(s));return rc;
}
