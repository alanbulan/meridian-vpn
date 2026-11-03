/* Trusted single-threaded pre-exec bootstrap. Not setuid. See README.md. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <unistd.h>
#include "policy.h"

#define WORKER_UID 65532
#define WORKER_GID 65532
#define ROOT_FD 7
#define ROOT_PATH "/var/lib/meridian/worker-root"
#define NATIVE_PATH "/bin/meridian-univpn"

/* Injectable stage boundary. Tests execute no production operations. There is
 * no runtime override, plugin, environment switch or mock flag in the binary. */
struct operations {
 int (*entry)(void);
 int (*descriptors)(void);
 int (*namespaces)(void);
 int (*rootfs)(void);
 int (*close_root)(void);
 int (*identity)(void);
 int (*no_new_privs)(void);
 int (*filter)(void);
 int (*execute)(char **);
};
static int bootstrap_run(const struct operations *o, char **argv) {
 int (*const steps[])(void) = {o->entry,o->descriptors,o->namespaces,o->rootfs,
  o->close_root,o->identity,o->no_new_privs,o->filter};
 for (unsigned i=0;i<sizeof(steps)/sizeof(steps[0]);i++)
  if (steps[i]() != 0) return 100+(int)i;
 /* Any return, even zero from an injected exec, is failure. */
 (void)o->execute(argv);
 return 108;
}

#ifndef BOOTSTRAP_TEST
static int entry(void) {
 if (getuid()!=0 || geteuid()!=0 || getgid()!=0 || getegid()!=0) return -1;
 if (clearenv()) return -1;
 umask(077);
 struct rlimit core={0,0};
 if (setrlimit(RLIMIT_CORE,&core)) return -1;
 sigset_t empty;
 if (sigemptyset(&empty) || sigprocmask(SIG_SETMASK,&empty,NULL)) return -1;
 for (int i=1;i<NSIG;i++) {
  if (i==SIGKILL || i==SIGSTOP) continue;
  struct sigaction sa={.sa_handler=SIG_DFL};
  if (sigemptyset(&sa.sa_mask)) return -1;
  /* glibc reserves two internal real-time signal numbers. */
  if (sigaction(i,&sa,NULL) && errno!=EINVAL) return -1;
 }
 return prctl(PR_SET_DUMPABLE,0,0,0,0);
}
static int sockopt(int fd,int opt,int expected) {
 int value=0; socklen_t size=sizeof(value);
 return getsockopt(fd,SOL_SOCKET,opt,&value,&size) || size!=sizeof(value) || value!=expected ? -1:0;
}
static int pipe_fd(int fd,int mode) {
 struct stat s; int flags=fcntl(fd,F_GETFL);
 return fstat(fd,&s) || !S_ISFIFO(s.st_mode) || flags<0 || (flags&O_ACCMODE)!=mode ? -1:0;
}
/* Walk the fixed administrator-owned ancestry without symlinks. The manager
 * must keep it immutable for the entire session, including host mount topology. */
static int root_path_matches(void) {
 const char *parts[]={"var","lib","meridian","worker-root"};
 int fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(fd<0) return -1;
 struct stat expected, actual;
 if(fstat(ROOT_FD,&expected)) {close(fd);return -1;}
 for(unsigned i=0;i<sizeof(parts)/sizeof(parts[0]);i++) {
  if(fstat(fd,&actual) || actual.st_uid!=0 || (actual.st_mode&0022)) {close(fd);return -1;}
  int next=openat(fd,parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  int old=fd;fd=next;
  if(close(old) || fd<0) {if(fd>=0)close(fd);return -1;}
 }
 int bad=fstat(fd,&actual) || actual.st_uid!=0 || (actual.st_mode&0022) ||
  expected.st_dev!=actual.st_dev || expected.st_ino!=actual.st_ino;
 return close(fd) || bad ? -1:0;
}
static int descriptors(void) {
 struct stat s[8];
 for(int i=0;i<=ROOT_FD;i++) {
  int flags=fcntl(i,F_GETFD);
  if(flags<0 || (i<ROOT_FD && (flags&FD_CLOEXEC)) || fstat(i,&s[i])) return -1;
 }
 if(pipe_fd(0,O_RDONLY) || pipe_fd(3,O_WRONLY)) return -1;
 for(int i=1;i<=2;i++) {
  int flags=fcntl(i,F_GETFL);
  if(!S_ISCHR(s[i].st_mode) || major(s[i].st_rdev)!=1 || minor(s[i].st_rdev)!=3 ||
     flags<0 || (flags&O_ACCMODE)!=O_WRONLY) return -1;
 }
 if(!S_ISDIR(s[7].st_mode) || s[7].st_uid!=0 || (s[7].st_mode&0022) || root_path_matches()) return -1;
 for(int i=0;i<=7;i++) for(int j=i+1;j<=7;j++) {
  if(i==1 && j==2) continue;
  if(s[i].st_dev==s[j].st_dev && s[i].st_ino==s[j].st_ino) return -1;
 }
 struct sockaddr_in peer[2]; memset(peer,0,sizeof(peer));
 for(int i=4;i<=5;i++) {
  socklen_t len=sizeof(peer[0]);
  if(!S_ISSOCK(s[i].st_mode) || sockopt(i,SO_TYPE,SOCK_STREAM) ||
     sockopt(i,SO_DOMAIN,AF_INET) || sockopt(i,SO_PROTOCOL,IPPROTO_TCP) ||
     getpeername(i,(struct sockaddr *)&peer[i-4],&len) || len!=sizeof(peer[0]) ||
     peer[i-4].sin_family!=AF_INET || peer[i-4].sin_port==0) return -1;
 }
 if(peer[0].sin_port!=peer[1].sin_port || peer[0].sin_addr.s_addr!=peer[1].sin_addr.s_addr) return -1;
 int flags=fcntl(6,F_GETFL);
 if(!S_ISSOCK(s[6].st_mode) || sockopt(6,SO_TYPE,SOCK_SEQPACKET) ||
    sockopt(6,SO_DOMAIN,AF_UNIX) || sockopt(6,SO_PROTOCOL,0) || flags<0 || !(flags&O_NONBLOCK)) return -1;
 struct sockaddr_un addr; socklen_t len=sizeof(addr);
 if(getsockname(6,(struct sockaddr *)&addr,&len) || len!=sizeof(sa_family_t) || addr.sun_family!=AF_UNIX) return -1;
 len=sizeof(addr);
 if(getpeername(6,(struct sockaddr *)&addr,&len) || len!=sizeof(sa_family_t) || addr.sun_family!=AF_UNIX) return -1;
 /* No cgroup FD, namespace FD, broker socket or hidden descriptor may survive.
  * close_range is mandatory; do not replace this with a guessed RLIMIT loop. */
 return syscall(SYS_close_range,8U,UINT_MAX,0);
}
static int namespaces(void) {
 if(unshare(CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS)) return -1;
 return mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL);
}
static int rootfs(void) {
 if(root_path_matches()) return -1;
 /* No recursive bind: no host submounts are imported into the minimal tree. */
 if(mount(ROOT_PATH,ROOT_PATH,NULL,MS_BIND,NULL)) return -1;
 /* Absolute lookup traverses the new mount; chdir(".") from an underlying
  * pinned cwd is NOT a substitute. Recheck identity after traversal. */
 if(chdir(ROOT_PATH)) return -1;
 struct stat expected,actual;
 if(fstat(ROOT_FD,&expected) || stat(".",&actual) ||
    expected.st_dev!=actual.st_dev || expected.st_ino!=actual.st_ino) return -1;
 struct mount_attr attr={.attr_set=MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV};
 if(syscall(SYS_mount_setattr,AT_FDCWD,".",AT_RECURSIVE,&attr,sizeof(attr))) return -1;
 /* Stacked pivot from pivot_root(2), no writable old-root directory needed. */
 if(syscall(SYS_pivot_root,".",".")) return -1;
 if(umount2(".",MNT_DETACH)) return -1;
 return chdir("/");
}
static int close_root(void) {
 if(syscall(SYS_close_range,7U,UINT_MAX,0)) return -1;
 struct rlimit files={64,64};
 return setrlimit(RLIMIT_NOFILE,&files);
}
static int identity(void) {
 if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)) return -1;
 int cap;
 for(cap=0;cap<1024;cap++) {
  int present=prctl(PR_CAPBSET_READ,cap,0,0,0);
  if(present<0) { if(errno==EINVAL && cap>0) break; return -1; }
  if(prctl(PR_CAPBSET_DROP,cap,0,0,0) || prctl(PR_CAPBSET_READ,cap,0,0,0)!=0) return -1;
 }
 if(cap==1024) return -1;
 if(prctl(PR_SET_SECUREBITS,SECBIT_NOROOT|SECBIT_NOROOT_LOCKED|
          SECBIT_NO_SETUID_FIXUP|SECBIT_NO_SETUID_FIXUP_LOCKED|SECBIT_KEEP_CAPS_LOCKED,0,0,0)) return -1;
 if(setgroups(0,NULL) || setresgid(WORKER_GID,WORKER_GID,WORKER_GID) ||
    setresuid(WORKER_UID,WORKER_UID,WORKER_UID)) return -1;
 struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
 struct __user_cap_data_struct d[2]={{0},{0}};
 if(syscall(SYS_capset,&h,d) || syscall(SYS_capget,&h,d)) return -1;
 for(unsigned i=0;i<2;i++) if(d[i].effective || d[i].permitted || d[i].inheritable) return -1;
 uid_t r,e,s; gid_t gr,ge,gs;
 if(getresuid(&r,&e,&s) || r!=WORKER_UID || e!=r || s!=r ||
    getresgid(&gr,&ge,&gs) || gr!=WORKER_GID || ge!=gr || gs!=gr || getgroups(0,NULL)!=0) return -1;
 return prctl(PR_SET_DUMPABLE,0,0,0,0);
}
static int no_new_privs(void) {
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) return -1;
 return prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1 ? 0:-1;
}
static int filter(void) {
 struct sock_fprog p={.len=sizeof(worker_filter)/sizeof(worker_filter[0]),.filter=(struct sock_filter *)worker_filter};
 return syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&p);
}
static int execute(char **argv) {
 char *const env[]={"LANG=C","LC_ALL=C","HOME=/",NULL};
 argv[0]=NATIVE_PATH;
 return execve(NATIVE_PATH,argv,env);
}
int main(int argc,char **argv) {
 if(argc<2) _exit(99);
 const struct operations o={entry,descriptors,namespaces,rootfs,close_root,identity,no_new_privs,filter,execute};
 _exit(bootstrap_run(&o,argv));
}
#endif
