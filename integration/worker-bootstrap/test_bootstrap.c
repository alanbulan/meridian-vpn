/* Only stage mocks and a userspace BPF interpreter run. No privileged operation,
 * namespaces, credentials, seccomp installation, socket, or child exec occurs. */
#define BOOTSTRAP_TEST
#include "bootstrap.c"
#include <assert.h>
#include <stdio.h>
static int index_seen, fail_at;
static int step(int expected) { assert(index_seen++==expected); return expected==fail_at ? -1:0; }
#define STEP(n) static int step##n(void) {return step(n);}
STEP(0) STEP(1) STEP(2) STEP(3) STEP(4) STEP(5) STEP(6) STEP(7)
static int test_exec(char **argv) {assert(argv[0]);return step(8);}
static uint32_t evaluate(const struct seccomp_data *data) {
 uint32_t accumulator=0;
 for(size_t pc=0;pc<sizeof(worker_filter)/sizeof(worker_filter[0]);pc++) {
  const struct sock_filter *f=&worker_filter[pc];
  if(f->code==(BPF_LD|BPF_W|BPF_ABS)) {
   assert(f->k+4<=sizeof(*data)); memcpy(&accumulator,(const char *)data+f->k,4);
  } else if(f->code==(BPF_RET|BPF_K)) return f->k;
  else {
   int yes=0;
   switch(f->code) {
    case BPF_JMP|BPF_JEQ|BPF_K: yes=accumulator==f->k;break;
    case BPF_JMP|BPF_JSET|BPF_K: yes=(accumulator&f->k)!=0;break;
    case BPF_JMP|BPF_JGE|BPF_K: yes=accumulator>=f->k;break;
    case BPF_JMP|BPF_JGT|BPF_K: yes=accumulator>f->k;break;
    default: assert(!"unsupported BPF instruction");
   }
   pc+=yes?f->jt:f->jf;
  }
 }
 assert(!"filter fell through"); return 0;
}
int main(void) {
 const struct operations o={step0,step1,step2,step3,step4,step5,step6,step7,test_exec};
 char *args[]={"bootstrap","--protocol=univpn",NULL};
 for(fail_at=0;fail_at<9;fail_at++) {
  index_seen=0; assert(bootstrap_run(&o,args)==100+fail_at);assert(index_seen==fail_at+1);
 }
 fail_at=-1;index_seen=0;assert(bootstrap_run(&o,args)==108);assert(index_seen==9);
 struct seccomp_data d={.arch=AUDIT_ARCH_X86_64,.nr=SYS_read};
 assert(evaluate(&d)==SECCOMP_RET_ALLOW);
 const int denied[]={SYS_socket,SYS_socketpair,SYS_connect,SYS_sendmsg,SYS_recvmmsg,
  SYS_clone,SYS_clone3,SYS_fork,SYS_vfork,SYS_unshare,SYS_setns,SYS_mount,SYS_umount2,
  SYS_ioctl,SYS_ptrace,SYS_process_vm_readv,SYS_process_vm_writev,SYS_pidfd_getfd,
  SYS_bpf,SYS_io_uring_setup,SYS_keyctl,SYS_kill,SYS_tkill,SYS_tgkill,SYS_setuid,
  SYS_setgid,SYS_setgroups,SYS_capset,SYS_prctl,SYS_seccomp,SYS_execveat,9999};
 for(size_t i=0;i<sizeof(denied)/sizeof(denied[0]);i++) {d.nr=denied[i];assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);}
 d.nr=SYS_read;d.arch=AUDIT_ARCH_I386;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 d.arch=AUDIT_ARCH_X86_64;d.nr=SYS_read|0x40000000;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 d.nr=SYS_recvmsg;
 for(unsigned fd=0;fd<20;fd++) {d.args[0]=fd;assert(evaluate(&d)==(fd==6?SECCOMP_RET_ALLOW:SECCOMP_RET_KILL_PROCESS));}
 d.args[0]=(1ULL<<32)|6;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 d.nr=SYS_sendto;
 for(unsigned fd=0;fd<20;fd++) {d.args[0]=fd;assert(evaluate(&d)==(fd>=4&&fd<=6?SECCOMP_RET_ALLOW:SECCOMP_RET_KILL_PROCESS));}
 d.args[0]=6;
 for(int arg=4;arg<=5;arg++) {
  d.args[arg]=1;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
  d.args[arg]=1ULL<<32;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);d.args[arg]=0;
 }
 d.args[0]=(1ULL<<32)|6;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 memset(d.args,0,sizeof(d.args)); d.nr=SYS_fcntl;
 for(unsigned cmd=0;cmd<4096;cmd++) {
  d.args[1]=cmd;
  assert(evaluate(&d)==(cmd==F_GETFD||cmd==F_GETFL||cmd==F_SETFD||cmd==F_SETFL?SECCOMP_RET_ALLOW:SECCOMP_RET_KILL_PROCESS));
 }
 d.args[1]=F_SETFL;
 d.args[2]=O_RDWR|O_NONBLOCK;assert(evaluate(&d)==SECCOMP_RET_ALLOW);
 d.args[2]=O_ASYNC|O_NONBLOCK;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 d.args[2]=1ULL<<32;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 d.args[1]=F_SETFD;d.args[2]=FD_CLOEXEC;assert(evaluate(&d)==SECCOMP_RET_ALLOW);
 d.args[2]=2;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 d.args[2]=1ULL<<32;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 d.args[1]=(1ULL<<32)|F_GETFD;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 memset(d.args,0,sizeof(d.args));d.nr=SYS_setsockopt;
 d.args[0]=4;d.args[1]=IPPROTO_TCP;d.args[2]=TCP_NODELAY;d.args[4]=sizeof(int);
 assert(evaluate(&d)==SECCOMP_RET_ALLOW);d.args[0]=5;assert(evaluate(&d)==SECCOMP_RET_ALLOW);
 d.args[0]=6;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);d.args[0]=4;
 const int checked_args[]={0,1,2,4};
 for(unsigned i=0;i<sizeof(checked_args)/sizeof(checked_args[0]);i++) {
  int a=checked_args[i];uint64_t value=d.args[a];d.args[a]=value|(1ULL<<32);
  assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);d.args[a]=value;
 }
 d.args[1]=SOL_SOCKET;d.args[2]=SO_ATTACH_FILTER;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 memset(d.args,0,sizeof(d.args));d.nr=SYS_prlimit64;
 assert(evaluate(&d)==SECCOMP_RET_ALLOW);
 for(int i=0;i<=2;i+=2) {d.args[i]=1;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);d.args[i]=1ULL<<32;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);d.args[i]=0;}
 d.nr=SYS_pipe;assert(evaluate(&d)==SECCOMP_RET_ALLOW);d.nr=SYS_pipe2;assert(evaluate(&d)==SECCOMP_RET_ALLOW);
 d.args[1]=O_CLOEXEC|O_NONBLOCK;assert(evaluate(&d)==SECCOMP_RET_ALLOW);
 d.args[1]=O_DIRECT;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 d.args[1]=1ULL<<32;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);
 /* Exhaust every syscall number with both ABIs: no unknown/future ABI passes. */
 for(int nr=0;nr<2048;nr++) {d.nr=nr|0x40000000;assert(evaluate(&d)==SECCOMP_RET_KILL_PROCESS);}
 puts("PASS: 9 stage failures, exec-return failure, syscall/ABI/FD policy tests (no kernel sandbox operations)");
 return 0;
}
