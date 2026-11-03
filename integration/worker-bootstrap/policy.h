#ifndef MERIDIAN_WORKER_POLICY_H
#define MERIDIAN_WORKER_POLICY_H
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#if !defined(__x86_64__) || defined(__ILP32__)
#error "Only the reviewed Linux x86-64 LP64 syscall ABI is supported"
#endif
#define ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_##n, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
/* No socket creation/connect, descriptor reception except the trusted packet
 * peer on fd 6, process creation, namespace changes, mount, ioctl, ptrace,
 * pidfd_getfd, process_vm_*, io_uring, bpf, keyring, or privilege syscalls.
 * File opens only see the immutable, minimal root. New/unknown calls kill.
 * x32 numbers and every non-x86-64 ABI fail closed. */
static const struct sock_filter worker_filter[] = {
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
 BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x40000000, 0, 1),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 /* recvmsg is necessary for MSG_TRUNC/MSG_CTRUNC packet rejection. The
  * exclusively owned broker peer must NEVER send SCM_RIGHTS or credentials. */
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_recvmsg, 0, 6),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 3),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 6, 0, 1),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 /* send()/TLS sendto() may only use the three inherited transports and
  * cannot supply a destination address or length. */
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_sendto, 0, 21),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
 BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 4, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K, 6, 0, 1),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[4])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[4])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[5])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[5])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
 /* fcntl cannot set signal ownership/O_ASYNC or leak descriptors. */
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_fcntl, 0, 23),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, F_GETFD, 17, 0),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, F_GETFL, 16, 0),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, F_SETFD, 8, 0),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, F_SETFL, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])),
 BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, ~(O_ACCMODE|O_NONBLOCK), 0, 8),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 /* F_SETFD supports only clearing or setting FD_CLOEXEC. */
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])),
 BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, ~FD_CLOEXEC, 0, 2),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
 /* Native preconnected TLS sets TCP_NODELAY, never arbitrary socket options. */
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_setsockopt, 0, 27),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
 BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 4, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K, 5, 0, 1),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_TCP, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, TCP_NODELAY, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[4])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[4])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, sizeof(int), 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
 /* libc loader/getrlimit: query own process only; never change a limit. */
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_prlimit64, 0, 13),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_pipe2, 0, 7),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])+4),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
 BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, ~(O_CLOEXEC|O_NONBLOCK), 0, 1),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
 ALLOW(read), ALLOW(write), ALLOW(readv), ALLOW(writev), ALLOW(close),
 ALLOW(fstat), ALLOW(newfstatat), ALLOW(stat), ALLOW(lstat), ALLOW(statx),
 ALLOW(open), ALLOW(openat), ALLOW(access), ALLOW(faccessat), ALLOW(readlink),
 ALLOW(readlinkat), ALLOW(lseek), ALLOW(pread64), ALLOW(getdents64),
 ALLOW(mmap), ALLOW(mprotect), ALLOW(munmap), ALLOW(mremap), ALLOW(madvise), ALLOW(brk),
 ALLOW(rt_sigaction), ALLOW(rt_sigprocmask), ALLOW(rt_sigreturn), ALLOW(sigaltstack),
 ALLOW(poll), ALLOW(ppoll), ALLOW(select), ALLOW(pselect6),
 ALLOW(epoll_create1), ALLOW(epoll_ctl), ALLOW(epoll_wait), ALLOW(epoll_pwait),
 ALLOW(dup), ALLOW(dup2), ALLOW(dup3),
 ALLOW(getsockopt), ALLOW(getsockname), ALLOW(getpeername),
 ALLOW(recvfrom), ALLOW(shutdown),
 ALLOW(clock_gettime), ALLOW(gettimeofday), ALLOW(time), ALLOW(nanosleep),
 ALLOW(clock_nanosleep), ALLOW(getrandom), ALLOW(uname), ALLOW(getcwd),
 ALLOW(getuid), ALLOW(geteuid), ALLOW(getgid), ALLOW(getegid), ALLOW(getgroups),
 ALLOW(getpid), ALLOW(gettid), ALLOW(getppid), ALLOW(getrlimit),
 ALLOW(arch_prctl), ALLOW(set_tid_address), ALLOW(set_robust_list), ALLOW(rseq),
 ALLOW(pipe), ALLOW(futex), ALLOW(sched_yield), ALLOW(restart_syscall),
 ALLOW(execve), ALLOW(exit), ALLOW(exit_group),
 BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS)
};
#undef ALLOW
#endif
