#include <seccomp.h>
#include <stdio.h>
#include <errno.h>

#define STAGE(STAGE) fprintf(stderr, "%s...\n", STAGE);

#define CHECK_ERROR() if (rc < 0) { goto cleanup; }

#define ALLOW_RULE(RULE) rc = seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(RULE), 0); \
                              CHECK_ERROR();

int main(void) {
  int rc = -1;
  scmp_filter_ctx filter;

  STAGE("Init");
  // Change this to log to identify what is killing the program
  // You can find the logs in one of:
  // - journalctl -e
  // - /var/log/messages
  // - /var/log/audit/audit.log
  filter = seccomp_init(SCMP_ACT_KILL);
  if (!filter) {
    // Failed to allocate filter
    goto cleanup;
  }

  STAGE("Add rules");

  ALLOW_RULE(wait4);
  ALLOW_RULE(access);
  ALLOW_RULE(bind);
  ALLOW_RULE(brk);
  ALLOW_RULE(capget);
  ALLOW_RULE(capset);
  ALLOW_RULE(chdir);
  ALLOW_RULE(chmod);
  ALLOW_RULE(clone);
  ALLOW_RULE(close);
  ALLOW_RULE(connect);
  ALLOW_RULE(creat);
  ALLOW_RULE(execve);
  ALLOW_RULE(exit);
  ALLOW_RULE(fallocate);
  ALLOW_RULE(fchdir);
  ALLOW_RULE(fcntl);
  ALLOW_RULE(fstatfs);
  ALLOW_RULE(ftruncate);
  ALLOW_RULE(futex);
  ALLOW_RULE(getcwd);
  ALLOW_RULE(getegid);
  ALLOW_RULE(geteuid);
  ALLOW_RULE(getgid);
  ALLOW_RULE(getpeername);
  ALLOW_RULE(getpgrp);
  ALLOW_RULE(getpid);
  ALLOW_RULE(getppid);
  ALLOW_RULE(getrandom);
  ALLOW_RULE(getsockname);
  ALLOW_RULE(getsockopt);
  ALLOW_RULE(gettid);
  ALLOW_RULE(getuid);
  ALLOW_RULE(ioctl);
  ALLOW_RULE(link);
  ALLOW_RULE(lseek);
  ALLOW_RULE(madvise);
  ALLOW_RULE(mkdir);
  ALLOW_RULE(mmap);
  ALLOW_RULE(mount);
  ALLOW_RULE(mprotect);
  ALLOW_RULE(munmap);
  ALLOW_RULE(newfstatat);
  ALLOW_RULE(openat);
  ALLOW_RULE(poll);
  ALLOW_RULE(prctl);
  ALLOW_RULE(read);
  ALLOW_RULE(readlink);
  ALLOW_RULE(recvfrom);
  ALLOW_RULE(recvmsg);
  ALLOW_RULE(rename);
  ALLOW_RULE(rseq);
  ALLOW_RULE(seccomp);
  ALLOW_RULE(sendmmsg);
  ALLOW_RULE(sendmsg);
  ALLOW_RULE(sendto);
  ALLOW_RULE(sethostname);
  ALLOW_RULE(setpriority);
  ALLOW_RULE(setsockopt);
  ALLOW_RULE(socket);
  ALLOW_RULE(statx);
  ALLOW_RULE(symlink);
  ALLOW_RULE(sysinfo);
  ALLOW_RULE(umask);
  ALLOW_RULE(uname);
  ALLOW_RULE(unlink);
  ALLOW_RULE(unshare);
  ALLOW_RULE(vfork);
  ALLOW_RULE(write);
  
  ALLOW_RULE(memfd_create);
  ALLOW_RULE(clone3);
  ALLOW_RULE(kill);
  ALLOW_RULE(fadvise64);
  ALLOW_RULE(exit_group);
  ALLOW_RULE(mremap);
  ALLOW_RULE(prlimit64);
  ALLOW_RULE(pread64);
  ALLOW_RULE(arch_prctl);
  ALLOW_RULE(close_range);
  ALLOW_RULE(dup2);
  ALLOW_RULE(pipe2);
  ALLOW_RULE(getdents64);
  ALLOW_RULE(clock_gettime);
  ALLOW_RULE(eventfd2);

  ALLOW_RULE(epoll_create1);
  ALLOW_RULE(epoll_wait);
  ALLOW_RULE(epoll_ctl);

  ALLOW_RULE(rt_sigprocmask);
  ALLOW_RULE(rt_sigreturn);
  ALLOW_RULE(set_tid_address);
  ALLOW_RULE(rt_sigaction);

  ALLOW_RULE(set_robust_list);

  ALLOW_RULE(sched_getaffinity);
  ALLOW_RULE(sched_setaffinity);
  ALLOW_RULE(sched_setscheduler);
  ALLOW_RULE(sched_getparam);
  ALLOW_RULE(sched_getscheduler);
  ALLOW_RULE(sched_get_priority_max);
  ALLOW_RULE(sched_get_priority_min);

  // Output as BPF
  rc = seccomp_export_bpf(filter, fileno(stdout));
  CHECK_ERROR();

  rc = seccomp_export_pfc(filter, fileno(stderr));
  CHECK_ERROR();


cleanup:
  seccomp_release(filter);

  return -rc;
}
