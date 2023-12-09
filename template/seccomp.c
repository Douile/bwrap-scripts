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

  // TODO: Put rules here

  // Output as BPF
  rc = seccomp_export_bpf(filter, fileno(stdout));
  CHECK_ERROR();

  rc = seccomp_export_pfc(filter, fileno(stderr));
  CHECK_ERROR();


cleanup:
  seccomp_release(filter);

  return -rc;
}
