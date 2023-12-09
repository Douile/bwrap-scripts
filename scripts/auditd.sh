#!/bin/sh

# Extract syscall names from auditd log
# Auditd logs can usually be found in /var/log/audit

awk '/type=SECCOMP/ {match($0, /SYSCALL=([[:alnum:]]+)/, r); print r[1] }' < /dev/stdin | sort | uniq -c
