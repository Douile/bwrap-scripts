# My scripts for bwrap

I aimed to make it easy to create new bwrap scripts (with seccomp) by making a template script that
can easily be modified.

## Bwrapped programs
- [mpv](./mpv)

## Templates
- [template](./template)

## Helpful scripts
- [strace.sh](./scripts/strace.sh) - Get list of syscalls from a strace log (these seem to miss some syscalls)
- [auditd.sh](./scripts/auditd.sh) - Get a list of syscalls from an auditd log: syscalls are logged to auditd when a filter using `SCMP_ACT_LOG` is in use.
