Rocky Linux 9 (arm64 VM), as root, 2026-11-13, after `journalctl --rotate` and `journalctl --vacuum-time=1s` in the VM:
journald has no sshd entries while /var/log/secure still has them (a journal that is not kept), so auth_events reads
/var/log/secure, marked unverified_source, instead of reporting no failed logins.
Re-masked offline as rocky9-journald-ok-root was.
