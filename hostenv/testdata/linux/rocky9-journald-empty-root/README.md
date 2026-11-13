Rocky Linux 9 (arm64 VM), as root, 2026-11-13, after `journalctl --rotate` and `journalctl --vacuum-time=1s` in the VM:
journald has no sshd entries while /var/log/secure still has them (a journal that is not kept), so auth_events reads
/var/log/secure, marked unverified_source, instead of reporting no failed logins.
Re-masked offline as rocky9-journald-ok-root was.
Added offline on 2026-11-13: the socket-unit query (journalctl -u 'ssh@*' -u 'sshd@*'), which the collector
asks since v0.3.0 when the ssh and sshd units are empty, answered "-- No entries --": the journal had been
vacuumed and Rocky 9 runs sshd as sshd.service, not socket-activated. Only that entry was added.
