Rocky Linux 9 (arm64 VM), as root, 2026-11-13. Both auth sources are present: journald and rsyslog's /var/log/secure.
Five failed logins for nonexistent users were made to 127.0.0.1 first. auth_events reads journald (verified).
Re-masked offline after recording: older sudo lines in /var/log/secure carried the names of an earlier recording's -mask-user/-mask-host flags.
