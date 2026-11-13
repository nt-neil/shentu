Rocky Linux 9 (arm64 VM), as root, 2026-11-13, right after rocky9-journald-ok-root, recorded with `hostfacts -journal-timeout 1ms`.
journalctl was stopped by the timeout (recorded as such), so auth_events falls back to /var/log/secure, marked unverified_source.
The detail on replay names the replaying binary's JournalTimeout, not the 1ms used here.
Re-masked offline as rocky9-journald-ok-root was.
