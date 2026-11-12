Recorded before auth_events read journald first (v0.3.0), so the fixture holds no journalctl output.
Replay takes the fallback path: journald is "not in fixture", /var/log/secure is read, and auth_events is partial with
unverified_source. Kept as it is to cover that path; see rocky9-journald-* for recordings with both sources.
