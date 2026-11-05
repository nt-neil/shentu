---
name: ssh-bruteforce
description: Investigate SSH brute-force attempts and decide whether to block the source.
---
1. Run ssh_logins (since_hours 24). Note the IPs with the most failed or invalid-user attempts.
2. For each top IP, check `accepted`. If it is above 0, treat it as a possible compromise:
   run accounts_audit and processes, and say so clearly.
3. Check the hardening: log_search on the auth log for "Accepted password" to see whether password
   login is in use. Recommend key-only login and fail2ban-style blocking if it is.
4. If an IP made many failed attempts and never logged in, propose block_ip with ttl 24h and the
   reason "SSH brute force: N failed attempts". The operator will confirm. Never propose blocking
   an IP that has successful logins without saying it might be a legitimate user.
