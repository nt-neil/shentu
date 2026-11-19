---
name: ssh-bruteforce
description: Investigate SSH brute-force attempts and decide whether to block the source.
---
1. Run ssh_logins (since_hours 24). Note the IPs with the most failed or invalid-user attempts.
   If `verified` is false, the events come from text logs that any local user can write to:
   say so, and do not propose block_ip on these counts alone. Check first (journalctl -u ssh,
   the IP's other connections). If `complete` is false, the counts are a lower bound.
2. For each top IP, check `accepted`. If it is above 0, treat it as a possible compromise:
   run accounts_audit and processes, and say so clearly.
3. Check the hardening: log_search on the auth log for "Accepted password" to see whether password
   login is in use. Recommend key-only login and fail2ban-style blocking if it is.
4. If an IP made many failed attempts and never logged in, propose block_ip with ttl 24h and the
   reason "SSH brute force: N failed attempts". The operator will confirm. Never propose blocking
   an IP that has successful logins without saying it might be a legitimate user.
   block_ip checks the evidence itself. If attack detection saw the IP, only a verified L2 or L3
   group of that IP's own backs the block (not an overflow summary); attempts only at L1 or
   Unknown, only in an overflow summary, or only from logs anyone here can write are refused,
   unless journald events written by sshd itself condemn the IP. Otherwise its SSH login events
   decide: block_ip refuses an IP whose events are only in text logs, are journald lines sshd
   did not write itself (for example from logger inside sshd's unit), or could not be read in
   full. It also refuses internal addresses (private, CGNAT), which may be a proxy or load
   balancer. Besides attack detection, that check covers SSH login evidence only. On the server
   (shentu chat), a block based on any other log (log_search over syslog, nginx or an
   application log) is not checked by it: say where the evidence came from and that anyone on
   the host may have written it, so the operator judges it.
   From Telegram only an IP with verified evidence can be blocked (a verified L2 or L3 attack
   group listing it, or SSH logins sshd itself logged); any other IP is for the server, with
   shentu chat. A refused block can be made only there, with override_unverified, after the
   operator has checked the logs; an overflow summary is refused even then.
