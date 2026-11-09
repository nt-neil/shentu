---
name: daily-patrol
description: Daily security health report for this server.
---
Collect, in this order:
1. ssh_logins (since_hours 24): top attacking IPs and any successful logins from unusual IPs.
2. accounts_audit: extra UID 0 accounts, unexpected sudo rules, recently changed authorized_keys.
3. listening_ports: anything exposed on 0.0.0.0 / :: that is not a usual service.
4. processes: any suspicious process.
5. package_vulns: number of affected packages; name the 3 most affected.
6. cert_expiry: certificates expiring within 30 days.
7. app_code_audit: secrets or backups the web server serves, debug mode, webshells, keys in code, injection flaws (rule, file and line).

Report:
- First line: overall status — OK, Needs attention, or Urgent.
- Then at most 3 short sections with only what needs attention.
- Then up to 3 suggested actions.
Keep it under 20 lines.
