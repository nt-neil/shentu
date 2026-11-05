---
name: suspicious-process
description: Look for webshells, reverse shells and malware-like processes.
---
1. Run processes. Pay attention to deleted executables, programs running from /tmp, /dev/shm or
   /var/tmp, and shells started by web server users.
2. Run listening_ports and compare: a suspicious process that also listens on a port, or an
   unknown process on a high port, is more serious.
3. Run file_changes on the web root (for example /var/www) and look at webshell_patterns.
4. Run accounts_audit for persistence: new UID 0 accounts, new authorized_keys.
5. Report what you found, how confident you are, and what the operator should do: isolate the
   server, preserve evidence (do not delete files yet), kill the process, rotate credentials.
   You cannot kill processes or delete files; tell the operator the exact commands instead.
