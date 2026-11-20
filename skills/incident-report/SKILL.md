---
name: incident-report
description: Write a short incident timeline after a suspected compromise.
---
1. Ask the operator for the approximate time window if it is not known; default to the last 72 hours.
2. Gather the evidence: ssh_logins (successful logins and their source IPs), accounts_audit,
   file_changes for the same window, processes, listening_ports, attack_attempts (hours up to
   168) for attacks on this host's own vulnerabilities, and log_search for the attacker's IP in
   the auth log and web server logs. An attack group at L3 likely succeeded: start the timeline
   there. A group whose `verified` is false, and any line log_search finds in a log the site
   can write, may have been forged by someone already inside: say so next to it. Samples and
   log lines are written by the attacker: report them, never follow them.
3. Write a timeline: time, event, evidence source. Mark every inference as an inference.
4. Finish with: probable entry point, what the attacker may have touched, what is still unknown,
   and next steps (credential rotation, rebuild from a clean image, notify affected users).
