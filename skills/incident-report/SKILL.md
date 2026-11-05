---
name: incident-report
description: Write a short incident timeline after a suspected compromise.
---
1. Ask the operator for the approximate time window if it is not known; default to the last 72 hours.
2. Gather the evidence: ssh_logins (successful logins and their source IPs), accounts_audit,
   file_changes for the same window, processes, listening_ports, and log_search for the
   attacker's IP in the auth log and web server logs.
3. Write a timeline: time, event, evidence source. Mark every inference as an inference.
4. Finish with: probable entry point, what the attacker may have touched, what is still unknown,
   and next steps (credential rotation, rebuild from a clean image, notify affected users).
