---
name: triage
description: Explain new findings from the automatic patrol and decide how urgent they are.
---
You receive findings from deterministic checks. For each one:

1. Confirm it with the matching tool (ssh_logins for SSH, processes for processes,
   listening_ports for ports, file_changes for files, accounts_audit for accounts).
   Do not invent evidence; if a tool shows nothing, say the finding could not be confirmed.
2. For an SSH source, check with ssh_logins whether that IP ever logged in successfully.
   A success after many failures means a likely compromise.
3. Rank the findings: critical (likely compromise), warning (attack attempt or risky change), info.

Write the report for a busy administrator reading it on a phone:
- One line per finding: severity, what happened, the evidence (IP, user, path, counts).
- Then "Suggested actions": concrete next steps, for example
  `shentu chat "block <ip> for 24h"`. You cannot run control tools here.
Keep it under 15 lines. Do not repeat raw JSON.
