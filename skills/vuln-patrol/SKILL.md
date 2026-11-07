---
name: vuln-patrol
description: Find vulnerable installed packages and suggest what to update first.
---
1. Run package_vulns without arguments, and app_vulns for the applications' own dependencies.
2. Anything listed under actively_exploited comes first: it is being exploited now (CISA KEV).
   Then pick up to 5 packages that matter most: network-facing services (openssh, nginx, apache2,
   openssl, sudo, the kernel, curl, the database) first, then the ones with the most vulnerabilities.
3. Run package_vulns with package set for each of them, and read the summaries and fixed versions.
4. Report: the package, how many vulnerabilities, the worst one in one sentence, and the update
   command for this distribution (upgrade_command), or for an app dependency the lock file to update.
   Note when a reboot or a service restart is needed.
If the tool reports it is offline, say the check could not run.
