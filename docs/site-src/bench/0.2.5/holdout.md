# CVE bench

2026-11-10, 70 rules, 30 cases.

- caught: a rule of the case's class reports within 10 lines of a line the fix changed, in the vulnerable release.
- fixed FP: a rule that caught the case still reports at the fix in the fixed release; the rate is over caught cases.
- rule source: a rule cites the id in its refs, so the rule was written from it; independent: no rule cites it.
- in fix files: reports of the case's class anywhere in the fix files of the vulnerable release, near the fix or not.
- findings and time: every report of every rule on the whole release, and the time to scan it.

## Summary

| group | cases | caught | catch rate | fixed FP | fixed FP rate | findings per release (vulnerable / fixed) | scan time per release |
|---|---|---|---|---|---|---|---|
| all | 30 | 2 | 6.7% | 0 | 0.0% | 5.3 / 5.1 | 5.9s |
| independent | 30 | 2 | 6.7% | 0 | 0.0% | 5.3 / 5.1 | 5.9s |
| composer | 6 | 0 | 0.0% | 0 | - | 14.7 / 14.0 | 9.5s |
| npm | 6 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.0s |
| pypi | 5 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 1.2s |
| wordpress-plugin | 13 | 2 | 15.4% | 0 | 0.0% | 5.5 / 5.2 | 8.8s |
| cmdi | 4 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.1s |
| code-eval | 5 | 0 | 0.0% | 0 | - | 8.6 / 8.2 | 2.9s |
| deserialization | 8 | 1 | 12.5% | 0 | 0.0% | 5.8 / 5.4 | 5.0s |
| path-traversal | 6 | 1 | 16.7% | 0 | 0.0% | 1.5 / 1.2 | 3.2s |
| sqli | 7 | 0 | 0.0% | 0 | - | 8.7 / 8.7 | 14.8s |

<!-- measured at integ-3205c10 -->
