# CVE bench

2026-11-16, 127 rules, 30 cases.

- caught: a rule of the case's class reports within 10 lines of a line the fix changed, in the vulnerable release.
- fixed FP: a rule that caught the case still reports at the fix in the fixed release; the rate is over caught cases.
- rule source: a rule cites the id in its refs, so the rule was written from it; independent: no rule cites it.
- in fix files: reports of the case's class anywhere in the fix files of the vulnerable release, near the fix or not.
- findings and time: every report of every rule on the whole release, and the time to scan it.

## Summary

| group | cases | caught | catch rate | fixed FP | fixed FP rate | findings per release (vulnerable / fixed) | scan time per release |
|---|---|---|---|---|---|---|---|
| all | 30 | 3 | 10.0% | 0 | 0.0% | 7.6 / 7.4 | 2.7s |
| independent | 30 | 3 | 10.0% | 0 | 0.0% | 7.6 / 7.4 | 2.7s |
| composer | 6 | 0 | 0.0% | 0 | - | 16.2 / 15.5 | 4.7s |
| npm | 6 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.0s |
| pypi | 5 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.4s |
| wordpress-plugin | 13 | 3 | 23.1% | 0 | 0.0% | 10.2 / 9.8 | 4.0s |
| cmdi | 4 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.0s |
| code-eval | 5 | 1 | 20.0% | 0 | 0.0% | 9.4 / 8.8 | 1.5s |
| deserialization | 8 | 1 | 12.5% | 0 | 0.0% | 6.2 / 5.8 | 2.4s |
| path-traversal | 6 | 1 | 16.7% | 0 | 0.0% | 1.5 / 1.3 | 1.3s |
| sqli | 7 | 0 | 0.0% | 0 | - | 17.6 / 17.6 | 6.8s |

<!-- measured at ccce0428f822a93b92a5171a9a87678b2008c8f7 -->
