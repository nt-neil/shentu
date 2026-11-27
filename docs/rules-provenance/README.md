# Rule provenance

Each file here records how one rule change was made: the vulnerability it was
designed from, the root cause read in the vulnerable release and its fix, the
design choices and the ones left out, the probes, the reviews and the numbers
before and after. The rules are designed from the vulnerability and its fix
alone; other tools' rules are not read, ported or adapted.

One file per rule change, named `<rule id>--<short name>.md`. Paths are
relative to the repository, or to the package root for upstream code. Upstream
code is quoted only in the few lines needed to show the cause.

## Sections

| section | what it holds |
|---|---|
| Case | the CVE and its bench case (`bench/cves/<id>.toml`), the package and releases, the class, and why the bench missed it |
| Root cause | the vulnerable line and the sink it reaches, what the upstream fix changed (a minimal excerpt), and which rule entry was missing |
| Design | what the change adds (source, sink, sanitizer or a new rule), why that side, the alternatives considered and why not, known limits |
| Probes | small neutral fixtures and counter-examples, each run on the base commit and on the new build, with the expected result |
| Process | the steps by role: rule lane (miss triage, design, probe), reviewer (review rounds), commander (approval, measurement gate) |
| Review | each review round: the head reviewed and its verdict (B blocking, N needed, S suggestion) |
| Measurement | cvebench in three groups (independent, rule source, holdout) and E7, before and after, with the load at the start and at the peak, and any segment voided and rerun |

A case a rule was designed from is cited in that rule's `refs`, so it counts
in the "rule source" group of the CVE bench, not in "independent"
(`bench/README.md`). Only `bench/holdout/` measures whether a change carries
over to cases it was not designed from.
