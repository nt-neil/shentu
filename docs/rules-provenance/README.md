# Rule provenance

Each file here records how one rule change was made: the vulnerability it was
designed from, the root cause read in the vulnerable release and its fix, the
design choices and the ones left out, the probes, the reviews and the numbers
before and after. The rules are designed from the vulnerability and its fix
alone; other tools' rules are not read, ported or adapted.

One file per rule change, named `<rule id>--<short name>.md` (see Kinds for route models and engine changes). Paths are
relative to the repository, or to the package root for upstream code. Upstream
code is quoted only in the few lines needed to show the cause.

## Kinds

A record's kind is one line between its title and its first section, written
exactly `Kind: cve` or `Kind: precision`; a record without one is a `cve`
record. A Kind line anywhere else, a second one, or any other spelling or value
is refused, never read as `cve`.

| kind | for | file name | must hold |
|---|---|---|---|
| `cve` | a change designed from a CVE: a rule, a source or sink, a route model, or an engine change made so a rule or route model catches that case | `<rule or route model id>--<short name>.md`: an engine change made for a CVE takes the id of the rule or route model that catches it | a Case section naming the `bench/cves/` case; that rule or route model cites it in `refs`; not a hold-out case |
| `precision` | a change no CVE was designed from: cutting false positives, or the engine itself (a condition, a cap, how a flow is followed), such as #284's `not_array` and `receivers` | `engine--<short name>.md` for an engine change; `<rule or route model id>--<short name>.md` only for a rule that cites a CVE in `refs` and already has its `cve` record | no `refs` (a citation would be made up); a Measured on section naming the cases the change was designed and measured on, from `bench/cves/` or `bench/cves-ts/` only, with the line-by-line summary and the numbers in a table (a `\|---` row and a row with a number) |

`engine--` is for `precision` records only. A new rule always starts with a
`cve` record: `precision` cannot stand in for one. Rules older than these
records, with no `cve` record yet, are listed in
`rules/testdata/provenance-legacy.txt`; that list may only shrink.

Hold-out cases stay independent. A `precision` record may name one only in a
section of its own, `## Holdout check`, showing the change made it no worse;
nowhere else, and never as a reason for the change. (A `cve` record cannot use a
hold-out case at all.)

Both kinds keep the other sections below where they apply, and neither names
another analysis tool or a model. `rules/provenance_test.go` checks all of this.

## Sections

| section | what it holds |
|---|---|
| Case | the CVE and its bench case (`bench/cves/<id>.toml`), the package and releases, the class, and why the bench missed it |
| Root cause | the vulnerable line and the sink it reaches, what the upstream fix changed (a minimal excerpt), and which rule entry was missing |
| Design | what the change adds (source, sink, sanitizer or a new rule), why that side, the alternatives considered and why not, known limits |
| Probes | small neutral fixtures and counter-examples, each run on the base commit and on the new build, with the expected result |
| Process | the steps by role: rule lane (miss triage, design, probe), reviewer (review rounds), commander (approval, measurement gate) |
| Review | each review round: the head reviewed and its verdict (B blocking, N needed, S suggestion) |
| Measured on | precision records: the cves and cves-ts cases measured on, and for each the lines that changed and the numbers before and after (a table) |
| Holdout check | precision records, optional: the hold-out cases run on base and head, to show no change made them worse |
| Measurement | cvebench in three groups (independent, rule source, holdout) and E7, before and after, with the load at the start and at the peak, and any segment voided and rerun |

A case a rule was designed from is cited in that rule's `refs`, so it counts
in the "rule source" group of the CVE bench, not in "independent"
(`bench/README.md`). Only `bench/holdout/` measures whether a change carries
over to cases it was not designed from.
