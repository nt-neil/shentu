# CVE bench

`go run ./cmd/cvebench` measures the code rules against real, published
vulnerabilities. For each case in `cves/` it downloads the last vulnerable and
the first fixed release of the package, scans both with `rules/engine`, and
writes a Markdown table: which rule caught which case, the catch rate, the
false-positive rate on fixed releases, and how many findings and how much time
each release took. `baseline.md` (cves), `baseline-holdout.md` and
`baseline-cves-ts.md` are the runs to compare later ones with: integ e0d8f79d
on 2026-11-28, on the product scan path (the default since then; each report's
header names it). The first run (2026-11-09, 59 cases) scanned file by file (as
`-scanpath per-file` now) and is in the history of `baseline.md`; compare it only
with a `-scanpath per-file` run.

The tool runs on a developer machine only. It is not built into the released
binary (`.goreleaser.yaml` builds the root package alone).

## Safety

- Downloads come only from `downloads.wordpress.org` (WordPress plugins),
  `codeload.github.com` (Composer packages, by git tag), PyPI (sdists, checked
  against the registry's sha256) and the npm registry (checked against its
  sha512). They are cached in the user cache directory
  (`~/Library/Caches/shentu-cvebench` on macOS), never in the repository.
- Each release is unpacked into its own new, empty directory. Entry names that
  are absolute, hold a backslash or climb out with `..` fail the release; links
  and devices are skipped; only files in a rule language are written; nothing is
  made executable. There are caps on file count and size.
- Nothing in a release is executed. The engine only reads the files.

## Cases

One file per vulnerability, `cves/<id>.toml` (TypeScript cases in `cves-ts/`, run with `-cases bench/cves-ts`). A case holds facts, never code:

| field | |
|---|---|
| `id` | CVE or GHSA id, also the file name |
| `ecosystem` | `wordpress-plugin`, `composer`, `pypi`, `npm` or `github` (TypeScript projects: npm packages ship compiled JavaScript, so the source comes from the git tag) |
| `package` | plugin slug, `owner/repo` on GitHub for Composer and github, or the registry name |
| `vulnerable`, `fixed` | the last vulnerable and the first fixed release (git tag for Composer and github) |
| `class` | one of the rule classes: `sqli`, `cmdi`, `code-eval`, `deserialization`, `path-traversal`, `xss`, `ssrf`, `open-redirect`, `xxe`, `ldapi`, `nosqli`, `file-upload`, `weak-crypto`, `hardcoded-secret` |
| `lang` | `php`, `python`, `js` or `ts` (checked with the js rules) |
| `[[fix_files]]` | each file the fix commit or changeset changed: `path` from the package root, and `vulnerable` / `fixed` lists of `[first, last]` lines it changed in each release |
| `source_url` | the advisory on CVE.org, NVD, GitHub Advisory or OSV |
| `note` | one plain sentence in our own words |
| `[[sinks]]` | optional, one per case: the call the fix protects, when it is not within 10 lines of a changed range (the engine reports a cross-file flow at the callee's sink): `path` from the package root, `vulnerable` and `fixed` (0 when the fix removed the call) its line in each release, `shared = true` for a helper or wrapper other flows reach too. A `# basis: ...` comment right above `[[sinks]]` says which upstream change protects that call and why it is the one; a shared one, and only a shared one, starts it with `shared helper: `. The tool fails a case without it |
| `known_gap` | optional: why the rules cannot catch the case yet (its input is not a source they read, say). Such a case is still run, but it is left out of the catch and fixed-FP rates and listed under "Known gaps" in the report, so a known blind spot neither dilutes the rates nor gets forgotten: a gap that shows as caught there is a change to look at. |

Only cases with a public fix commit or changeset belong here. Open the fix and
read it before filling in `fix_files`; keep only the hunks that fix this
vulnerability (not version bumps, comments or unrelated hardening in the same
commit), and check the line numbers against the released files: a fix made on
trunk can sit at other lines in the tagged release. The tool fails a case
whose file or range is not in the release.

A case whose id a rule or a route model (`rules/routes/`) cites in `refs` counts in the "rule source" group, the
rest in "independent", so rules are not graded on the advisories they were
written from. A rule designed from a case of `cves/` (its miss read in the
vulnerable release and the fix) cites that case in `refs`, so the case moves to
the "rule source" group and the "independent" group keeps only cases no rule
was designed from. A later CVE found in another case's fix (a bypass of it, as
CVE-2023-41330 of CVE-2023-28115's) and used to design a rule goes in `cves/`,
never in `holdout/`, and is cited the same way. Report the two groups and
`holdout/` apart: only `holdout/` tells whether a change carries over to cases
it was not designed from.

`holdout/` is a second set in the same format, for measuring only
(`go run ./cmd/cvebench -cases bench/holdout`). No rule may cite a hold-out case
and none may repeat a case of `cves/`; a test checks both. Its numbers tell
whether an improvement measured on `cves/` carries over.
A hold-out case whose miss or false positive is then used to design a change
moves to `cves/`, with a comment above its `id` naming the change, so `holdout/`
keeps only untuned cases. v0.5.8 moved eight this way (CVE-2023-6996,
CVE-2024-1698, CVE-2024-3211, CVE-2024-3342, CVE-2024-5756, CVE-2025-1753,
CVE-2026-32593, CVE-2026-33154); a run before the move compares with a later one
only on the cases both have.

`-library` scans Composer, PyPI and npm cases in the engine's library mode
(public parameters are input); WordPress plugins stay in application mode.

Releases are scanned as app_code_audit scans a server's code (`-scanpath
product`, the default): each file on its own first, then what following calls
across the release's files finds, the two merged by rule, path and line. A
finding of the first pass stays when the calls across files show a check, as it
does for a user: a check written in another file (a base class's method) leaves
the fixed release reported. The project caps are the engine's defaults, written
in the report's header; there is no audit clock (app_code_audit goes on in the
next audit where its clock stopped) and no cap on the findings listed. Files a
clock or the heap still cut short are listed under "Cut by a clock" (the product
path only: `Project.Scan` does not say when its clock stopped it, so a project
run's cuts show only in the unfinished and calls-cut columns): those numbers
depend on how busy the machine was. Which files are read is cvebench's own:
vendor, node_modules and .git are skipped, but not the virtual environments,
site-packages or caches app_code_audit skips, and there is no folder depth cap.
`-scanpath project` scans with `Project.Scan`, which decides each flow with the
calls across files, so such a check takes the finding away: it is kept to
compare with, as the most a project-level check could take away, not as the
verdict. A product run usually reports more than a project run, so its catches
and its fixed false positives can both be higher; that is a measured result, not
a guarantee (the two paths stop differently at a project cap). Runs before
v0.5.8 used the project path; compare those only with a `-scanpath project`
run. `-per-file` (`-scanpath per-file`) follows no calls across files.

## Verdicts

- caught: a rule of the case's class and language reports within 10 lines of a
  changed range in the vulnerable release;
- fixed FP: a rule that caught the case still reports within 10 lines of a
  changed range in the fixed release (the rate is over caught cases);
- in fix files: reports of the case's class anywhere in the fix files, near the
  fix or not, to tell "found but elsewhere" from "found nothing";
- with sink lines: caught and fixed FP again, a report of the class on the very
  line of the case's `[[sinks]]` (no window) also counting, in the vulnerable and
  the fixed release. Always shown next to the main verdict, never in its place;
  the comparison with other tools uses the same rule for every tool. It tells
  whether a rule follows the flow to the protected call; it does not tell that
  the rule tells the fix apart. A rise in these two columns is no improvement:
  the CHANGELOG and any number quoted outside cite the main verdict only. When
  they came in, the three cases they added (ad-widget CVE-2017-20289, vanquish
  CVE-2026-122265, folders CVE-2024-2023) were all still reported on the same
  line of the fixed release, whose fix adds a check before the call.
