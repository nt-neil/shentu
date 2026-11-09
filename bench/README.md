# CVE bench

`go run ./cmd/cvebench` measures the code rules against real, published
vulnerabilities. For each case in `cves/` it downloads the last vulnerable and
the first fixed release of the package, scans both with `rules/engine`, and
writes a Markdown table: which rule caught which case, the catch rate, the
false-positive rate on fixed releases, and how many findings and how much time
each release took. `baseline.md` is the first run; compare later runs with it.

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
| `class` | one of the rule classes: `sqli`, `cmdi`, `code-eval`, `deserialization`, `path-traversal` |
| `lang` | `php`, `python`, `js` or `ts` (checked with the js rules) |
| `[[fix_files]]` | each file the fix commit or changeset changed: `path` from the package root, and `vulnerable` / `fixed` lists of `[first, last]` lines it changed in each release |
| `source_url` | the advisory on CVE.org, NVD, GitHub Advisory or OSV |
| `note` | one plain sentence in our own words |

Only cases with a public fix commit or changeset belong here. Open the fix and
read it before filling in `fix_files`; keep only the hunks that fix this
vulnerability (not version bumps, comments or unrelated hardening in the same
commit), and check the line numbers against the released files: a fix made on
trunk can sit at other lines in the tagged release. The tool fails a case
whose file or range is not in the release.

A case whose id a rule cites in `refs` counts in the "rule source" group, the
rest in "independent", so rules are not graded on the advisories they were
written from.

## Verdicts

- caught: a rule of the case's class and language reports within 10 lines of a
  changed range in the vulnerable release;
- fixed FP: a rule that caught the case still reports within 10 lines of a
  changed range in the fixed release (the rate is over caught cases);
- in fix files: reports of the case's class anywhere in the fix files, near the
  fix or not, to tell "found but elsewhere" from "found nothing".
