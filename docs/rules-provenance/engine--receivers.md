# engine: receivers, a library's method sink on the project's own class
Kind: precision

## Root cause
- Rules whose sinks are method names (`->find(`, `->where(`, `->setQuery(`)
  counted the method on any object, since the engine does not know a
  receiver's type. In the CVE bench's noise lines:
  - wp-recall's `RQ::tbl(...)->where()`, its own `Rcl_Query::where()`, read as
    five frameworks' SQL;
  - redaxo's `rex_sql::setQuery()` read as Joomla's;
  - nextgen-gallery's DataMapper `where()` read as Doctrine's and Yii's.
- When a project never names a library and one of its own classes declares a
  method of that name, the call cannot be the library's.

## Design
- A rule field, `receivers`: the library's names (classes, namespaces,
  functions) and its Composer packages. It is added to `php-nosqli-mongo-query`
  and to the CodeIgniter, Doctrine, Drupal, Joomla and Yii SQL rules.
- A method sink that another file's call reaches is the project's own, and is
  not reported, when all of these hold (`Project.ownMethodOnly`):
  - no file names the library:
    - not as a name in its PHP code, other than after `->` or `::`;
    - not as a word in a string;
    - not in composer.json or composer.lock;
    - not as a package, either a `vendor/<vendor>/<package>/` path or one the
      caller lists;
  - a class of the project declares a method of that name;
  - every file given was read and indexed to its end;
  - the caller left no rule-language file out.
- On the product path (review 1, N-284-2), app_code_audit gives the project:
  - composer.lock;
  - the package names under vendor/: the folder is listed, not read, and a
    vendor folder it cannot list counts by its name (`mongodb/*`);
  - `ProjectOptions.Incomplete` when it left a rule-language file out: a folder
    it skips (node_modules/, .git/), a folder more than 8 levels deep, a file
    over 1 MiB or unreadable, more than 20,000 files, or a walk cut short. An
    incomplete project holds no "never named" (`Project.NamesComplete`).
- cvebench gives the project the same, and its report lists the cases held
  back ("Receivers held back").
- The trade-off: a site with node_modules/ or .git/, or a minified script over
  1 MiB, is not relaxed at all. This is the fail-closed direction; the
  commander accepted it.
- yields_to: when the rule another rule yields to is left out by its own
  receivers, the yielding rule is judged by its own receivers
  (`TestReceiversYieldsTo`).
- Known limits:
  - a vendored package counts by its name only, so one that uses MongoDB under
    another name is not seen;
  - a method declaration counts as a mention, so a plugin's
    `function get_instance()` keeps CodeIgniter's rule. This is conservative,
    and tracked separately;
  - cvebench keeps only rule-language files and composer.json of a release, so
    it does not see the composer.lock of composer releases.

## Probes
- `rules/engine/recvnamed_test.go`:
  - `TestReceiversOwnMethod`, 17 rows;
  - `TestReceiversFrameworkSQL`, 5 rows;
  - `TestReceiversYieldsTo`, 5 rows, reverse-checked three ways: without the
    receivers check, with CodeIgniter's own receivers skipped, and without
    yields_to.
- `tools/codeaudit_receivers_test.go`, `TestAppCodeAuditReceivers`, 9 rows,
  through `AppCodeAudit`:
  - review 1's five cases are each reported: a file over 1 MiB, a file too
    deep, vendor/, only composer.lock, and an unreadable file;
  - a project naming nothing, and vendor/ with other packages only, are not
    reported;
  - a project with node_modules/ is reported.
  - Reverse-checked four ways: without composer.lock, without the vendor
    listing, without the per-file reasons, and without the skipped folders.
- `cmd/cvebench/receivers_test.go`, `TestScanReceivers`, 5 rows.

## Process
- Rule-engine lane: design, implementation, measurement, line-by-line triage.
- Commander: chose to apply it across the project, also outside WordPress; set
  the release conditions; accepted the fail-closed handling of skipped folders.
- Reviewer: two rounds (see Review).

## Review
- Round 1 at af9d5143: B0 N2 S2. N-284-2: app_code_audit skipped files before
  the project saw them, and never gave it composer.lock or vendor/. Fixed as
  above.
- Round 2 at 07d4ce66: B0 N0 S2. Merged as #284.

## Follow-up: per-language incompleteness and composer.json
- x20 held back 18 of the 65 PHP cases. In some of them the only file left out
  was a minified script over 1 MiB, which cannot name a PHP library. The
  review of #284 split the reasons in two (#300):
  - a single file left out (too big, unreadable, not a regular file) holds
    back only its own language's rules (`ProjectOptions.IncompleteLangs`,
    `Project.NamesCompleteFor`);
  - a folder skipped, a folder too deep, the file cap, a walk cut short, or
    composer.json, composer.lock or vendor/ not read hold back every rule
    (`Incomplete`).
- The review of #300 (N-300-0) found that app_code_audit returned early for
  a composer.json it could not read, or one over 1 MiB, without marking the
  project incomplete; cvebench did mark it. Both now mark it.
  `TestAppCodeAuditReceivers` gained a row for each case, both reported.
- x21 (VM, product path, base b088eae6, head #300):
  - the CVE set lost 8 more noise lines and gained none, all in one case
    already triaged above;
  - Receivers held back went from 18 cases to 8;
  - E7, the hold-out set and the TypeScript set were unchanged line for line.
- A known limit stays: the product path's file-by-file pass knows no project,
  so it still reports a method sink found in the file it is written in. Only
  what the cross-file pass finds is relaxed. In that case most of its lines
  are found file by file; that is why x21 relaxed 8 of them and the earlier
  Project.Scan measurement relaxed them all. Reading the project's names in
  that pass too is tracked separately.

## Measured on
Each line removed was traced to its source and is a false positive. The calls
are:
- redaxo's `rex_sql::setQuery()`, with int-cast, escaped or fixed values;
- wp-recall's `Rcl_Query::where()`, whose values go through `esc_sql()` in
  quotes.
- CVE-2025-27411 (redaxo 5.18.2 → 5.18.3), php-sqli-joomla-query.
- CVE-2025-1324 (wp-recall 16.26.10 → 16.26.12), the five framework SQL rules.
- CVE-2026-101325 (newsletters-lite 4.18.1 → 4.18.2), php-nosqli-mongo-query.
- CVE-2025-13641 (nextgen-gallery 4.0.0), php-sqli-doctrine-query-text and php-sqli-yii-query.

| case | x19 lines removed (Project.Scan, before review 1) | x20 lines removed (product path, after review 1) | x20 lines added |
|---|---|---|---|
| CVE-2025-27411 | 30 | 30 | 0 |
| CVE-2025-1324 | 10 | 10 | 0 |
| CVE-2026-101325 | 116 | 0 | 0 |
| CVE-2025-13641 | 3 (and 1 with another rule id) | 0 | 0 |

In x20, newsletters-lite and nextgen-gallery are held back. Each holds a
minified script over 1 MiB that app_code_audit does not read, so their projects
are incomplete. In the CVE set, 18 of the 65 PHP cases were held back.

## Holdout check
- x20 ran the hold-out set on base and head: the same 159 lines on both sides.

## Measurement
- x20, in a throwaway Linux VM; every segment was valid, with the host's load at
  most 4. Base integ e0d8f79d, head 6806f3fd, both on the product scan path.
- E7, two runs per side: the same 120 lines on both sides, with the same cuts
  and unfinished files.
- cvebench:
  - detection unchanged (21 of 106 cases);
  - the CVE set lost 40 lines and gained none (table above);
  - the TypeScript set is unchanged (155 lines), and so is the hold-out set
    (above).
