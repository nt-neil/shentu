# php-deserialization-unserialize: rows read with fgetcsv() as a source

## Case
- CVE-2025-13145 (`bench/cves/CVE-2025-13145.toml`): wordpress-plugin wp-ultimate-csv-importer 7.33.1 → 7.34, deserialization.
- Cited in `refs` from this change, so it counts as "rule source".
- Missed because the source was not known.

## Root cause
- `SingleImportExport.php:86` moves `$_FILES['file']['tmp_name']` to `$csv_file`;
  `:89` `$headers = fgetcsv($handle, 1000, ',')`, `:90` the rows, `:91`
  `array_combine($headers, $row)`, then `:116` `@unserialize($value)`.
- The fix stops unserializing those meta fields and decodes JSON instead
  (summarized; a comment added between the lines is left out):
  ```
  -            $maybe_array = @unserialize($value);
  +            $decoded_value = json_decode($value, true);
  ```
- The rule's sources were request variables, cookies and Laravel's request;
  the content of an uploaded file was not one.

## Design
- Source: `fgetcsv(`.
- A source, because the sink `unserialize(` was known. Rows read with
  `fgetcsv()` are most often an import file a user uploaded.
- Not chosen:
  - counting `fgetcsv()` only on a handle opened from `$_FILES[...]['tmp_name']`:
    the engine does not follow a handle back to its `fopen()`;
  - `fgets(`, `file(`, `file_get_contents(`: they would take every local file
    read, configuration included.
- Known limits:
  - a row assigned in a `while` condition
    (`while (($row = fgetcsv($h)) !== false)`) is not followed into the loop: an
    engine gap, held out as a known gap (`r277 fgetcsv row assigned in a while
    condition`). It is the usual way of reading a CSV file, so the source misses
    most of them for now. The case is caught through `$headers = fgetcsv(...)`
    above the loop, joined to the row by `array_combine()`;
  - false-positive risk (medium): a CSV file the application ships, unserialized,
    is reported as well, as critical. Unserializing CSV cells is risky in itself,
    so this is accepted; E7 shows how many such findings it adds.

## Probes
| fixture | base faac5b02 | new build | expected |
|---|---|---|---|
| upload → `fgetcsv` → `array_combine` → `foreach` → `@unserialize` | - | reported | reported |
| `is_serialized_string()` check before `unserialize` | - | - | not reported |
| `json_decode` instead | - | - | not reported |
| a local CSV, `$row = fgetcsv($h)`, `unserialize($row[1])` | - | reported | known false positive |
| a local CSV read in a `while` condition, `$opts[$row[0]] = unserialize($row[1])` | - | - | not reported: the `while` gap |

The rule gained one vulnerable and one safe sample, both with the row read
above any loop, so the safe one tests `allowed_classes => false` and nothing else.

## Process
- Rule lane: miss triage, design, probes.
- Commander: approved the batch; the measurement gate.
- Reviewer: round 1 (see Review).

## Review
Round 1 at 759e1c87: B1 N3 S6, not mergeable. CI red (TestUnlessAfterOwnerReads,
TestHeldOut); the site was not regenerated and there was no CHANGELOG entry. Lines,
diffs and the single-case numbers were checked against the releases and the run.
No other tool or model is named, and no private path appears.
For this rule: the first samples read the row in a `while` condition, so the
safe one was clean for that reason and did not test `allowed_classes`.

## Measurement
Single case, base faac5b02, rules at e99a52e5: missed → caught; the fixed
release is not reported. Load (1-minute) 12.0 at the start, 13.3 at the peak
sampled, no segment voided.

Full measurement, base b8c15062 (integ), head 26ba87d6 (the rules of this
change); E7 twice on each side, cvebench on the three sets, all segments valid,
the 1-minute load peaking at 9.6 (first head run) and 14.5 (second), none voided
or rerun:

| set | caught base → head | with sink lines | fixed FP |
|---|---|---|---|
| cves, all (106) | 17 → 21 | 21 → 25 | 1 → 2 |
| cves, rule source | 5/27 → 9/31 | 5 → 9 | 0 → 1 |
| cves, independent | 12/79 → 12/75 (the same 12 cases) | 16 → 16 | 1 → 1 |
| holdout (22) | 3 → 3 | 4 → 4 | 0 → 0 |
| cves-ts (18) | 1 → 1 | 1 → 1 | 1 → 1 |

E7: the same 120 findings and the same cuts and unfinished files on every run.
cvebench lines: 23 more in cves (the four cases' own findings, two in tornado's
test handlers, and false positives of kinds listed as known issues), none fewer; holdout and
cves-ts line for line the same.

This rule's new line: wp-ultimate-csv-importer 7.33.1 `SingleImportExport.php:116`
(the case).
