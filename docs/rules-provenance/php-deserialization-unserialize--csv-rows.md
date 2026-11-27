# php-deserialization-unserialize: rows read with fgetcsv() as a source

## Case
- CVE-2025-13145 (`bench/cves/CVE-2025-13145.toml`): wordpress-plugin wp-ultimate-csv-importer 7.33.1 → 7.34, deserialization.
- Cited in `refs` from this change, so it counts as "rule source".
- Missed because the source was not known.

## Root cause
- `SingleImportExport.php:86` moves `$_FILES['file']['tmp_name']` to `$csv_file`;
  `:89` `$headers = fgetcsv($handle, 1000, ',')`, `:90` the rows, `:91`
  `array_combine($headers, $row)`, then `:116` `@unserialize($value)`.
- The fix stops unserializing those meta fields and decodes JSON instead:
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
- Known limits and false-positive risk (medium): a local CSV file unserialized
  is reported as well. Unserializing CSV cells is risky in itself, so this is
  accepted; E7 shows how many such findings it adds.

## Probes
| fixture | base faac5b02 | new build | expected |
|---|---|---|---|
| upload → `fgetcsv` → `array_combine` → `foreach` → `@unserialize` | - | reported | reported |
| `is_serialized_string()` check before `unserialize` | - | - | not reported |
| `json_decode` instead | - | - | not reported |
| a local CSV, `$row = fgetcsv($h)`, `unserialize($row[1])` | - | reported | known false positive |
| a local CSV read in a `while` condition, `$opts[$row[0]] = unserialize($row[1])` | - | - | not reported (cause not traced) |

The rule gained one vulnerable and one safe sample (`allowed_classes => false`).

## Process
- Rule lane: miss triage, design, probes.
- Commander: approved the batch; the measurement gate.
- Reviewer: pending.

## Review
Pending.

## Measurement
Single case, base faac5b02, rules at e99a52e5: missed → caught; the fixed
release is not reported. Load (1-minute) 12.0 at the start, 13.3 at the peak
sampled, no segment voided. The full runs are pending.
