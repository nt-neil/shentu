# php-sqli-string-concat: the Symfony request body as a source

## Case
- CVE-2026-56738 (`bench/cves/CVE-2026-56738.toml`): composer thorsten/phpMyFAQ 4.1.5 → 4.1.6, sqli.
- Already cited in this rule's `refs` ("rule source").
- Missed because the source was not known, and because of an engine gap (below).

## Root cause
- `phpmyfaq/src/phpMyFAQ/Controller/Administration/Api/StopWordController.php:84`
  `$data = json_decode($request->getContent());` → `:88`
  `Filter::filterVar($data->stopWord, FILTER_SANITIZE_SPECIAL_CHARS)` → `:104`
  `$stopWords->add($stopWord)` → `phpmyfaq/src/phpMyFAQ/StopWords.php:63`
  `sprintf("INSERT INTO %s VALUES(%d, '%s', '%s')", ...)` → `:71` `->query($sql)`.
- The fix (StopWords.php:68), the last argument of that `sprintf`:
  ```
  -                $word,
  +                $this->configuration->getDb()->escape($word),
  ```
- The rule had no Symfony request-body source. With one, the case is still
  missed: a `json_decode()` result, or a field of it, passed to another
  function loses its taint in the engine (see the probes).

## Design
- Sources: `$request->getContent(`, `$request->toArray(`, here and in
  `php-sqli-orderby-identifier`, which this rule hands an ORDER BY column to:
  the two rules read the same sources (`TestUnlessAfterOwnerReads`).
- `$request->` and not any receiver: Symfony HttpClient responses have
  `getContent()` too, and that is a remote server's data.
- Not chosen:
  - `FILTER_SANITIZE_SPECIAL_CHARS` as a sanitizer: it encodes quotes as HTML
    entities but protects no numeric position; left as it is.
  - an engine change so a `json_decode()` result keeps its taint across a call:
    out of scope for a rule change; scheduled separately in the engine lane.
- Known limits:
  - `$this->db->quote($d['w'])` is still reported: `quote(` is no sanitizer here;
  - `->query(` also takes search clients' `->query([...])` (Elasticsearch,
    Algolia). Both were there before; the body now reaches them too.
- Expected effect on this case: +0, because of the engine gap. The source works
  for flows inside one function.
- The fix's `->escape(` is not one of this rule's sanitizers on purpose (an
  escape without quotes does not stop a numeric position; see the comment on
  `sanitizers` in the rule). Once the engine gap is closed, the fixed release
  will still be reported: a choice the rule already made, not one of this change.

## Probes
| fixture | base faac5b02 | new build | expected |
|---|---|---|---|
| `$request->toArray()['id']` concatenated into `$db->query` | - | reported | reported |
| the same with `(int)` | - | - | not reported |
| HttpClient `->getContent()` into a query | - | - | not reported |
| `prepare` + `execute` | - | - | not reported |
| one function: `json_decode($request->getContent())` → field → `sprintf` → `query` | - | reported | reported |
| the same through `Filter::filterVar(...)` | - | reported | reported |
| the same into `->getDb()->query` | - | reported | reported |
| the case's shape: through the method `add()` of another class | - | - | engine gap |

Narrowing the gap (new build): `add_word($request->getContent())` is reported;
`$d = json_decode(...); add_word($d->w)` is not, with `$_GET` as well;
`add_word(json_decode($_GET['j']))` through a variable is not;
`add_word(trim($_GET['j']))` through a variable is. The rule gained one
vulnerable and one safe Symfony sample.

## Process
- Rule lane: miss triage, design, probes (the probes found the engine gap, handed to the commander).
- Commander: approved the batch; scheduled the engine gap; the measurement gate.
- Reviewer: round 1 (see Review).

## Review
Round 1 at 759e1c87: B1 N3 S6, not mergeable. CI red (TestUnlessAfterOwnerReads,
TestHeldOut); the site was not regenerated and there was no CHANGELOG entry. Lines,
diffs and the single-case numbers were checked against the releases and the run.
No other tool or model is named, and no private path appears.
For this rule: the ORDER BY hand-over lacked the two sources in
`php-sqli-orderby-identifier` (fixed, with a sample).

## Measurement
Single case, base faac5b02, rules at e99a52e5: missed → missed, as expected.
Load (1-minute) 12.0 at the start, 13.3 at the peak sampled, no segment voided.
The full runs are pending.
