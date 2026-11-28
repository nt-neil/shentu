# engine: not_array, an array argument is not reported where an array cannot do harm
Kind: precision

## Root cause
- WordPress's `maybe_unserialize($data)` unserializes only a string that
  `is_serialized()`; anything else comes back as it was given. An array of
  request values never reaches `unserialize()`.
- The engine knew input was in the value, not that the value was an array, so
  `php-deserialization-wp-maybe-unserialize` reported such a call. booking's
  `includes/page-form-simple/form_simple__get_data.php:59` and `:126` were the
  cases in the CVE bench's noise lines: `$visual_form_structure` is built as
  `array()` with an entry appended per posted field, then handed to the
  functions that call `maybe_unserialize()` on it.

## Design
- An argument condition, `not_array` (rules README, `[[args]]`): the argument
  does not count when it is an array on every path that gives it input. Used by
  `php-deserialization-wp-maybe-unserialize`.
- The engine keeps an `arr` mark next to taint, joined with AND across paths:
  - `array(...)` and `[...]`;
  - an `(array)` cast;
  - a variable written by key or appended to;
  - the result of a function that always returns an array (`explode()`,
    `wp_parse_args()` and the others in the README).
  - It also reaches a callee that passes its parameter on to such a sink as it
    is (`sinkArr` in the summary).
- Fail closed (review 1, N-284-1): the mark is not trusted where the code may
  write the variable in a way the analysis does not follow:
  - a reference, a `foreach` target, a destructuring, any `extract()`;
  - a variable of the global scope (named outside every function body), or
    declared `global` under its own name;
  - `$$name`, `${...}`, `$GLOBALS`, or a one-argument `parse_str()` in the
    file;
  - the variable passed whole to:
    - a method, a constructor, or a computed callee;
    - a PHP function with a by-reference parameter at that place
      (`rules/engine/php_refparams.txt`, generated from PHP's reflection, the
      command in its header);
    - a project function declared with one (`fileIndex.RefFuncs`);
    - a function the project does not declare, except those in
      `rules/engine/wp_byvalue.txt`, each listed with why it takes its
      arguments by value.
  - A file scanned on its own cannot read another file, so there any function
    it does not declare may take a reference.
- The trade-off for `global`: the review proposed dropping the mark in any file
  that holds `global`. Almost every WordPress file holds `global $wpdb`, so that
  would turn the condition off for WordPress. Instead, the mark is dropped for a
  variable declared `global` under its own name, and for every variable of the
  global scope. The second covers a function in another file writing the
  variable through `global` or `$GLOBALS`, which the file at hand cannot see. A
  function's own variable is written that way only when it is declared `global`
  there, which the first rule already covers.
- Known limits:
  - an array that goes through a WordPress or plugin function not in
    `wp_byvalue.txt` is still reported;
  - so is an array at a file's top level;
  - an index of an object is trusted when the object was made some way other
    than `$o = new ...` (`$o = (new Bag())`, `$o = $p = new Bag()`,
    `Bag::make()`, `clone`). Only a class that implements ArrayAccess makes
    that matter (review of #302, S-302-4). The thorough fix, trusting an index
    only where the base variable was assigned an array in the function, is
    planned for v0.5.9.

## Probes
Product path (`ScanTimed`, then `ScanCallsPart`), `rules/engine/notarray_test.go`:
- `TestNotArrayMaybeUnserialize` (about 30 rows) and `TestNotArrayAcrossFiles`
  (8): arrays are not reported; a value taken from the array, a string made
  from it, and a path that gives a string are.
- `TestNotArrayUnseenWrites` (13 rows): review 1's seven ways of writing the
  variable (B1 to B7), plus `settype()`, a computed callee, a by-reference
  function of another file, and two by-value controls. Every B row fails on
  af9d5143, before the fix.
- `TestNotArrayFileAlone` (3 rows): the file scanned on its own.
- `TestWPByValueList`: every line of `wp_byvalue.txt` gives a reason, and none
  is a PHP internal function.
- Each mechanism was turned off in turn, and the rows only it covers failed:
  - the global scope: B1 across files;
  - `global`: B1 in a closure;
  - `$$` and `${`: B6, B7;
  - methods: B3, B4;
  - `RefFuncs`: the by-reference function of another file;
  - `php_refparams.txt`: `settype()`;
  - `wp_byvalue.txt`: every array row;
  - no project: the file-alone row.

## Process
- Rule-engine lane: design, implementation, measurement, line-by-line triage.
- Commander: approved the design (v058-array-fp-cheap) and its release
  conditions, and the trade-off for `global`.
- Reviewer: two rounds (see Review).

## Review
- Round 1 at af9d5143: B0 N2 S2. N-284-1: seven ways of writing the variable
  that the analysis did not see. Fixed as above.
- Round 2 at 07d4ce66: B0 N0 S2. Merged as #284.

## Follow-up: object members
- After #284 merged, a security review of the merge found that the mark
  reached object members too. `$this->x` or `$o->p` written with an array
  kept the mark even when a method of the class, or a copy of the object
  (`$q = $o; $q->p = ...`), had made it a string since. The arrUnsure checks
  look at the base variable only, and an object is shared, not copied.
- Probe on the product path, the same fixtures on e0d8f79d (before #284) and
  on b088eae6:
  - `$this->x` rewritten by a method: reported before, not after #284;
  - an object copied, then its property written: reported before, not after;
  - a method of the object called: reported before, not after.
  - These are three missed reports that #284 added. Since v0.5.8 was not
    released, no release had them.
- Fix: a value read under a key with a member segment (`$this->x`, `$o->p`,
  `self::$x`) or a call's result (`$o->get()`) keeps no mark. Only a variable of
  the function, or an index of one (`$a['k']`), does, and still through the
  checks above. `$this->x` that stays an array is reported again: that is
  fail closed, accepted by the commander.
- An index of a variable the file assigns an object with `new` keeps no mark
  either (review of #302, S-302-1): `$o['k']` is then ArrayAccess's
  `offsetGet()`, which may return anything.
- The CHANGELOG states only the final behavior. The earlier v0.5.8 build
  that let a property pass was never released, so the record of it stays
  here (review of #302, S-302-3).
- Tests: `TestNotArrayMembers`, 8 rows on the product path (one of them the
  ArrayAccess index), and
  `TestAppCodeAuditNotArrayMembers`, 3 rows through `AppCodeAudit`. With the
  member rule turned off, the five member rows fail (the static property among them), and the two through `AppCodeAudit`; with `newBound` off, the ArrayAccess row fails.

## Measured on
- CVE-2025-14383 (booking 10.14.8 → 10.14.9): the two `maybe_unserialize()` lines above, in both releases.

| measurement | path | booking lines removed | booking lines added |
|---|---|---|---|
| x19, before review 1 (base 6bb70780) | Project.Scan | 4 | 0 |
| x20, after review 1 (base e0d8f79d) | product | 0 | 0 |

x19 traced each of the four lines: the argument is an array on every path that
carries request input, so all four were false positives. After review 1 they are
reported again. booking passes the array to
`wpbc_save_custom_booking_form__for_simple_form_mode()`, which the project does
not declare, so it may take the array by reference. This is the fail-closed
direction the review asked for.

## Holdout check
- x20 ran the hold-out set on base and head: the same 159 lines on both sides.

## Measurement
- x20, in a throwaway Linux VM; every segment was valid, with the host's load at
  most 4. Base integ e0d8f79d, head 6806f3fd, both on the product scan path.
- E7, two runs per side: the same 120 lines on both sides, with the same cuts
  and unfinished files.
- cvebench: detection unchanged (21 of 106 cases). The TypeScript set is
  unchanged (155 lines), and so is the hold-out set (above). This record's rule
  added and removed nothing in the CVE set; the 40 lines that set lost are
  receivers' (`engine--receivers.md`).
