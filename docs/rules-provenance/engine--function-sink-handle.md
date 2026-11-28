# engine: a function sink's handle argument can be required to come from given calls (handle)
Kind: precision

## Why
- A protocol-injection rule (a request value written into a line of a network
  protocol, as in the IMAP and HTTP request lines of a webmail's spellcheck and
  message fetch) needs `fwrite($fp, ...)` and `fputs($fp, ...)` as sinks only
  when `$fp` is a socket. With `fwrite(` as a plain sink, every write to a file
  would be reported.
- `[[args]] receiver` only applied to method sinks (`$obj->m()`); a function
  sink's handle is an argument, and PHP variables were not in the receiver's
  table of assignments (it was written for Python names). So no rule could say
  "a write to a socket".
- No rule uses the field yet: the protocol-injection rule that needs it comes
  in a pull request of its own, designed from its CVE cases, with its own cve
  record. This change is the engine part alone, so it is a precision record.

## Design
- `handle = N` in `[[args]]`, with `receiver`: the call counts only when
  argument N was made by one of `receiver` (`fsockopen(`, `stream_socket_client(`):
  - in place: `fwrite(fsockopen(...), ...)`;
  - by the nearest assignment before the call in the same function: the
    analysis records, at each assignment, which receivers made the value
    (also through another name, a chained assignment or a ternary), and the next
    assignment replaces it. So another function's `$fp` of the same name, or a
    `$fp` reopened as a file after `fclose`, does not count (review round 1);
  - for `$this->x`, by an assignment to the property anywhere in its file: a
    project keeps, per PHP file, which receivers each property's assignments
    call. Names only, no tokens; a method analysed from another file reads its
    class's own file.
- Cost: nothing is recorded or kept unless a loaded rule has a handle condition.
  A file with more than 4096 property assignments gets no table: its handles are
  not known (not reported) and its scan records the cut `handle-table`. A
  crafted 1 MiB file of property assignments is read in under 1 MiB of
  allocation (`TestHandleCost`); round 1 measured the first version copying 5
  million tokens (361 MB) for it.
- Unlike `receiver`, a handle whose origin the code does not show does not count.
  Known limits, all missed rather than reported: a parameter, `STDOUT`, a
  method's return value (`$this->fp = $this->connect()`), a static property set
  in another method (`self::$conn`), an array element, a `foreach` variable,
  `list()`. A rule using the field states the limits its cases meet in its own
  record.
- `handle` without `receiver`, or a negative `handle`, is refused when the rules
  load.

## Probes
A test rule (sources `$_GET`, sinks `fwrite(`, `fputs(`, `handle = 1`,
`receiver = ["fsockopen(", "stream_socket_client("]`):

| fixture | expected | new build |
|---|---|---|
| `$fp = fsockopen(...); fwrite($fp, $_GET[...])`; with `@` and parentheses | reported | reported |
| through another name; a chained assignment; a ternary of two sockets; in place | reported | reported |
| `$this->fp` set in `connect()`, written in `put()`; the same class in another file | reported | reported |
| `self::$conn` set and written in one method | reported | reported |
| a file, `fclose`, then a socket before the write | reported | reported |
| `fopen('log.txt')`; `php://stdout`; `STDOUT` | not reported | not reported |
| function a's `$fp = fopen(...)` written, function b's `$fp = fsockopen(...)` | not reported | not reported |
| a socket, `fclose`, then `$fp = fopen(...)` before the write | not reported | not reported |
| a parameter; `$this->fp = $this->open()`; `self::$conn` set in another method | not reported (known limits) | not reported |
| more than 4096 `$this->x =` in the file | not reported, cut `handle-table` | as expected |

Checked by mutation: without replacing a variable's record on reassignment, the
reopened file is reported; without the cap, the cost and cut tests fail;
without the property table, the property and cross-file cases are missed.

## Process
- Rule lane: found the gap while designing the protocol-injection rule, asked
  the rule engine lane about open work on the same code (one pull request adds
  a field next to it; the later one merges), wrote the field and its tests.
- Commander: chose that the rule lane writes the field, in a pull request of
  its own, before the rule; set the fail-closed reading and the fixtures.
- Reviewer: see Review.

## Review
Round 1 at ac10f454: B0 N1 S3. N-295-1: the first version built a table for
every PHP file even with no rule using it, copying each assignment's right side;
a crafted 1 MiB file cost 361 MB. It also kept one table per file, so another
function's `$fp`, or one reassigned before the write, could count. Fixed as in
Design (cost zero without a handle rule; names, not tokens; a per-file cap with a
cut; function scope with the nearest assignment). S-295-1 to S-295-3: the known
limits are written out, and this record follows what the code does.

## Measured on
Full A/B in the throwaway Linux bench VM: base 216b6988, head 08ee0ac6 (this
change). E7 twice per side; cvebench on the three sets. Every segment was
valid: the host's 1-minute load peaked at 4.0, the VM's at 3.1, and nothing was
voided. Every case of every set was run; the change builds its per-file table
for each PHP file, so the PHP cases are the ones it could touch, among them
CVE-2026-56738 (phpMyFAQ) and CVE-2024-3211 (wp-easycart): no line of any case
changed.

| set | lines base | lines head | only base | only head | caught base → head | wall time base / head |
|---|---|---|---|---|---|---|
| cves (106) | 3324 | 3324 | 0 | 0 | 22 → 22 | 12:40 / 12:36 |
| cves-ts (18) | 155 | 155 | 0 | 0 | 1 → 1 | 1:58 / 1:56 |

The reports are the same apart from the scan time column. E7: all four outputs
are identical (md5 the same), with the same files, findings and unfinished
files per corpus. The time per corpus, base runs / head runs:

| corpus | base | head |
|---|---|---|
| wordpress | 161.6 s, 157.4 s | 161.3 s, 161.4 s |
| laravel-framework | 6.2 s, 6.1 s | 6.1 s, 6.1 s |
| django | 10.5 s, 10.4 s | 10.3 s, 10.3 s |
| flask, express | 0.6 s, 0.5–0.6 s | 0.6 s, 0.5–0.6 s |

The peak memory was 1.29–1.38 GB on both sides.

## Holdout check
Holdout (22 cases) on base and head: 159 lines on both sides, line for line the
same; caught 3 → 3, fixed false positives 0 → 0. For example CVE-2017-5954 and
CVE-2021-23352 had the same lines.
