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
  argument N, followed back through the file's assignments a few steps, names
  one of `receiver` (`fsockopen(`, `stream_socket_client(`).
- PHP: `$x = ...` and `$this->x = ...` are read (right sides of up to 32 tokens,
  copied, so a file's tokens need not stay in memory); other languages use the
  receiver's table (`x`, `self.x`).
- A project keeps each PHP file's table, so a method analysed from another file
  (a client class whose `connect()` sets `$this->fp` and whose `put()` writes to
  it) reads its own file's assignments.
- Unlike `receiver`, a handle whose origin the file does not show does not count:
  a parameter, `STDOUT`, a handle from another file. That misses a socket passed
  in from elsewhere, rather than reporting every file write (a known limit).
- `handle` without `receiver`, or a negative `handle`, is refused when the rules
  load.

## Probes
A test rule (sources `$_GET`, sinks `fwrite(`, `fputs(`, `handle = 1`,
`receiver = ["fsockopen(", "stream_socket_client("]`):

| fixture | expected | new build |
|---|---|---|
| `$fp = fsockopen(...); fwrite($fp, $_GET[...])` | reported | reported |
| `fputs(($fp), ...)` after `@fsockopen(...)` | reported | reported |
| `$sock = stream_socket_client(...); $fp = $sock; fwrite($fp, ...)` | reported | reported |
| `$this->fp = stream_socket_client(...)` in `connect()`, `fputs($this->fp, ...)` in `put()` | reported | reported |
| the same class in another file than the request | reported | reported |
| `$fp = fopen('log.txt', 'a'); fwrite($fp, ...)` | not reported | not reported |
| `fopen('php://stdout', 'w')`, `STDOUT` | not reported | not reported |
| `function put($fp) { fwrite($fp, ...) }` (origin unknown) | not reported | not reported |
| input only in `fsockopen()`'s host, a fixed line written | not reported | not reported |

Checked by mutation: without the project's per-file table the cross-file
fixture is missed; with an unknown origin counted as a socket, the stdout and
parameter fixtures are reported. Both fail `TestHandleCondition*`.

## Process
- Rule lane: found the gap while designing the protocol-injection rule, asked
  the rule engine lane about open work on the same code (one pull request adds
  a field next to it; the later one merges), wrote the field and its tests.
- Commander: chose that the rule lane writes the field, in a pull request of
  its own, before the rule; set the fail-closed reading and the fixtures.
- Reviewer: see Review.

## Review
Pending.

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
