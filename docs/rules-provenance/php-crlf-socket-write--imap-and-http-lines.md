# php-crlf-socket-write: request input written into a protocol line sent over a socket

## Case
- CVE-2026-126813 (`bench/cves/CVE-2026-126813.toml`): Composer roundcube/roundcubemail 1.6.20 → 1.6.21, a new class, `crlf`.
- Cited in the rule's `refs`, so it counts as "rule source".
- The case is a **known gap** (see Measurement): the rule does not reach its flow.
- A second flow of the same shape, the spellcheck backend's HTTP request line
  (fixed in 1.6.21, and again in 1.6.22), has **no CVE or GHSA id**. The
  release notes say only "Fix HTTP request injection via the spellcheck ATD
  backend" (1.6.21) and "Fix (again) HTTP request injection via the spellcheck
  ATD backend" (1.6.22), and the project's two security announcements say the
  same. So it is not a bench case: it is written as the rule's neutral sample
  and as probes, and only the release notes are cited.

## Root cause
- CVE-2026-126813: with the messages cache on, the message id from the request
  (`_uid`) goes into IMAP commands such as `UID FETCH $uid (...)`, which
  `putLine()` writes to the server with `fwrite($this->fp, $string)`
  (`program/lib/Roundcube/rcube_imap_generic.php:117`). `$this->fp` is made in
  `connect()` by `stream_socket_client(...)` or `@fsockopen(...)`. A CR LF in
  the id ends the command and starts another. The allowlist the id met,
  `preg_match('/^[0-9:.]+$/', $uid)` (`program/include/rcmail_action.php:897`),
  ends with `$`, which lets a final line break through. The fix anchors it with
  `\z`, cleans CR and LF in `rcube_message`'s constructor, and refuses any id
  with other characters before the commands are built:
  ```
  -                else if (preg_match('/^[0-9:.]+$/', $uid)) {
  +                elseif (preg_match('/^[0-9:.]+\z/', $uid)) {
  +        if (preg_match('/[^0-9:,*]/', (string) $uid)) {
  +            return false;
  ```
- The spellcheck backend (no id): the language from the request goes into the
  request line `"POST $path HTTP/1.0\r\n"` written with `fwrite($fp, $out)`
  after `$fp = fsockopen(...)` in the same function. 1.6.21 checked the
  language in the two spellcheck entry points; 1.6.22 moved the check into the
  spellchecker's constructor, because sending a message ran the spellcheck
  through another entry point that skipped it. The 1.6.21 check itself,
  `!preg_match('/[^\w.-]/', $input)`, is a negated class: it rejects a line
  break anywhere, `\n` included, so that check was sound; the gap was the entry
  point it did not cover.
- No rule read a write to a network protocol: no class covered it.

## Design
- A new class, `crlf` (CWE-93, CWE-77): a line break written into a line of a
  network protocol (an IMAP command, an HTTP request line written to a socket).
  A response header set with `header()` is not this class (it is not covered,
  and would be discussed apart).
- The rule `php-crlf-socket-write`:
  - sources: the PHP request (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) and
    the usual framework readers;
  - sinks: `fwrite(` and `fputs(`, argument 2, only when argument 1 is a socket:
    `[[args]] handle = 1` with `receiver = ["fsockopen(", "stream_socket_client("]`
    (the engine field added before this rule, see
    `engine--function-sink-handle.md`). A write to a file, `php://stdout`, or a
    handle the code does not show the origin of, is not reported;
  - sanitizers: integer casts and `intval`/`absint`, `ctype_digit`,
    `ctype_alnum`, and encoders that leave no line break (`rawurlencode`,
    `urlencode`, `base64_encode`, `bin2hex`). An allowlist regular expression
    of letters, digits, `_` and `-` anchored at both ends counts as a check (the
    engine's own reading).
- Not chosen:
  - every `fwrite(`/`fputs(` as a sink: every log write would be reported;
  - the application's input helper as a source, or its IMAP client's methods
    as sinks: one application's names.
- Known limits:
  - the engine reads `$` and `\z` alike as an end anchor, so a `$`-anchored
    allowlist of letters and digits counts as a check though a final `\n`
    passes it. Told to the rule engine lane;
  - input kept in a property by a constructor and read in another method (the
    1.6.22 entry point) is not followed;
  - the handle condition's own limits apply (a method's return value, a static
    property set in another method, arrays, `foreach`; `list()` over-reports).

## Probes
Neutral fixtures (`meas/crlf-fx`), product path:

| fixture | expected | new build |
|---|---|---|
| a function: `fsockopen`, the language into `"POST ...?lang=$lang HTTP/1.0\r\n"`, `fwrite` | reported | reported (product, project, per file) |
| the 1.6.22 entry point: input given to a class's constructor, kept in `$this->lang`, written in another method | reported | **not reported** (known limit) |
| a `$`-anchored digit allowlist before the write | reported (a final `\n` passes) | not reported (known limit) |
| a log class: `$this->fp = fopen(...)`, the language written | not reported | not reported |

The rule's samples: two vulnerable (an IMAP client whose `connect()` sets
`$this->fp`, the spellcheck function) and four safe (a log file, an integer
cast, `ctype_digit`, a `\z`-anchored digit allowlist).

## Process
- Rule lane: root cause from the CVE's fix and the release notes, the handle
  field first (its own pull request), the class, the rule, probes; asked the
  commander about the missing id and the class.
- Commander: approved the rule and its scope, the case without the
  spellcheck flow (no id), the new class `crlf`, and the known gap if missed.
- Reviewer: see Review.

## Review
Pending.

## Measurement
Single case on the work machine (through the shared test lock), head of this
change: the rule reports nothing in Roundcube 1.6.20 or 1.6.21, so no false
positive there and the case is missed. The `$` anchor is not the cause: the
engine's allowlist reading does not take `[0-9:.]` (it reads letters, digits,
`_` and `-` only), so 1.6.20's check does not count as one. The id is read
through the application's input helper and reaches `putLine()` through methods
of objects kept in properties (`$this->storage`, `$this->conn`) across several
classes, which the engine does not follow. The case is a known gap with that
reason. The full A/B is below.
