# The dispatch archive

Every sub-agent dispatch is written to `state_dir/dispatch/` (`dispatchlog.go`): one JSON record per line,
in a file per local day (`YYYY-MM-DD.jsonl`), and the operator's verdicts in `feedback-YYYY-MM-DD.jsonl`.
Proposal buttons, the automatic incident checks' daily limit, `shentu dispatch stats` and the daily
report all read it back. It is for anyone changing what a record holds.

## What a record may hold

- Counts and enumerations only, never free text: roles, statuses, reasons, gate codes and the
  not-checked reasons are fixed words; findings are counted by severity; the trigger is a hash;
  addresses are in canonical form. A sub-agent's or a model's words are never stored.
- Every field is checked when a line is read back (`dispatchRecord.check`, `feedbackLine.ok`). A line
  that fails is counted as unreadable, and an unreadable line stops the automatic incident checks until
  `sudo shentu dispatch repair` moves it to `*.jsonl.bad`.

## Adding a field

From v0.5.4 a line with a field the reading version does not know is read: the unknown field is
ignored, the known ones are checked as always, and such lines are counted apart (`dispatch stats`,
`unknown_field_lines` in JSON, and the daily report). `repair` leaves them. Versions before v0.5.4
refuse the whole line instead (see v0.5.4's upgrade note in the CHANGELOG).

So a new field must be one an older version can safely not see:

- **A restriction is never a new field alone.** A proposal withdrawn, used up or revoked, a dispatch no
  longer to be acted on: an older version ignores a field it does not know, so after a downgrade it would
  not see the restriction and would allow what it forbids. Say a restriction with a value of a field the
  older versions know and their `check()` refuses (so the line is unreadable to them: fail closed), or keep
  it in a file of its own that the older versions already consult.
- A new field holds counts and enumerations only, like the others, and is checked by the new `check()`.
- An older version's outputs never show an unknown field's content; keep it that way (no generic
  "print every field").
- Bump `dispatchVersion` only for a change older versions must refuse outright.
