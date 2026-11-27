# js-file-upload-client-name-write: new rule, an upload written under its client-sent name

## Case
- CVE-2018-3758 (`bench/cves/CVE-2018-3758.toml`): npm express-cart 1.1.6 → 1.1.7, file-upload.
- Cited in the new rule's `refs`, so it counts as "rule source".
- Missed because the sink was not known.

## Root cause
- `routes/admin.js:428` `let file = req.file;` reaches `:430`
  `fs.createWriteStream(path.join(uploadDir, file.originalname.replace(/ /g, '_')))`:
  any file type is written to `public/uploads` under the name the client sent.
- The fix checks the type and size before writing:
  ```
  +        const mimeType = mime.lookup(file.originalname);
  +        if(!common.allowedMimeType.includes(mimeType) || file.size > common.fileSizeLimit){
  ```
- `js-file-upload-client-name` knew moves and copies (`.mv(`, `fs.rename(`,
  `fs.copyFile(`, ...), not writes. A path-traversal rule already reports line
  430, so the flow itself is followed.

## Design
- A new rule:
  - source: `.originalname` only;
  - sinks: `fs.createWriteStream(`, `fs.writeFile(`, `fs.writeFileSync(`,
    `fs.promises.writeFile(`, the first argument (the path) only;
  - sanitizers: the server-made names of `js-file-upload-client-name`.
  - `route_input = false`: request values a route model makes input (a header,
    the query) are not this rule's; added after the full measurement (see Measurement).
- Why not in `js-file-upload-client-name`: its sources include `req.file` and
  `req.files`. With the write sinks there:
  - `fs.createWriteStream(req.file.path + '.copy')` was reported. `req.file.path`
    is the temporary path multer chose, not the client's name: a false positive.
  - A safe sample of `js-path-traversal-archive-extract` (`new AdmZip(req.file.path)`,
    entries written with `writeFileSync`) was reported, and the samples test failed.
  So the writes have a rule of their own, with the client's name as the only
  source; `js-file-upload-client-name` is unchanged.
- Not chosen:
  - a source list per sink: the rule format has none;
  - `unless` on `req.file.path`: it drops a call only when that is a whole
    argument, so `req.file.path + '.copy'` would still count.
- Known limits:
  - express-fileupload's `req.files.<field>.name` is not a source here;
  - a write after an extension or MIME allowlist check
    (`allowedMimeType.includes(mime.lookup(name))`) is still reported: the rule
    reads no allowlist as a check. This is the fixed release's false positive;
  - `path.basename()` and `uuidv4() + path.extname(name)` are reported: the
    extension is still the client's.

## Probes
| fixture | base faac5b02 | new build | expected |
|---|---|---|---|
| `createWriteStream(path.join(dir, file.originalname...))` | path-traversal only | + this rule | reported |
| `fs.promises.writeFile(path.join(DIR, req.file.originalname), buf)` | - | reported | reported |
| the client's name written as content of a fixed log file | - | - | not reported |
| a fixed name, the upload's bytes written | - | - | not reported |
| `createWriteStream(req.file.path + '.copy')` | path-traversal only | this rule does not report | not reported |
| express-fileupload `f.name` | - | - | known limit |

The rule has two vulnerable and two safe samples.

## Process
- Rule lane: miss triage, design, probes (the probes moved the sinks out into a new rule).
- Commander: approved the new rule and the `refs` citation; the measurement gate.
- Reviewer: round 1 (see Review).

## Review
Round 1 at 759e1c87: B1 N3 S6, not mergeable. CI red (TestUnlessAfterOwnerReads,
TestHeldOut); the site was not regenerated and there was no CHANGELOG entry. Lines,
diffs and the single-case numbers were checked against the releases and the run.
No other tool or model is named, and no private path appears.

## Measurement
Single case, base faac5b02, rules at e99a52e5: missed → caught, and the fixed
release still reports (a fixed false positive). In 1.1.7 the type check returns
early for a type outside `allowedMimeType`, then `routes/admin.js:461` writes
under the client's name as before; the rule does not read a MIME allowlist as a
check. Load (1-minute) 12.0 at the start, 13.3 at the peak sampled, no segment
voided.

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

This rule's new lines: express-cart 1.1.6 `routes/admin.js:430` (the case) and
1.1.7 `:461` (the fixed false positive). The first head run also reported
actual's `packages/sync-server/src/app-sync.ts:298` / `:307` in cves-ts: a
header (`x-actual-file-id`) in the file's path, a path-traversal flow, not an
upload stored under its client-sent name. The Express route model makes every
request value a rule's input; the rule now has `route_input = false`, so only
`.originalname` counts, and the second run no longer reports them.
