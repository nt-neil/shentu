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
- Known limits: express-fileupload's `req.files.<field>.name` is not a source here.

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
- Reviewer: pending.

## Review
Pending.

## Measurement
Single case, base faac5b02, rules at e99a52e5: missed → caught, and the fixed
release still reports (a fixed false positive). In 1.1.7 the type check returns
early for a type outside `allowedMimeType`, then `routes/admin.js:461` writes
under the client's name as before; the rule does not read a MIME allowlist as a
check. Load (1-minute) 12.0 at the start, 13.3 at the peak sampled, no segment
voided. The full runs are pending.
