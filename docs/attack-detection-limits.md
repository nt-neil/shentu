# Attack detection: known limitations in v0.4.0

[繁體中文](attack-detection-limits.zh-TW.md)

v0.4.0 ships 27 attack signatures, and they are not extended to catch rewritten forms of an attack.
The cases below are known misses. A miss only costs an alert: Shentu misses the request or rates it lower. None of them can make Shentu block the wrong address.
v0.4.0 never blocks on its own: `block_ip` always needs the operator's confirmation. Its attacks are checked too: an address with attack attempts is blocked only for a verified L2 or L3 group of its own, not an overflow summary of many sources. Attempts that only reached a route (L1), could not be judged (Unknown) or come from unverified logs do not back a block; the address's SSH logins that journald itself confirms still can. An internal address (private, loopback, CGNAT and the like) is refused. `override_unverified` lifts all of these checks but one, and only from the server (`shentu chat`), never from Telegram: attempts that are unverified, L1 or Unknown no longer hold a block back, SSH logins are not checked, and an internal address may be blocked, so the block rests on the operator's own reading of the logs. An address listed in an overflow summary is still refused, unless it also has a verified L2 or L3 group of its own. From Telegram, since v0.4.1, `block_ip` blocks only an address with evidence Shentu verified (a verified L2 or L3 group listing it, or SSH login events sshd itself logged); any other address, one no group lists included, is refused there and is for the operator on the server.

## What is never seen

- **Linux only.** Attack detection reads Linux hosts' logs only.
- **Some log formats are refused.** nginx's and Apache's access logs are read, custom formats from their configuration included. A format with a field Shentu does not support, with `escape=none` or with a custom time format is refused.
- **No protocol-layer attacks.** An access log records the requests a server parsed, not the HTTP/2 frames or TLS records that carried them, so an attack on the protocol layer itself (nginx's HTTP/2 flaws CVE-2026-123007 and CVE-2026-123633, for example) is never seen here. The host survey covers those by version and configuration instead: it warns when an affected nginx serves HTTP/2. It reads a distribution's backported fix from the package changelog. Images without changelogs (Ubuntu's minimized images, some container images) keep the warning after the fix; there, the distribution's advisory is what counts. A host where the nginx package was removed with its configuration left behind, and another nginx was built from source outside the places the survey looks for one, may get no warning.
- **No request bodies.** Access logs do not record POST bodies, JSON or uploads, so a payload there is never seen. A route reached that way is L1 at most.
- **Two decoding rounds.** URL encoding is decoded at most twice (with `%u` and overlong UTF-8). Base64, gzip and other encodings are not decoded.
- **Unknown requests are counted, and L1 is not pushed.** A request cut where it may hide a payload (Unknown) is counted, and pushed only when one sink gets 20 of them within 24 hours. L1 attempts are counted and reported, never pushed as alerts.
- **Unverified logs never back a block.** Attempts from a log Shentu cannot verify are marked unverified, and the alert names the reason. `block_ip` refuses them as a basis for blocking; only the operator on the server can override that (see above). The reasons:
  - `web_user_writable`: the web server's or PHP's account owns the log or can write a directory above it. This is the default for nginx on Debian, Ubuntu and Rocky, whose logrotate creates the logs so. A server that runs application code in its own processes (mod_php, application modules in nginx), and a web account that can ptrace the server's workers count the same.
  - `untrusted_owner`: the log, a link to it or a directory above it is owned by an account other than root, or the log is writable by group or others, or a directory above it by others.
  - `unverified_source`: Shentu cannot confirm that only root can change the log: a directory writable by a group whose members are not known, an ACL, account databases or links that could not be read. Also a file that is not the one judged when it is read (replaced in between), and a rotated file that fails the check. When the web server's configuration could not be read in full, or it names more log sources than Shentu reads, every log is unverified for this reason.
  - `not_regular_file`: the log is not a regular file.
  - `symlink_not_followed`: the log could only be looked at by following a link, which Shentu does not do.
  - `client_from_header`: the server takes the client address from a request header (nginx's realip, Apache's mod_remoteip), so the logged address is what a proxy or the client wrote.
  - `custom_format`: the log format is not a standard one (nginx combined or main, Apache combined or common). Its lines are matched, but a field the client writes shifting the others is not ruled out.
- **SSH logins read by a user other than root**: journald's SSH logins count as complete for a block only for root or a member of the systemd-journal or adm group. A member of wheel (RHEL, Fedora), who may read the whole journal, is taken as reading only part of it, so its SSH logins do not back a block. An adm member is taken as reading all of it even where the journal grants adm nothing (for example a journal kept only in /run/log/journal).

## Requests that may be missed

- **Path traversal written differently.** The traversal signatures expect the plain form. An attacker can pad the path with doubled or backslash separators, `./` segments or `;` path parameters, and those requests may not match.
- **SQL injection written differently.** These may not match:
  - a comment placed between keywords;
  - whitespace characters other than space and tab;
  - a comment that ends the value;
  - an always-true condition on a number with no quote.
- **Command injection written differently.** These may not match:
  - a command called by its full path;
  - a command outside the short list the signature names;
  - a command name split by quotes.
- **Log4Shell lookups written differently or sent elsewhere.** A lookup built from nested lookups may not match. So may one sent in the Referer header, which is not checked.
- **Deserialization payloads written differently.**
  - A PHP serialized object with a sign before its length, or a custom-serialized one, may not match.
  - For Java, the branch for raw serialized bytes never matches, because the request text is lower-cased first. The base64 and hex forms still match.
- **Other PHP stream wrappers.** The signature covers `php://filter`, `php://input`, base64 `data:`, `expect://` and `zip://`. Other wrappers (such as `glob://` or `compress.zlib://`) and `data:` without base64 do not match. `phar://` is not in this signature, but the deserialization signature matches a value that starts with it.
- **Flarum's open redirect (composer-cves) without slashes.** A redirect target written as a scheme and a colon, with no `//`, may not match, though browsers still leave the site for it.
- **Flarum under a directory with a dot.** Flarum's logout route is anchored: only directories, or `index.php` right before it, may come first. Flarum mounted under a directory whose name has a dot (such as `/v1.2/`) is missed.
- **An encoded `/` in a route parameter.** Routes are matched on the decoded path. A request whose route parameter holds an encoded `/` (such as `/files/:name`) does not reach the route, unless the route takes several segments.
- **WordPress plugins.** There are no signatures for particular WordPress plugin vulnerabilities. A request against an installed vulnerable plugin is seen only if a generic class signature catches it, and then it is not tied to that plugin's CVE.

## Parameter names and path segments

Class signatures are tried on parameter names and on each path segment too, so ordinary traffic has more text that can match.

- A hit in a parameter name counts like one in its value: on a route of the same class it is L2.
- A hit in a path segment is L2 only where a route's placeholder took that segment. Otherwise the route stays at L1 and the hit is unanchored.
- For a route written as a regular expression, its capture groups are the placeholders. A route with no group leaves a path segment hit at L1. A fixed word inside a group (such as `(user|list)`) is taken as a placeholder value, so a hit in that word is L2.
- A placeholder's value is taken both from the path with `;` parameters cleaned away and from the path that keeps them, so a hit in a `;` parameter of the placeholder's segment (such as `/user/:id` with `/user/42;…`) is L2. One in a `;` parameter of the route's own words or of a mount prefix stays L1.
- A route's usual response size is learned from its ordinary responses; only requests a hit took to L2 are left out (an unanchored hit or noise is learned). A route whose ordinary requests often carry a class signature's text where its placeholder or a parameter takes it, and get larger responses, still learns too small a usual size. An L2 on that route then gets size evidence more easily. An L3 on a single piece of evidence is at most high.

## Narrowed to spare ordinary text

Three class signatures were narrowed so that the three forms listed below no longer match them:

- a common word followed by a space and a parenthesis, such as "system (";
- a quote, a space and a double dash, as in a search;
- a semicolon followed by "id" and more words.

Ordinary text of other forms still matches, for example:

- one of the function names the signature lists, a space and a parenthesis whose content starts with a quote, `$` or another call (a parenthesis inside a parenthesis alone does not match);
- a value ending in a quote, `--` and at least one more space or `-`;
- a semicolon followed by a short command name.

The cost is misses. A call with a space before its parenthesis is caught only when its argument looks like code (a quote, `$` or another call). After the quote, only `--` must end the value when a space comes first; `#` and `/*` are still caught after a space. `id` after a separator is not caught when arguments or a quote follow it.

## Measured detection

The numbers come from the evaluation tool (`tools/detecteval`, PR #94) with the signatures and matching of integ adff9e6 (#87, #90 and #91 merged); they are the ones in `tools/detecteval/baseline.json` next to this document. They include parameter names, path segments, anchored routes and the three narrowed signatures.

What they mean:

- **"Detected"**: a signature of the same class matched the request line a template converts to. It is not an alert, and not an L2 on a host.
- **"False alert"**: an ordinary request matched any signature other than a scanner's.
- **The samples are synthetic**: requests converted from nuclei templates, and requests generated with a fixed seed. They are not real traffic.

The results:

- **All templates: 40.5% detected (1548 of 3822).**
  - Source: nuclei-templates v10.5.2 (commit 5442582a), the 11835 templates under `http/`.
  - Templates the tool could not convert (1143), unclassified ones (6618) and `rce-unspecified` ones (252) are not counted.
- **Ordinary traffic: no false alerts in 1216 requests.**
  - The requests are 8 for each of 152 routes of 8 applications (WordPress, Django, Flask, Laravel, Express, Immich, Nest, Next). Where a route's fillers run out, tracking parameters make the request differ.
  - Of the 1216 requests, 363 differ in more than tracking parameters (campaign tags, click ids, language, cache buster); with that many, the false-alert rate can only be said to be below about 0.8% (95% upper bound), and they come from only 152 routes. The tool counts both (`normal_distinct`, `normal_routes` in `baseline.json`).
- **Templates for a vulnerability the host really has: 3 of 10 alerted.** Each row is what `-explain-host` reports.

| CVE | Alert | Why |
|---|---|---|
| CVE-2017-9841 | L1 | Has its own signature. The payload is in the request body, which access logs do not record, so it reaches L1 only. |
| CVE-2021-3129 | L1 | Has its own signature. The payload is in the body, so L1 only. |
| CVE-2024-21641 | L2 | Has its own signature. |
| CVE-2021-21315 | none | No signature of its own. A class signature matched the path, but class signatures are never tied to a package's CVE, whatever their class, so it is noise. |
| CVE-2021-23337 | none | No signature of its own. The payload is in the body. |
| CVE-2022-29078 | none | No signature of its own, and no class signature matched. |
| CVE-2023-0297 | none | No signature of its own. The payload is in the body. |
| CVE-2023-3452 | none | No signature of its own. A class signature of the same class matched the path, but a package CVE needs a signature of its own, so it is noise. |
| CVE-2024-3136 | none | No signature of its own. The payload is in the body. A class signature matched the path and is noise as well. |
| CVE-2025-69971 | none | No signature of its own. The flaw is a hard-coded secret, so the request line carries no payload. |

No template that names none of these CVEs alerts on the host: Shibboleth SP's logout no longer maps to Flarum's CVE-2024-21641.

Raising "class matches and the host has the package vulnerability" to L1 is deferred to v0.4.1.
