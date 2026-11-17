# Attack detection: known limitations in v0.4.0

[繁體中文](attack-detection-limits.zh-TW.md)

v0.4.0 ships 27 attack signatures, and they are not extended to catch rewritten forms of an attack.
The cases below are known misses. A miss only costs an alert: Shentu misses the request or rates it lower. None of them can make Shentu block the wrong address.
v0.4.0 never blocks on its own: `block_ip` always needs the operator's confirmation. In this tree the check that the evidence is verified covers SSH login evidence only. The gate that keeps unverified web logs from backing a block comes with P5 (#91).

## What is never seen

- **Linux only.** Attack detection reads Linux hosts' logs only.
- **Some log formats are refused.** nginx's and Apache's access logs are read, custom formats from their configuration included. A format with a field Shentu does not support, with `escape=none` or with a custom time format is refused.
- **No request bodies.** Access logs do not record POST bodies, JSON or uploads, so a payload there is never seen. A route reached that way is L1 at most.
- **Two decoding rounds.** URL encoding is decoded at most twice (with `%u` and overlong UTF-8). Base64, gzip and other encodings are not decoded.
- **Unknown requests are counted, and L1 is not pushed (needs #91).** A request Shentu cannot judge is only counted. L1 attempts are not sent as alerts. This tree does not have that code yet; it holds once #91 is in.
- **Unverified logs never back a block (needs #91).** A log Shentu cannot verify (one the web user can write to, for example) is said so in the alert, and it is not a basis for blocking. This holds once #91 is in.

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
- **A `;` parameter in a route parameter's value.** A placeholder's value is taken from the path after `;` parameters are cleaned away, so a hit in a segment that carries one (such as `/user/:id` with `/user/42;…`) is L1 only. The hit is still listed as unanchored.
- **WordPress plugins.** There are no signatures for particular WordPress plugin vulnerabilities. A request against an installed vulnerable plugin is seen only if a generic class signature catches it, and then it is not tied to that plugin's CVE.

## Parameter names and path segments

Class signatures are tried on parameter names and on each path segment too, so ordinary traffic has more text that can match.

- A hit in a parameter name counts like one in its value: on a route of the same class it is L2.
- A hit in a path segment is L2 only where a route's placeholder took that segment. Otherwise the route stays at L1 and the hit is unanchored.
- For a route written as a regular expression, its capture groups are the placeholders. A route with no group leaves a path segment hit at L1. A fixed word inside a group (such as `(user|list)`) is taken as a placeholder value, so a hit in that word is L2.
- A route whose ordinary requests often carry a class signature's text in their path, and get larger responses, learns too small a usual response size: requests with a hit are left out of it. An L2 on that route then gets size evidence more easily. An L3 on a single piece of evidence is at most high.

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

The numbers come from the evaluation tool (`tools/detecteval`, PR #94) at detect-eval 8f4d496, using the signatures of detect-p5 6c54200. They do not include this branch's changes (parameter names, path segments, anchored routes, the three narrowed signatures). They will be measured again once #87, #90 and #91 are in integ.

What they mean:

- **"Detected"**: a signature of the same class matched the request line a template converts to. It is not an alert, and not an L2 on a host.
- **"False alert"**: an ordinary request matched any signature other than a scanner's.
- **The samples are synthetic**: requests converted from nuclei templates, and requests generated with a fixed seed. They are not real traffic.

The results:

- **All templates: 36.4% detected (1390 of 3819).**
  - Source: nuclei-templates v10.5.2 (commit 5442582a), the 11835 templates under `http/`.
  - Templates the tool could not convert (1147), unclassified ones (6618) and `rce-unspecified` ones (251) are not counted.
- **Ordinary traffic: no false alerts in 1216 requests.**
  - The requests are 8 for each of 152 routes of 8 applications (WordPress, Django, Flask, Laravel, Express, Immich, Nest, Next).
  - With this sample size, the false-alert rate can only be said to be below about 0.25% (95% upper bound).
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

Raising "class matches and the host has the package vulnerability" to L1 is deferred to v0.4.1.
