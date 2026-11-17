# Attack detection: known limitations in v0.4.0

[繁體中文](attack-detection-limits.zh-TW.md)

v0.4.0 ships 27 attack signatures, and they are not extended to catch rewritten forms of an attack.
The cases below are known misses. Each one can only cost an alert: Shentu misses the request or rates it lower.
None of them can make Shentu block an address. v0.4.0 never blocks on its own. A block always needs the operator's confirmation and a verified client address.

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
- **Deserialization payloads written differently.** A PHP serialized object with a sign before its length, or a custom-serialized one, may not match. The Java serialized-bytes signature never matches, because lower-casing the request text changes those bytes.
- **Other PHP stream wrappers.** File parameters that use a wrapper the signature does not list (such as data, glob or compression wrappers) may not match.
- **Flarum's open redirect (composer-cves) without slashes.** A redirect target written as a scheme and a colon, with no `//`, may not match, though browsers still leave the site for it.
- **WordPress plugins.** There are no signatures for particular WordPress plugin vulnerabilities. A request against an installed vulnerable plugin is seen only if a generic class signature catches it, and then it is not tied to that plugin's CVE.

## Ordinary requests that may match

Three kinds of ordinary text can match a class signature:

- a common word followed by a parenthesis, such as "system (";
- a quote followed by a double dash;
- a semicolon followed by a short word that is also a command name.

Such a request is listed as noise. If it reaches a route whose code has a sink of that class, it is rated L2. It is never blocked automatically.

## Measured detection

Measured with the evaluation tool (`tools/detecteval`, PR #94) at detect-eval bfb6d75, then rerun at 8f4d496 with the same result. Both runs use the 27 built-in signatures.

- **All templates: 36.4% detected (1390 of 3819).**
  - Source: nuclei-templates v10.5.2 (commit 5442582a), the 11835 templates under `http/`.
  - Templates the tool could not convert (1147), unclassified ones (6618) and `rce-unspecified` ones (251) are not counted.
- **Ordinary traffic: no false alerts in 1216 requests.**
  - The requests are 8 generated with a fixed seed for each of 152 routes of 8 applications (WordPress, Django, Flask, Laravel, Express, Immich, Nest, Next).
  - With this sample size, the false-alert rate can only be said to be below about 0.25% (95% upper bound).
- **Templates for a vulnerability the host really has: 3 of 10 alerted.** Each row is what `-explain-host` reports.

| CVE | Alert | Why |
|---|---|---|
| CVE-2017-9841 | L1 | Has its own signature. The payload is in the request body, which access logs do not record, so it reaches L1 only. |
| CVE-2021-3129 | L1 | Has its own signature. The payload is in the body, so L1 only. |
| CVE-2024-21641 | L2 | Has its own signature. |
| CVE-2021-21315 | none | No signature of its own. A class signature matched the path, but its class is not this CVE's (cmdi), so it is noise. |
| CVE-2021-23337 | none | No signature of its own. The payload is in the body. |
| CVE-2022-29078 | none | No signature of its own, and no class signature matched. |
| CVE-2023-0297 | none | No signature of its own. The payload is in the body. |
| CVE-2023-3452 | none | No signature of its own. A class signature of the same class matched the path, but a package CVE needs a signature of its own, so it is noise. |
| CVE-2024-3136 | none | No signature of its own. The payload is in the body. A class signature matched the path and is noise as well. |
| CVE-2025-69971 | none | No signature of its own. The flaw is a hard-coded secret, so the request line carries no payload. |

Raising "class matches and the host has the package vulnerability" to L1 is deferred to v0.4.1.
