# CVE bench

2026-11-10, 70 rules, 97 cases.

- caught: a rule of the case's class reports within 10 lines of a line the fix changed, in the vulnerable release.
- fixed FP: a rule that caught the case still reports at the fix in the fixed release; the rate is over caught cases.
- rule source: a rule cites the id in its refs, so the rule was written from it; independent: no rule cites it.
- in fix files: reports of the case's class anywhere in the fix files of the vulnerable release, near the fix or not.
- findings and time: every report of every rule on the whole release, and the time to scan it.

## Summary

| group | cases | caught | catch rate | fixed FP | fixed FP rate | findings per release (vulnerable / fixed) | scan time per release |
|---|---|---|---|---|---|---|---|
| all | 97 | 15 | 15.5% | 0 | 0.0% | 12.7 / 12.5 | 10.8s |
| rule source | 23 | 5 | 21.7% | 0 | 0.0% | 7.5 / 7.0 | 15.4s |
| independent | 74 | 10 | 13.5% | 0 | 0.0% | 14.4 / 14.2 | 9.4s |
| composer | 18 | 2 | 11.1% | 0 | 0.0% | 3.5 / 3.5 | 7.2s |
| npm | 19 | 0 | 0.0% | 0 | - | 1.8 / 1.8 | 1.4s |
| pypi | 21 | 1 | 4.8% | 0 | 0.0% | 5.3 / 5.2 | 5.5s |
| wordpress-plugin | 39 | 12 | 30.8% | 0 | 0.0% | 26.3 / 25.7 | 20.0s |
| cmdi | 3 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 1.9s |
| code-eval | 7 | 1 | 14.3% | 0 | 0.0% | 2.0 / 1.9 | 3.7s |
| deserialization | 9 | 2 | 22.2% | 0 | 0.0% | 38.6 / 37.0 | 7.8s |
| file-upload | 5 | 0 | 0.0% | 0 | - | 17.2 / 17.2 | 8.1s |
| hardcoded-secret | 3 | 0 | 0.0% | 0 | - | 3.3 / 3.3 | 2.7s |
| ldapi | 3 | 0 | 0.0% | 0 | - | 3.7 / 4.3 | 15.2s |
| nosqli | 4 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 2.2s |
| open-redirect | 5 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 2.5s |
| path-traversal | 20 | 7 | 35.0% | 0 | 0.0% | 12.9 / 13.4 | 18.9s |
| sqli | 20 | 3 | 15.0% | 0 | 0.0% | 22.9 / 22.1 | 19.3s |
| ssrf | 5 | 1 | 20.0% | 0 | 0.0% | 5.4 / 4.4 | 2.3s |
| weak-crypto | 4 | 0 | 0.0% | 0 | - | 0.2 / 0.2 | 4.1s |
| xss | 5 | 0 | 0.0% | 0 | - | 3.8 / 3.8 | 7.6s |
| xxe | 4 | 1 | 25.0% | 0 | 0.0% | 0.8 / 0.8 | 0.4s |

## Cases

| case | package | releases | class | group | rule | vulnerable | fixed | in fix files | findings | unfinished files | scan time |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2014-6394 | npm send | 0.8.3 → 0.8.4 | path-traversal | rule source | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2014-6394 | npm send | 0.8.3 → 0.8.4 | path-traversal | rule source | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2015-7294 | npm ldapauth-fork | 2.3.2 → 2.3.3 | ldapi | independent | js-ldapi-filter | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2016-10928 | composer onelogin/wordpress-saml | v2.1.8 → v2.2.0 | hardcoded-secret | independent | php-hardcoded-secret-credentials | - | - | 0 | 4 / 4 | 0 / 0 | 1.1s / 1.2s |
| CVE-2016-20018 | npm knex | 2.3.0 → 2.4.0 | sqli | rule source | js-sqli-object-input | - | - | 0 | 4 / 4 | 0 / 0 | 0.8s / 0.8s |
| CVE-2016-20018 | npm knex | 2.3.0 → 2.4.0 | sqli | rule source | js-sqli-raw-interpolation | - | - | 0 | 4 / 4 | 0 / 0 | 0.8s / 0.8s |
| CVE-2016-20018 | npm knex | 2.3.0 → 2.4.0 | sqli | rule source | js-sqli-sequelize-literal | - | - | 0 | 4 / 4 | 0 / 0 | 0.8s / 0.8s |
| CVE-2017-14596 | composer joomla/joomla-cms | 3.7.5 → 3.8.0 | ldapi | independent | php-ldapi-filter | - | - | 0 | 11 / 13 | 0 / 0 | 45.9s / 41.4s |
| CVE-2017-20289 | wordpress-plugin ad-widget | 2.11.0 → 2.12.0 | path-traversal | independent | php-path-traversal-file-include | - | - | 1 | 5 / 5 | 0 / 0 | 0.2s / 0.3s |
| CVE-2017-20289 | wordpress-plugin ad-widget | 2.11.0 → 2.12.0 | path-traversal | independent | php-path-traversal-file-read | - | - | 1 | 5 / 5 | 0 / 0 | 0.2s / 0.3s |
| CVE-2017-20289 | wordpress-plugin ad-widget | 2.11.0 → 2.12.0 | path-traversal | independent | php-path-traversal-file-write | - | - | 1 | 5 / 5 | 0 / 0 | 0.2s / 0.3s |
| CVE-2017-20289 | wordpress-plugin ad-widget | 2.11.0 → 2.12.0 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 5 / 5 | 0 / 0 | 0.2s / 0.3s |
| CVE-2017-9841 | composer sebastianbergmann/phpunit | 5.6.2 → 5.6.3 | code-eval | rule source | php-code-eval-eval | caught | - | 1 | 1 / 0 | 0 / 0 | 2.0s / 1.8s |
| CVE-2018-1002204 | npm adm-zip | 0.4.9 → 0.4.11 | path-traversal | rule source | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2018-1002204 | npm adm-zip | 0.4.9 → 0.4.11 | path-traversal | rule source | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2018-15133 | composer laravel/framework | v5.6.29 → v5.6.30 | deserialization | rule source | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 4.7s / 4.8s |
| CVE-2018-15133 | composer laravel/framework | v5.6.29 → v5.6.30 | deserialization | rule source | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 4.7s / 4.8s |
| CVE-2018-3758 | npm express-cart | 1.1.6 → 1.1.7 | file-upload | independent | js-file-upload-client-name | - | - | 0 | 29 / 29 | 0 / 0 | 0.5s / 0.5s |
| CVE-2020-10799 | pypi svglib | 0.9.3 → 0.9.4 | xxe | independent | python-xxe-parser-entities | - | - | 0 | 0 / 0 | 0 / 0 | 0.3s / 0.3s |
| CVE-2020-12265 | npm decompress | 4.2.0 → 4.2.1 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2020-12265 | npm decompress | 4.2.0 → 4.2.1 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2020-29128 | pypi petl | 1.6.7 → 1.6.8 | xxe | independent | python-xxe-parser-entities | - | - | 0 | 2 / 3 | 0 / 0 | 0.7s / 0.6s |
| CVE-2020-36326 | composer PHPMailer/PHPMailer | v6.4.0 → v6.4.1 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 0.9s / 1.0s |
| CVE-2020-36326 | composer PHPMailer/PHPMailer | v6.4.0 → v6.4.1 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.9s / 1.0s |
| CVE-2021-21315 | npm systeminformation | 5.3.0 → 5.3.1 | cmdi | independent | js-cmdi-exec | - | - | 0 | 0 / 0 | 0 / 0 | 1.0s / 1.0s |
| CVE-2021-21315 | npm systeminformation | 5.3.0 → 5.3.1 | cmdi | independent | js-cmdi-spawn-shell | - | - | 0 | 0 / 0 | 0 / 0 | 1.0s / 1.0s |
| CVE-2021-23337 | npm lodash | 4.17.20 → 4.17.21 | code-eval | independent | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 3.1s / 2.9s |
| CVE-2021-23337 | npm lodash | 4.17.20 → 4.17.21 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 3.1s / 2.9s |
| CVE-2021-23344 | npm total.js | 3.4.7 → 3.4.8 | code-eval | rule source | js-code-eval-eval | - | - | 0 | 0 / 0 | 1 / 1 | 13.6s / 13.4s |
| CVE-2021-23344 | npm total.js | 3.4.7 → 3.4.8 | code-eval | rule source | js-code-eval-template-options | - | - | 0 | 0 / 0 | 1 / 1 | 13.6s / 13.4s |
| CVE-2021-23664 | npm @isomorphic-git/cors-proxy | 2.7.0 → 2.7.1 | ssrf | independent | js-ssrf-http-request | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2021-29454 | composer smarty-php/smarty | v3.1.41 → v3.1.42 | code-eval | independent | php-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 1.4s / 1.4s |
| CVE-2021-29472 | composer composer/composer | 2.0.12 → 2.0.13 | cmdi | rule source | php-cmdi-mail-params | - | - | 0 | 0 / 0 | 0 / 0 | 3.9s / 4.0s |
| CVE-2021-29472 | composer composer/composer | 2.0.12 → 2.0.13 | cmdi | rule source | php-cmdi-shell-exec | - | - | 0 | 0 / 0 | 0 / 0 | 3.9s / 4.0s |
| CVE-2021-3129 | composer facade/ignition | 2.5.1 → 2.5.2 | deserialization | rule source | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 3.6s / 3.4s |
| CVE-2021-3129 | composer facade/ignition | 2.5.1 → 2.5.2 | deserialization | rule source | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 3.6s / 3.4s |
| CVE-2021-35042 | pypi Django | 3.2.4 → 3.2.5 | sqli | independent | python-sqli-dbapi-format | - | - | 0 | 15 / 15 | 0 / 0 | 14.7s / 14.5s |
| CVE-2021-35042 | pypi Django | 3.2.4 → 3.2.5 | sqli | independent | python-sqli-django-kwargs-alias | - | - | 0 | 15 / 15 | 0 / 0 | 14.7s / 14.5s |
| CVE-2021-35042 | pypi Django | 3.2.4 → 3.2.5 | sqli | independent | python-sqli-sqlalchemy-text | - | - | 0 | 15 / 15 | 0 / 0 | 14.7s / 14.5s |
| CVE-2021-39182 | pypi enrocrypt | 1.1.3 → 1.1.4 | weak-crypto | independent | python-weak-crypto-cipher | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2021-39182 | pypi enrocrypt | 1.1.3 → 1.1.4 | weak-crypto | independent | python-weak-crypto-password-hash | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2022-22817 | pypi Pillow | 9.0.0 → 9.0.1 | code-eval | independent | python-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 2.1s / 3.2s |
| CVE-2022-22817 | pypi Pillow | 9.0.0 → 9.0.1 | code-eval | independent | python-code-eval-template-injection | - | - | 0 | 0 / 0 | 0 / 0 | 2.1s / 3.2s |
| CVE-2022-24439 | pypi GitPython | 3.1.29 → 3.1.30 | cmdi | independent | python-cmdi-argument-injection | - | - | 0 | 0 / 0 | 0 / 0 | 0.6s / 0.6s |
| CVE-2022-24439 | pypi GitPython | 3.1.29 → 3.1.30 | cmdi | independent | python-cmdi-shell | - | - | 0 | 0 / 0 | 0 / 0 | 0.6s / 0.6s |
| CVE-2022-28346 | pypi Django | 4.0.3 → 4.0.4 | sqli | rule source | python-sqli-dbapi-format | - | - | 0 | 15 / 15 | 0 / 0 | 16.3s / 17.0s |
| CVE-2022-28346 | pypi Django | 4.0.3 → 4.0.4 | sqli | rule source | python-sqli-django-kwargs-alias | - | - | 0 | 15 / 15 | 0 / 0 | 16.3s / 17.0s |
| CVE-2022-28346 | pypi Django | 4.0.3 → 4.0.4 | sqli | rule source | python-sqli-sqlalchemy-text | - | - | 0 | 15 / 15 | 0 / 0 | 16.3s / 17.0s |
| CVE-2022-2872 | pypi OctoPrint | 1.8.2 → 1.8.3 | file-upload | independent | python-file-upload-client-name | - | - | 0 | 12 / 12 | 0 / 0 | 15.4s / 15.9s |
| CVE-2022-29078 | npm ejs | 3.1.6 → 3.1.7 | code-eval | rule source | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.2s |
| CVE-2022-29078 | npm ejs | 3.1.6 → 3.1.7 | code-eval | rule source | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.2s |
| CVE-2022-3342 | wordpress-plugin zero-bs-crm | 5.3.1 → 5.4.0 | deserialization | independent | php-deserialization-phar-wrapper | caught | - | 5 | 30 / 19 | 0 / 0 | 28.4s / 23.6s |
| CVE-2022-3342 | wordpress-plugin zero-bs-crm | 5.3.1 → 5.4.0 | deserialization | independent | php-deserialization-unserialize | - | - | 5 | 30 / 19 | 0 / 0 | 28.4s / 23.6s |
| CVE-2022-34265 | pypi Django | 4.0.5 → 4.0.6 | sqli | independent | python-sqli-dbapi-format | - | - | 0 | 15 / 15 | 0 / 0 | 17.4s / 17.9s |
| CVE-2022-34265 | pypi Django | 4.0.5 → 4.0.6 | sqli | independent | python-sqli-django-kwargs-alias | - | - | 0 | 15 / 15 | 0 / 0 | 17.4s / 17.9s |
| CVE-2022-34265 | pypi Django | 4.0.5 → 4.0.6 | sqli | independent | python-sqli-sqlalchemy-text | - | - | 0 | 15 / 15 | 0 / 0 | 17.4s / 17.9s |
| CVE-2022-41343 | composer dompdf/dompdf | v2.0.0 → v2.0.1 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 3.6s / 3.1s |
| CVE-2022-41343 | composer dompdf/dompdf | v2.0.0 → v2.0.1 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 3.6s / 3.1s |
| CVE-2023-0297 | pypi pyload-ng | 0.5.0b3.dev30 → 0.5.0b3.dev31 | code-eval | rule source | python-code-eval-eval | - | - | 0 | 13 / 13 | 0 / 0 | 3.7s / 3.7s |
| CVE-2023-0297 | pypi pyload-ng | 0.5.0b3.dev30 → 0.5.0b3.dev31 | code-eval | rule source | python-code-eval-template-injection | - | - | 0 | 13 / 13 | 0 / 0 | 3.7s / 3.7s |
| CVE-2023-25813 | npm sequelize | 6.19.0 → 6.19.1 | sqli | independent | js-sqli-object-input | - | - | 0 | 0 / 0 | 0 / 0 | 1.5s / 1.5s |
| CVE-2023-25813 | npm sequelize | 6.19.0 → 6.19.1 | sqli | independent | js-sqli-raw-interpolation | - | - | 0 | 0 / 0 | 0 / 0 | 1.5s / 1.5s |
| CVE-2023-25813 | npm sequelize | 6.19.0 → 6.19.1 | sqli | independent | js-sqli-sequelize-literal | - | - | 0 | 0 / 0 | 0 / 0 | 1.5s / 1.5s |
| CVE-2023-28115 | composer KnpLabs/snappy | v1.4.1 → v1.4.2 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2023-28115 | composer KnpLabs/snappy | v1.4.1 → v1.4.2 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2023-3452 | wordpress-plugin canto | 3.0.4 → 3.0.5 | path-traversal | independent | php-path-traversal-file-include | caught | - | 1 | 21 / 23 | 1 / 1 | 0.9s / 0.7s |
| CVE-2023-3452 | wordpress-plugin canto | 3.0.4 → 3.0.5 | path-traversal | independent | php-path-traversal-file-read | - | - | 1 | 21 / 23 | 1 / 1 | 0.9s / 0.7s |
| CVE-2023-3452 | wordpress-plugin canto | 3.0.4 → 3.0.5 | path-traversal | independent | php-path-traversal-file-write | - | - | 1 | 21 / 23 | 1 / 1 | 0.9s / 0.7s |
| CVE-2023-3452 | wordpress-plugin canto | 3.0.4 → 3.0.5 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 21 / 23 | 1 / 1 | 0.9s / 0.7s |
| CVE-2023-46233 | npm crypto-js | 4.1.1 → 4.2.0 | weak-crypto | independent | js-weak-crypto-cipher | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.3s |
| CVE-2023-46233 | npm crypto-js | 4.1.1 → 4.2.0 | weak-crypto | independent | js-weak-crypto-password-hash | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.3s |
| CVE-2023-6120 | wordpress-plugin usc-e-shop | 2.9.6 → 2.9.7 | path-traversal | rule source | php-path-traversal-file-include | - | - | 1 | 78 / 77 | 1 / 1 | 57.3s / 55.8s |
| CVE-2023-6120 | wordpress-plugin usc-e-shop | 2.9.6 → 2.9.7 | path-traversal | rule source | php-path-traversal-file-read | - | - | 1 | 78 / 77 | 1 / 1 | 57.3s / 55.8s |
| CVE-2023-6120 | wordpress-plugin usc-e-shop | 2.9.6 → 2.9.7 | path-traversal | rule source | php-path-traversal-file-write | caught | - | 1 | 78 / 77 | 1 / 1 | 57.3s / 55.8s |
| CVE-2023-6120 | wordpress-plugin usc-e-shop | 2.9.6 → 2.9.7 | path-traversal | rule source | php-path-traversal-laravel-storage | - | - | 1 | 78 / 77 | 1 / 1 | 57.3s / 55.8s |
| CVE-2024-12032 | wordpress-plugin tourfic | 2.15.3 → 2.15.4 | sqli | independent | php-sqli-orderby-identifier | - | - | 1 | 32 / 31 | 0 / 0 | 25.2s / 27.6s |
| CVE-2024-12032 | wordpress-plugin tourfic | 2.15.3 → 2.15.4 | sqli | independent | php-sqli-string-concat | - | - | 1 | 32 / 31 | 0 / 0 | 25.2s / 27.6s |
| CVE-2024-12032 | wordpress-plugin tourfic | 2.15.3 → 2.15.4 | sqli | independent | php-sqli-wpdb-unprepared | caught | - | 1 | 32 / 31 | 0 / 0 | 25.2s / 27.6s |
| CVE-2024-12850 | wordpress-plugin database-backup | 2.32 → 2.33 | path-traversal | independent | php-path-traversal-file-include | - | - | 1 | 5 / 4 | 0 / 0 | 0.6s / 0.6s |
| CVE-2024-12850 | wordpress-plugin database-backup | 2.32 → 2.33 | path-traversal | independent | php-path-traversal-file-read | caught | - | 1 | 5 / 4 | 0 / 0 | 0.6s / 0.6s |
| CVE-2024-12850 | wordpress-plugin database-backup | 2.32 → 2.33 | path-traversal | independent | php-path-traversal-file-write | - | - | 1 | 5 / 4 | 0 / 0 | 0.6s / 0.6s |
| CVE-2024-12850 | wordpress-plugin database-backup | 2.32 → 2.33 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 5 / 4 | 0 / 0 | 0.6s / 0.6s |
| CVE-2024-21641 | composer flarum/flarum-core | v1.8.4 → v1.8.5 | open-redirect | independent | php-open-redirect-redirect | - | - | 0 | 0 / 0 | 0 / 0 | 7.0s / 6.8s |
| CVE-2024-22205 | pypi whoogle-search | 0.8.3 → 0.8.4 | ssrf | independent | python-ssrf-http-request | - | - | 0 | 7 / 7 | 0 / 0 | 0.4s / 0.4s |
| CVE-2024-3136 | wordpress-plugin masterstudy-lms-learning-management-system | 3.3.3 → 3.3.4 | path-traversal | rule source | php-path-traversal-file-include | caught | - | 1 | 4 / 3 | 3 / 3 | 28.4s / 29.0s |
| CVE-2024-3136 | wordpress-plugin masterstudy-lms-learning-management-system | 3.3.3 → 3.3.4 | path-traversal | rule source | php-path-traversal-file-read | - | - | 1 | 4 / 3 | 3 / 3 | 28.4s / 29.0s |
| CVE-2024-3136 | wordpress-plugin masterstudy-lms-learning-management-system | 3.3.3 → 3.3.4 | path-traversal | rule source | php-path-traversal-file-write | - | - | 1 | 4 / 3 | 3 / 3 | 28.4s / 29.0s |
| CVE-2024-3136 | wordpress-plugin masterstudy-lms-learning-management-system | 3.3.3 → 3.3.4 | path-traversal | rule source | php-path-traversal-laravel-storage | - | - | 1 | 4 / 3 | 3 / 3 | 28.4s / 29.0s |
| CVE-2024-34345 | npm @cyclonedx/cyclonedx-library | 6.7.0 → 6.7.1 | xxe | independent | js-xxe-libxmljs-noent | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.5s |
| CVE-2024-34914 | composer php-censor/php-censor | 2.1.4 → 2.1.5 | weak-crypto | independent | php-weak-crypto-cipher | - | - | 0 | 0 / 0 | 0 / 0 | 1.3s / 1.3s |
| CVE-2024-34914 | composer php-censor/php-censor | 2.1.4 → 2.1.5 | weak-crypto | independent | php-weak-crypto-password-hash | - | - | 0 | 0 / 0 | 0 / 0 | 1.3s / 1.3s |
| CVE-2024-42353 | pypi webob | 1.8.7 → 1.8.8 | open-redirect | independent | python-open-redirect-redirect | - | - | 0 | 0 / 0 | 0 / 0 | 1.1s / 1.1s |
| CVE-2024-4359 | wordpress-plugin bdthemes-element-pack-lite | 5.7.2 → 5.7.3 | path-traversal | independent | php-path-traversal-file-include | - | - | 1 | 22 / 19 | 0 / 0 | 13.3s / 13.7s |
| CVE-2024-4359 | wordpress-plugin bdthemes-element-pack-lite | 5.7.2 → 5.7.3 | path-traversal | independent | php-path-traversal-file-read | caught | - | 1 | 22 / 19 | 0 / 0 | 13.3s / 13.7s |
| CVE-2024-4359 | wordpress-plugin bdthemes-element-pack-lite | 5.7.2 → 5.7.3 | path-traversal | independent | php-path-traversal-file-write | - | - | 1 | 22 / 19 | 0 / 0 | 13.3s / 13.7s |
| CVE-2024-4359 | wordpress-plugin bdthemes-element-pack-lite | 5.7.2 → 5.7.3 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 22 / 19 | 0 / 0 | 13.3s / 13.7s |
| CVE-2024-4887 | wordpress-plugin qi-addons-for-elementor | 1.7.2 → 1.7.3 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 0 / 0 | 0 / 0 | 6.4s / 6.0s |
| CVE-2024-4887 | wordpress-plugin qi-addons-for-elementor | 1.7.2 → 1.7.3 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 0 / 0 | 0 / 0 | 6.4s / 6.0s |
| CVE-2024-4887 | wordpress-plugin qi-addons-for-elementor | 1.7.2 → 1.7.3 | path-traversal | independent | php-path-traversal-file-write | - | - | 0 | 0 / 0 | 0 / 0 | 6.4s / 6.0s |
| CVE-2024-4887 | wordpress-plugin qi-addons-for-elementor | 1.7.2 → 1.7.3 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 0 / 0 | 0 / 0 | 6.4s / 6.0s |
| CVE-2024-8392 | wordpress-plugin sogrid | 1.5.6 → 1.5.7 | path-traversal | independent | php-path-traversal-file-include | caught | - | 1 | 1 / 0 | 0 / 0 | 0.3s / 0.3s |
| CVE-2024-8392 | wordpress-plugin sogrid | 1.5.6 → 1.5.7 | path-traversal | independent | php-path-traversal-file-read | - | - | 1 | 1 / 0 | 0 / 0 | 0.3s / 0.3s |
| CVE-2024-8392 | wordpress-plugin sogrid | 1.5.6 → 1.5.7 | path-traversal | independent | php-path-traversal-file-write | - | - | 1 | 1 / 0 | 0 / 0 | 0.3s / 0.3s |
| CVE-2024-8392 | wordpress-plugin sogrid | 1.5.6 → 1.5.7 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 1 / 0 | 0 / 0 | 0.3s / 0.3s |
| CVE-2025-11167 | wordpress-plugin cm-invitation-codes | 2.5.5 → 2.6.0 | open-redirect | independent | php-open-redirect-redirect | - | - | 0 | 0 / 0 | 0 / 0 | 3.1s / 3.1s |
| CVE-2025-13145 | wordpress-plugin wp-ultimate-csv-importer | 7.33.1 → 7.34 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 77 / 77 | 1 / 1 | 17.1s / 12.8s |
| CVE-2025-13145 | wordpress-plugin wp-ultimate-csv-importer | 7.33.1 → 7.34 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 77 / 77 | 1 / 1 | 17.1s / 12.8s |
| CVE-2025-1324 | wordpress-plugin wp-recall | 16.26.10 → 16.26.12 | xss | independent | php-xss-echo-attribute | - | - | 0 | 18 / 18 | 0 / 0 | 9.7s / 7.9s |
| CVE-2025-1324 | wordpress-plugin wp-recall | 16.26.10 → 16.26.12 | xss | independent | php-xss-echo-html | - | - | 0 | 18 / 18 | 0 / 0 | 9.7s / 7.9s |
| CVE-2025-1324 | wordpress-plugin wp-recall | 16.26.10 → 16.26.12 | xss | independent | php-xss-echo-script | - | - | 0 | 18 / 18 | 0 / 0 | 9.7s / 7.9s |
| CVE-2025-1324 | wordpress-plugin wp-recall | 16.26.10 → 16.26.12 | xss | independent | php-xss-echo-url | - | - | 0 | 18 / 18 | 0 / 0 | 9.7s / 7.9s |
| CVE-2025-13378 | wordpress-plugin ays-chatgpt-assistant | 2.7.0 → 2.7.1 | ssrf | independent | php-ssrf-http-request | caught | - | 6 | 7 / 2 | 0 / 0 | 1.8s / 1.8s |
| CVE-2025-13393 | wordpress-plugin featured-image-from-url | 5.3.1 → 5.3.2 | ssrf | independent | php-ssrf-http-request | - | - | 0 | 3 / 3 | 0 / 0 | 1.5s / 1.4s |
| CVE-2025-13641 | wordpress-plugin nextgen-gallery | 3.59.12 → 4.0.0 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 9 / 28 | 1 / 2 | 13.4s / 19.6s |
| CVE-2025-13641 | wordpress-plugin nextgen-gallery | 3.59.12 → 4.0.0 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 9 / 28 | 1 / 2 | 13.4s / 19.6s |
| CVE-2025-13641 | wordpress-plugin nextgen-gallery | 3.59.12 → 4.0.0 | path-traversal | independent | php-path-traversal-file-write | - | - | 0 | 9 / 28 | 1 / 2 | 13.4s / 19.6s |
| CVE-2025-13641 | wordpress-plugin nextgen-gallery | 3.59.12 → 4.0.0 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 9 / 28 | 1 / 2 | 13.4s / 19.6s |
| CVE-2025-13999 | wordpress-plugin html5-audio-player | 2.5.1 → 2.5.2 | ssrf | independent | php-ssrf-http-request | - | - | 0 | 10 / 10 | 0 / 0 | 7.4s / 7.8s |
| CVE-2025-14071 | wordpress-plugin live-composer-page-builder | 2.0.2 → 2.0.3 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 3 | 240 / 237 | 0 / 0 | 15.3s / 14.3s |
| CVE-2025-14071 | wordpress-plugin live-composer-page-builder | 2.0.2 → 2.0.3 | deserialization | independent | php-deserialization-unserialize | caught | - | 3 | 240 / 237 | 0 / 0 | 15.3s / 14.3s |
| CVE-2025-14383 | wordpress-plugin booking | 10.14.8 → 10.14.9 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 30 / 30 | 0 / 0 | 24.2s / 26.3s |
| CVE-2025-14383 | wordpress-plugin booking | 10.14.8 → 10.14.9 | sqli | independent | php-sqli-string-concat | - | - | 0 | 30 / 30 | 0 / 0 | 24.2s / 26.3s |
| CVE-2025-14383 | wordpress-plugin booking | 10.14.8 → 10.14.9 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 30 / 30 | 0 / 0 | 24.2s / 26.3s |
| CVE-2025-1783 | wordpress-plugin gallery-styles | 1.3.4 → 1.3.5 | xss | independent | php-xss-echo-attribute | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2025-1783 | wordpress-plugin gallery-styles | 1.3.4 → 1.3.5 | xss | independent | php-xss-echo-html | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2025-1783 | wordpress-plugin gallery-styles | 1.3.4 → 1.3.5 | xss | independent | php-xss-echo-script | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2025-1783 | wordpress-plugin gallery-styles | 1.3.4 → 1.3.5 | xss | independent | php-xss-echo-url | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2025-27411 | composer redaxo/redaxo | 5.18.2 → 5.18.3 | file-upload | independent | php-file-upload-client-name | - | - | 0 | 35 / 35 | 0 / 0 | 7.1s / 7.6s |
| CVE-2025-32379 | npm koa | 2.16.0 → 2.16.1 | xss | independent | js-xss-dom | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2025-32379 | npm koa | 2.16.0 → 2.16.1 | xss | independent | js-xss-response-url | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2025-32379 | npm koa | 2.16.0 → 2.16.1 | xss | independent | js-xss-response | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2025-3914 | wordpress-plugin aeropage-sync-for-airtable | 3.2.0 → 3.3.0 | file-upload | independent | php-file-upload-client-name | - | - | 0 | 0 / 0 | 0 / 1 | 3.6s / 1.3s |
| CVE-2025-48882 | composer PHPOffice/Math | 0.2.0 → 0.3.0 | xxe | independent | php-xxe-libxml-noent | caught | - | 1 | 1 / 0 | 0 / 0 | 0.1s / 0.0s |
| CVE-2025-54140 | pypi pyload-ng | 0.5.0b3.dev89 → 0.5.0b3.dev90 | path-traversal | rule source | python-path-traversal-archive-extract | - | - | 2 | 13 / 10 | 0 / 0 | 3.9s / 4.0s |
| CVE-2025-54140 | pypi pyload-ng | 0.5.0b3.dev89 → 0.5.0b3.dev90 | path-traversal | rule source | python-path-traversal-send-file | caught | - | 2 | 13 / 10 | 0 / 0 | 3.9s / 4.0s |
| CVE-2025-55449 | pypi astrbot | 3.5.17 → 3.5.18 | hardcoded-secret | independent | python-hardcoded-secret-credentials | - | - | 0 | 4 / 4 | 0 / 0 | 1.4s / 1.4s |
| CVE-2025-59681 | pypi Django | 5.2.6 → 5.2.7 | sqli | rule source | python-sqli-dbapi-format | - | - | 0 | 16 / 16 | 0 / 0 | 18.9s / 21.8s |
| CVE-2025-59681 | pypi Django | 5.2.6 → 5.2.7 | sqli | rule source | python-sqli-django-kwargs-alias | - | - | 0 | 16 / 16 | 0 / 0 | 18.9s / 21.8s |
| CVE-2025-59681 | pypi Django | 5.2.6 → 5.2.7 | sqli | rule source | python-sqli-sqlalchemy-text | - | - | 0 | 16 / 16 | 0 / 0 | 18.9s / 21.8s |
| CVE-2025-62595 | npm koa | 3.0.2 → 3.0.3 | open-redirect | independent | js-open-redirect-redirect | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2025-67502 | pypi taguette | 1.5.1 → 1.5.2 | open-redirect | independent | python-open-redirect-redirect | - | - | 0 | 0 / 0 | 0 / 0 | 1.6s / 1.6s |
| CVE-2025-67724 | pypi tornado | 6.5.2 → 6.5.3 | xss | independent | python-xss-mark-safe | - | - | 0 | 0 / 0 | 0 / 0 | 1.9s / 2.1s |
| CVE-2025-67724 | pypi tornado | 6.5.2 → 6.5.3 | xss | independent | python-xss-response | - | - | 0 | 0 / 0 | 0 / 0 | 1.9s / 2.1s |
| CVE-2025-69971 | npm @frangoteam/fuxa | 1.2.11 → 1.3.0 | hardcoded-secret | independent | js-hardcoded-secret-credentials | - | - | 0 | 2 / 2 | 1 / 1 | 5.5s / 5.9s |
| CVE-2025-7036 | wordpress-plugin cleverreach-wp | 1.5.20 → 1.5.21 | sqli | rule source | php-sqli-orderby-identifier | - | - | 0 | 1 / 1 | 0 / 0 | 0.6s / 0.6s |
| CVE-2025-7036 | wordpress-plugin cleverreach-wp | 1.5.20 → 1.5.21 | sqli | rule source | php-sqli-string-concat | - | - | 0 | 1 / 1 | 0 / 0 | 0.6s / 0.6s |
| CVE-2025-7036 | wordpress-plugin cleverreach-wp | 1.5.20 → 1.5.21 | sqli | rule source | php-sqli-wpdb-unprepared | - | - | 0 | 1 / 1 | 0 / 0 | 0.6s / 0.6s |
| CVE-2025-8897 | wordpress-plugin beaver-builder-lite-version | 2.9.2.1 → 2.9.3.1 | xss | independent | php-xss-echo-attribute | - | - | 0 | 1 / 1 | 1 / 1 | 29.6s / 25.1s |
| CVE-2025-8897 | wordpress-plugin beaver-builder-lite-version | 2.9.2.1 → 2.9.3.1 | xss | independent | php-xss-echo-html | - | - | 0 | 1 / 1 | 1 / 1 | 29.6s / 25.1s |
| CVE-2025-8897 | wordpress-plugin beaver-builder-lite-version | 2.9.2.1 → 2.9.3.1 | xss | independent | php-xss-echo-script | - | - | 0 | 1 / 1 | 1 / 1 | 29.6s / 25.1s |
| CVE-2025-8897 | wordpress-plugin beaver-builder-lite-version | 2.9.2.1 → 2.9.3.1 | xss | independent | php-xss-echo-url | - | - | 0 | 1 / 1 | 1 / 1 | 29.6s / 25.1s |
| CVE-2025-9462 | wordpress-plugin wp2leads | 3.5.6 → 3.5.12 | sqli | independent | php-sqli-orderby-identifier | caught | - | 2 | 75 / 72 | 0 / 0 | 24.2s / 21.6s |
| CVE-2025-9462 | wordpress-plugin wp2leads | 3.5.6 → 3.5.12 | sqli | independent | php-sqli-string-concat | - | - | 2 | 75 / 72 | 0 / 0 | 24.2s / 21.6s |
| CVE-2025-9462 | wordpress-plugin wp2leads | 3.5.6 → 3.5.12 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 2 | 75 / 72 | 0 / 0 | 24.2s / 21.6s |
| CVE-2026-101325 | wordpress-plugin newsletters-lite | 4.18.1 → 4.18.2 | sqli | independent | php-sqli-orderby-identifier | - | - | 25 | 206 / 199 | 3 / 2 | 75.5s / 67.3s |
| CVE-2026-101325 | wordpress-plugin newsletters-lite | 4.18.1 → 4.18.2 | sqli | independent | php-sqli-string-concat | - | - | 25 | 206 / 199 | 3 / 2 | 75.5s / 67.3s |
| CVE-2026-101325 | wordpress-plugin newsletters-lite | 4.18.1 → 4.18.2 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 25 | 206 / 199 | 3 / 2 | 75.5s / 67.3s |
| CVE-2026-103914 | wordpress-plugin anywhere-elementor | 1.3.0 → 1.3.1 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 3 / 2 | 0 / 1 | 4.0s / 9.3s |
| CVE-2026-103914 | wordpress-plugin anywhere-elementor | 1.3.0 → 1.3.1 | sqli | independent | php-sqli-string-concat | - | - | 0 | 3 / 2 | 0 / 1 | 4.0s / 9.3s |
| CVE-2026-103914 | wordpress-plugin anywhere-elementor | 1.3.0 → 1.3.1 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 3 / 2 | 0 / 1 | 4.0s / 9.3s |
| CVE-2026-104746 | wordpress-plugin motors-car-dealership-classified-listings | 1.4.125 → 1.4.126 | path-traversal | rule source | php-path-traversal-file-include | - | - | 0 | 2 / 2 | 3 / 3 | 57.7s / 41.8s |
| CVE-2026-104746 | wordpress-plugin motors-car-dealership-classified-listings | 1.4.125 → 1.4.126 | path-traversal | rule source | php-path-traversal-file-read | - | - | 0 | 2 / 2 | 3 / 3 | 57.7s / 41.8s |
| CVE-2026-104746 | wordpress-plugin motors-car-dealership-classified-listings | 1.4.125 → 1.4.126 | path-traversal | rule source | php-path-traversal-file-write | - | - | 0 | 2 / 2 | 3 / 3 | 57.7s / 41.8s |
| CVE-2026-104746 | wordpress-plugin motors-car-dealership-classified-listings | 1.4.125 → 1.4.126 | path-traversal | rule source | php-path-traversal-laravel-storage | - | - | 0 | 2 / 2 | 3 / 3 | 57.7s / 41.8s |
| CVE-2026-104899 | wordpress-plugin geodirectory | 2.8.187 → 2.8.188 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 48 / 48 | 0 / 0 | 54.6s / 55.6s |
| CVE-2026-104899 | wordpress-plugin geodirectory | 2.8.187 → 2.8.188 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 48 / 48 | 0 / 0 | 54.6s / 55.6s |
| CVE-2026-104899 | wordpress-plugin geodirectory | 2.8.187 → 2.8.188 | path-traversal | independent | php-path-traversal-file-write | - | - | 0 | 48 / 48 | 0 / 0 | 54.6s / 55.6s |
| CVE-2026-104899 | wordpress-plugin geodirectory | 2.8.187 → 2.8.188 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 48 / 48 | 0 / 0 | 54.6s / 55.6s |
| CVE-2026-106119 | npm @langchain/mongodb | 1.3.0 → 1.3.1 | nosqli | independent | js-nosqli-mongo-query | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2026-110284 | wordpress-plugin lifterlms | 10.3.1 → 10.3.2 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 1 / 1 | 0 / 0 | 17.2s / 19.4s |
| CVE-2026-110284 | wordpress-plugin lifterlms | 10.3.1 → 10.3.2 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 1 / 1 | 0 / 0 | 17.2s / 19.4s |
| CVE-2026-110284 | wordpress-plugin lifterlms | 10.3.1 → 10.3.2 | path-traversal | independent | php-path-traversal-file-write | - | - | 0 | 1 / 1 | 0 / 0 | 17.2s / 19.4s |
| CVE-2026-110284 | wordpress-plugin lifterlms | 10.3.1 → 10.3.2 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 1 / 1 | 0 / 0 | 17.2s / 19.4s |
| CVE-2026-114630 | wordpress-plugin elex-helpdesk-customer-support-ticket-system | 3.3.8 → 3.3.9 | path-traversal | rule source | php-path-traversal-file-include | - | - | 0 | 0 / 0 | 0 / 0 | 45.1s / 39.5s |
| CVE-2026-114630 | wordpress-plugin elex-helpdesk-customer-support-ticket-system | 3.3.8 → 3.3.9 | path-traversal | rule source | php-path-traversal-file-read | - | - | 0 | 0 / 0 | 0 / 0 | 45.1s / 39.5s |
| CVE-2026-114630 | wordpress-plugin elex-helpdesk-customer-support-ticket-system | 3.3.8 → 3.3.9 | path-traversal | rule source | php-path-traversal-file-write | - | - | 0 | 0 / 0 | 0 / 0 | 45.1s / 39.5s |
| CVE-2026-114630 | wordpress-plugin elex-helpdesk-customer-support-ticket-system | 3.3.8 → 3.3.9 | path-traversal | rule source | php-path-traversal-laravel-storage | - | - | 0 | 0 / 0 | 0 / 0 | 45.1s / 39.5s |
| CVE-2026-118192 | wordpress-plugin joomsport-sports-league-results-management | 5.7.11 → 5.7.14 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 3 / 3 | 0 / 0 | 10.7s / 10.9s |
| CVE-2026-118192 | wordpress-plugin joomsport-sports-league-results-management | 5.7.11 → 5.7.14 | sqli | independent | php-sqli-string-concat | - | - | 0 | 3 / 3 | 0 / 0 | 10.7s / 10.9s |
| CVE-2026-118192 | wordpress-plugin joomsport-sports-league-results-management | 5.7.11 → 5.7.14 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 3 / 3 | 0 / 0 | 10.7s / 10.9s |
| CVE-2026-118698 | wordpress-plugin joomsport-sports-league-results-management | 5.7.14 → 5.7.15 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 3 / 3 | 0 / 0 | 13.4s / 12.3s |
| CVE-2026-118698 | wordpress-plugin joomsport-sports-league-results-management | 5.7.14 → 5.7.15 | sqli | independent | php-sqli-string-concat | - | - | 0 | 3 / 3 | 0 / 0 | 13.4s / 12.3s |
| CVE-2026-118698 | wordpress-plugin joomsport-sports-league-results-management | 5.7.14 → 5.7.15 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 3 / 3 | 0 / 0 | 13.4s / 12.3s |
| CVE-2026-119163 | wordpress-plugin wp-marketing-automations | 3.8.5.2 → 3.8.6 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 0 / 0 | 2 / 2 | 44.6s / 41.7s |
| CVE-2026-119163 | wordpress-plugin wp-marketing-automations | 3.8.5.2 → 3.8.6 | sqli | independent | php-sqli-string-concat | - | - | 0 | 0 / 0 | 2 / 2 | 44.6s / 41.7s |
| CVE-2026-119163 | wordpress-plugin wp-marketing-automations | 3.8.5.2 → 3.8.6 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 0 / 0 | 2 / 2 | 44.6s / 41.7s |
| CVE-2026-120043 | wordpress-plugin slicewp | 1.2.14 → 1.2.15 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 4 / 4 | 0 / 0 | 7.0s / 7.6s |
| CVE-2026-120043 | wordpress-plugin slicewp | 1.2.14 → 1.2.15 | sqli | independent | php-sqli-string-concat | - | - | 0 | 4 / 4 | 0 / 0 | 7.0s / 7.6s |
| CVE-2026-120043 | wordpress-plugin slicewp | 1.2.14 → 1.2.15 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 4 / 4 | 0 / 0 | 7.0s / 7.6s |
| CVE-2026-120530 | wordpress-plugin wp-migration-duplicator | 1.6.1 → 1.6.2 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 20 / 20 | 0 / 0 | 3.1s / 4.1s |
| CVE-2026-120530 | wordpress-plugin wp-migration-duplicator | 1.6.1 → 1.6.2 | sqli | independent | php-sqli-string-concat | - | - | 0 | 20 / 20 | 0 / 0 | 3.1s / 4.1s |
| CVE-2026-120530 | wordpress-plugin wp-migration-duplicator | 1.6.1 → 1.6.2 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 20 / 20 | 0 / 0 | 3.1s / 4.1s |
| CVE-2026-122265 | wordpress-plugin vanquish-upload-files-for-woocommerce | 2.7.13 → 2.8.0 | path-traversal | independent | php-path-traversal-file-include | - | - | 2 | 20 / 20 | 0 / 0 | 14.9s / 13.6s |
| CVE-2026-122265 | wordpress-plugin vanquish-upload-files-for-woocommerce | 2.7.13 → 2.8.0 | path-traversal | independent | php-path-traversal-file-read | - | - | 2 | 20 / 20 | 0 / 0 | 14.9s / 13.6s |
| CVE-2026-122265 | wordpress-plugin vanquish-upload-files-for-woocommerce | 2.7.13 → 2.8.0 | path-traversal | independent | php-path-traversal-file-write | - | - | 2 | 20 / 20 | 0 / 0 | 14.9s / 13.6s |
| CVE-2026-122265 | wordpress-plugin vanquish-upload-files-for-woocommerce | 2.7.13 → 2.8.0 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 2 | 20 / 20 | 0 / 0 | 14.9s / 13.6s |
| CVE-2026-13357 | wordpress-plugin houzez-property-feed | 2.5.46 → 2.5.47 | sqli | rule source | php-sqli-orderby-identifier | caught | - | 4 | 15 / 11 | 0 / 0 | 67.7s / 67.3s |
| CVE-2026-13357 | wordpress-plugin houzez-property-feed | 2.5.46 → 2.5.47 | sqli | rule source | php-sqli-string-concat | - | - | 4 | 15 / 11 | 0 / 0 | 67.7s / 67.3s |
| CVE-2026-13357 | wordpress-plugin houzez-property-feed | 2.5.46 → 2.5.47 | sqli | rule source | php-sqli-wpdb-unprepared | caught | - | 4 | 15 / 11 | 0 / 0 | 67.7s / 67.3s |
| CVE-2026-1756 | wordpress-plugin wp-foft-loader | 2.1.39 → 2.1.40 | file-upload | independent | php-file-upload-client-name | - | - | 0 | 10 / 10 | 0 / 0 | 14.9s / 14.2s |
| CVE-2026-24009 | pypi docling-core | 2.48.3 → 2.48.4 | deserialization | rule source | python-deserialization-pickle | - | - | 0 | 0 / 0 | 0 / 0 | 1.7s / 1.7s |
| CVE-2026-24009 | pypi docling-core | 2.48.3 → 2.48.4 | deserialization | rule source | python-deserialization-yaml-load | - | - | 0 | 0 / 0 | 0 / 0 | 1.7s / 1.7s |
| CVE-2026-26198 | pypi ormar | 0.22.0 → 0.23.0 | sqli | rule source | python-sqli-dbapi-format | - | - | 0 | 0 / 0 | 0 / 0 | 0.3s / 0.4s |
| CVE-2026-26198 | pypi ormar | 0.22.0 → 0.23.0 | sqli | rule source | python-sqli-django-kwargs-alias | - | - | 0 | 0 / 0 | 0 / 0 | 0.3s / 0.4s |
| CVE-2026-26198 | pypi ormar | 0.22.0 → 0.23.0 | sqli | rule source | python-sqli-sqlalchemy-text | - | - | 0 | 0 / 0 | 0 / 0 | 0.3s / 0.4s |
| CVE-2026-29793 | npm @feathersjs/mongodb | 5.0.41 → 5.0.42 | nosqli | independent | js-nosqli-mongo-query | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2026-41228 | composer froxlor/froxlor | 2.3.5 → 2.3.6 | path-traversal | rule source | php-path-traversal-file-include | - | - | 0 | 9 / 9 | 0 / 0 | 19.3s / 16.0s |
| CVE-2026-41228 | composer froxlor/froxlor | 2.3.5 → 2.3.6 | path-traversal | rule source | php-path-traversal-file-read | - | - | 0 | 9 / 9 | 0 / 0 | 19.3s / 16.0s |
| CVE-2026-41228 | composer froxlor/froxlor | 2.3.5 → 2.3.6 | path-traversal | rule source | php-path-traversal-file-write | - | - | 0 | 9 / 9 | 0 / 0 | 19.3s / 16.0s |
| CVE-2026-41228 | composer froxlor/froxlor | 2.3.5 → 2.3.6 | path-traversal | rule source | php-path-traversal-laravel-storage | - | - | 0 | 9 / 9 | 0 / 0 | 19.3s / 16.0s |
| CVE-2026-46745 | pypi apache-airflow-providers-fab | 3.6.3 → 3.6.4 | ldapi | independent | python-ldapi-filter | - | - | 0 | 0 / 0 | 0 / 0 | 1.8s / 1.8s |
| CVE-2026-48488 | composer thorsten/phpMyFAQ | 4.1.3 → 4.1.4 | weak-crypto | independent | php-weak-crypto-cipher | - | - | 0 | 1 / 1 | 0 / 0 | 14.4s / 14.9s |
| CVE-2026-48488 | composer thorsten/phpMyFAQ | 4.1.3 → 4.1.4 | weak-crypto | independent | php-weak-crypto-password-hash | - | - | 0 | 1 / 1 | 0 / 0 | 14.4s / 14.9s |
| CVE-2026-56738 | composer thorsten/phpMyFAQ | 4.1.5 → 4.1.6 | sqli | rule source | php-sqli-orderby-identifier | - | - | 0 | 1 / 1 | 0 / 0 | 16.0s / 15.4s |
| CVE-2026-56738 | composer thorsten/phpMyFAQ | 4.1.5 → 4.1.6 | sqli | rule source | php-sqli-string-concat | - | - | 0 | 1 / 1 | 0 / 0 | 16.0s / 15.4s |
| CVE-2026-56738 | composer thorsten/phpMyFAQ | 4.1.5 → 4.1.6 | sqli | rule source | php-sqli-wpdb-unprepared | - | - | 0 | 1 / 1 | 0 / 0 | 16.0s / 15.4s |
| CVE-2026-88023 | composer mongodb/mongo-php-library | 1.21.4 → 1.21.5 | nosqli | independent | php-nosqli-mongo-query | - | - | 0 | 0 / 0 | 0 / 0 | 0.9s / 0.9s |
| CVE-2026-88029 | pypi pymongo | 4.18.0 → 4.18.1 | nosqli | independent | python-nosqli-mongo-query | - | - | 0 | 0 / 0 | 0 / 0 | 6.9s / 8.5s |
| CVE-2026-9231 | wordpress-plugin wp-travel-engine | 6.8.0 → 6.8.1 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 20 / 20 | 6 / 5 | 55.1s / 52.7s |
| CVE-2026-9231 | wordpress-plugin wp-travel-engine | 6.8.0 → 6.8.1 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 20 / 20 | 6 / 5 | 55.1s / 52.7s |
| CVE-2026-9231 | wordpress-plugin wp-travel-engine | 6.8.0 → 6.8.1 | path-traversal | independent | php-path-traversal-file-write | - | - | 0 | 20 / 20 | 6 / 5 | 55.1s / 52.7s |
| CVE-2026-9231 | wordpress-plugin wp-travel-engine | 6.8.0 → 6.8.1 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 20 / 20 | 6 / 5 | 55.1s / 52.7s |

<!-- measured at integ-3205c10 -->
