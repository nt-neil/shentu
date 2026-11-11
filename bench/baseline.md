# CVE bench

2026-11-09, 33 rules, 59 cases.

- caught: a rule of the case's class reports within 10 lines of a line the fix changed, in the vulnerable release.
- fixed FP: a rule that caught the case still reports at the fix in the fixed release; the rate is over caught cases.
- rule source: a rule cites the id in its refs, so the rule was written from it; independent: no rule cites it.
- in fix files: reports of the case's class anywhere in the fix files of the vulnerable release, near the fix or not.
- findings and time: every report of every rule on the whole release, and the time to scan it.

## Summary

| group | cases | caught | catch rate | fixed FP | fixed FP rate | findings per release (vulnerable / fixed) | scan time per release |
|---|---|---|---|---|---|---|---|
| all | 59 | 7 | 11.9% | 3 | 42.9% | 6.6 / 6.4 | 2.4s |
| rule source | 16 | 2 | 12.5% | 1 | 50.0% | 0.8 / 0.6 | 2.0s |
| independent | 43 | 5 | 11.6% | 2 | 40.0% | 8.8 / 8.6 | 2.5s |
| composer | 10 | 1 | 10.0% | 0 | 0.0% | 0.2 / 0.1 | 1.2s |
| npm | 9 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.7s |
| pypi | 10 | 0 | 0.0% | 0 | - | 0.4 / 0.4 | 1.8s |
| wordpress-plugin | 30 | 6 | 20.0% | 3 | 50.0% | 12.9 / 12.4 | 3.5s |
| cmdi | 3 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.3s |
| code-eval | 7 | 1 | 14.3% | 0 | 0.0% | 0.1 / 0.0 | 1.0s |
| deserialization | 9 | 1 | 11.1% | 0 | 0.0% | 11.0 / 10.4 | 0.9s |
| path-traversal | 20 | 3 | 15.0% | 2 | 66.7% | 4.4 / 4.2 | 3.2s |
| sqli | 20 | 2 | 10.0% | 1 | 50.0% | 10.2 / 10.0 | 3.0s |

## Cases

| case | package | releases | class | group | rule | vulnerable | fixed | in fix files | findings | unfinished files | scan time |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2014-6394 | npm send | 0.8.3 → 0.8.4 | path-traversal | rule source | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2014-6394 | npm send | 0.8.3 → 0.8.4 | path-traversal | rule source | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2016-20018 | npm knex | 2.3.0 → 2.4.0 | sqli | rule source | js-sqli-object-input | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2016-20018 | npm knex | 2.3.0 → 2.4.0 | sqli | rule source | js-sqli-raw-interpolation | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2016-20018 | npm knex | 2.3.0 → 2.4.0 | sqli | rule source | js-sqli-sequelize-literal | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2017-20289 | wordpress-plugin ad-widget | 2.11.0 → 2.12.0 | path-traversal | independent | php-path-traversal-file-include | - | - | 1 | 1 / 1 | 0 / 0 | 0.0s / 0.0s |
| CVE-2017-20289 | wordpress-plugin ad-widget | 2.11.0 → 2.12.0 | path-traversal | independent | php-path-traversal-file-read | - | - | 1 | 1 / 1 | 0 / 0 | 0.0s / 0.0s |
| CVE-2017-20289 | wordpress-plugin ad-widget | 2.11.0 → 2.12.0 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 1 / 1 | 0 / 0 | 0.0s / 0.0s |
| CVE-2017-9841 | composer sebastianbergmann/phpunit | 5.6.2 → 5.6.3 | code-eval | rule source | php-code-eval-eval | caught | - | 1 | 1 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2018-1002204 | npm adm-zip | 0.4.9 → 0.4.11 | path-traversal | rule source | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2018-1002204 | npm adm-zip | 0.4.9 → 0.4.11 | path-traversal | rule source | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2018-15133 | composer laravel/framework | v5.6.29 → v5.6.30 | deserialization | rule source | php-deserialization-phar-wrapper | - | - | 0 | 1 / 1 | 0 / 0 | 0.3s / 0.3s |
| CVE-2018-15133 | composer laravel/framework | v5.6.29 → v5.6.30 | deserialization | rule source | php-deserialization-unserialize | - | - | 0 | 1 / 1 | 0 / 0 | 0.3s / 0.3s |
| CVE-2020-12265 | npm decompress | 4.2.0 → 4.2.1 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2020-12265 | npm decompress | 4.2.0 → 4.2.1 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2020-36326 | composer PHPMailer/PHPMailer | v6.4.0 → v6.4.1 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2020-36326 | composer PHPMailer/PHPMailer | v6.4.0 → v6.4.1 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2021-21315 | npm systeminformation | 5.3.0 → 5.3.1 | cmdi | independent | js-cmdi-exec | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2021-21315 | npm systeminformation | 5.3.0 → 5.3.1 | cmdi | independent | js-cmdi-spawn-shell | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2021-23337 | npm lodash | 4.17.20 → 4.17.21 | code-eval | independent | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 1.1s / 1.1s |
| CVE-2021-23337 | npm lodash | 4.17.20 → 4.17.21 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 1.1s / 1.1s |
| CVE-2021-23344 | npm total.js | 3.4.7 → 3.4.8 | code-eval | rule source | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 3.9s / 4.0s |
| CVE-2021-23344 | npm total.js | 3.4.7 → 3.4.8 | code-eval | rule source | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 3.9s / 4.0s |
| CVE-2021-29454 | composer smarty-php/smarty | v3.1.41 → v3.1.42 | code-eval | independent | php-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2021-29472 | composer composer/composer | 2.0.12 → 2.0.13 | cmdi | independent | php-cmdi-mail-params | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.4s |
| CVE-2021-29472 | composer composer/composer | 2.0.12 → 2.0.13 | cmdi | independent | php-cmdi-shell-exec | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.4s |
| CVE-2021-3129 | composer facade/ignition | 2.5.1 → 2.5.2 | deserialization | rule source | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 0.8s / 0.8s |
| CVE-2021-3129 | composer facade/ignition | 2.5.1 → 2.5.2 | deserialization | rule source | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.8s / 0.8s |
| CVE-2021-35042 | pypi Django | 3.2.4 → 3.2.5 | sqli | independent | python-sqli-dbapi-format | - | - | 0 | 1 / 1 | 0 / 0 | 3.0s / 3.0s |
| CVE-2021-35042 | pypi Django | 3.2.4 → 3.2.5 | sqli | independent | python-sqli-django-kwargs-alias | - | - | 0 | 1 / 1 | 0 / 0 | 3.0s / 3.0s |
| CVE-2021-35042 | pypi Django | 3.2.4 → 3.2.5 | sqli | independent | python-sqli-sqlalchemy-text | - | - | 0 | 1 / 1 | 0 / 0 | 3.0s / 3.0s |
| CVE-2022-22817 | pypi Pillow | 9.0.0 → 9.0.1 | code-eval | independent | python-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 0.7s / 0.7s |
| CVE-2022-22817 | pypi Pillow | 9.0.0 → 9.0.1 | code-eval | independent | python-code-eval-template-injection | - | - | 0 | 0 / 0 | 0 / 0 | 0.7s / 0.7s |
| CVE-2022-24439 | pypi GitPython | 3.1.29 → 3.1.30 | cmdi | independent | python-cmdi-argument-injection | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2022-24439 | pypi GitPython | 3.1.29 → 3.1.30 | cmdi | independent | python-cmdi-shell | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2022-28346 | pypi Django | 4.0.3 → 4.0.4 | sqli | rule source | python-sqli-dbapi-format | - | - | 0 | 1 / 1 | 0 / 0 | 3.1s / 3.2s |
| CVE-2022-28346 | pypi Django | 4.0.3 → 4.0.4 | sqli | rule source | python-sqli-django-kwargs-alias | - | - | 0 | 1 / 1 | 0 / 0 | 3.1s / 3.2s |
| CVE-2022-28346 | pypi Django | 4.0.3 → 4.0.4 | sqli | rule source | python-sqli-sqlalchemy-text | - | - | 0 | 1 / 1 | 0 / 0 | 3.1s / 3.2s |
| CVE-2022-29078 | npm ejs | 3.1.6 → 3.1.7 | code-eval | rule source | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2022-29078 | npm ejs | 3.1.6 → 3.1.7 | code-eval | rule source | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2022-3342 | wordpress-plugin zero-bs-crm | 5.3.1 → 5.4.0 | deserialization | independent | php-deserialization-phar-wrapper | caught | - | 5 | 13 / 8 | 0 / 0 | 2.5s / 2.2s |
| CVE-2022-3342 | wordpress-plugin zero-bs-crm | 5.3.1 → 5.4.0 | deserialization | independent | php-deserialization-unserialize | - | - | 5 | 13 / 8 | 0 / 0 | 2.5s / 2.2s |
| CVE-2022-34265 | pypi Django | 4.0.5 → 4.0.6 | sqli | independent | python-sqli-dbapi-format | - | - | 0 | 1 / 1 | 0 / 0 | 3.2s / 3.7s |
| CVE-2022-34265 | pypi Django | 4.0.5 → 4.0.6 | sqli | independent | python-sqli-django-kwargs-alias | - | - | 0 | 1 / 1 | 0 / 0 | 3.2s / 3.7s |
| CVE-2022-34265 | pypi Django | 4.0.5 → 4.0.6 | sqli | independent | python-sqli-sqlalchemy-text | - | - | 0 | 1 / 1 | 0 / 0 | 3.2s / 3.7s |
| CVE-2022-41343 | composer dompdf/dompdf | v2.0.0 → v2.0.1 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.3s |
| CVE-2022-41343 | composer dompdf/dompdf | v2.0.0 → v2.0.1 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.3s |
| CVE-2023-0297 | pypi pyload-ng | 0.5.0b3.dev30 → 0.5.0b3.dev31 | code-eval | independent | python-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 0.8s / 0.8s |
| CVE-2023-0297 | pypi pyload-ng | 0.5.0b3.dev30 → 0.5.0b3.dev31 | code-eval | independent | python-code-eval-template-injection | - | - | 0 | 0 / 0 | 0 / 0 | 0.8s / 0.8s |
| CVE-2023-25813 | npm sequelize | 6.19.0 → 6.19.1 | sqli | independent | js-sqli-object-input | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.4s |
| CVE-2023-25813 | npm sequelize | 6.19.0 → 6.19.1 | sqli | independent | js-sqli-raw-interpolation | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.4s |
| CVE-2023-25813 | npm sequelize | 6.19.0 → 6.19.1 | sqli | independent | js-sqli-sequelize-literal | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.4s |
| CVE-2023-28115 | composer KnpLabs/snappy | v1.4.1 → v1.4.2 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2023-28115 | composer KnpLabs/snappy | v1.4.1 → v1.4.2 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s |
| CVE-2023-3452 | wordpress-plugin canto | 3.0.4 → 3.0.5 | path-traversal | independent | php-path-traversal-file-include | caught | - | 1 | 11 / 6 | 1 / 1 | 0.1s / 0.1s |
| CVE-2023-3452 | wordpress-plugin canto | 3.0.4 → 3.0.5 | path-traversal | independent | php-path-traversal-file-read | - | - | 1 | 11 / 6 | 1 / 1 | 0.1s / 0.1s |
| CVE-2023-3452 | wordpress-plugin canto | 3.0.4 → 3.0.5 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 11 / 6 | 1 / 1 | 0.1s / 0.1s |
| CVE-2023-6120 | wordpress-plugin usc-e-shop | 2.9.6 → 2.9.7 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 26 / 26 | 0 / 0 | 3.8s / 3.8s |
| CVE-2023-6120 | wordpress-plugin usc-e-shop | 2.9.6 → 2.9.7 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 26 / 26 | 0 / 0 | 3.8s / 3.8s |
| CVE-2023-6120 | wordpress-plugin usc-e-shop | 2.9.6 → 2.9.7 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 26 / 26 | 0 / 0 | 3.8s / 3.8s |
| CVE-2024-12032 | wordpress-plugin tourfic | 2.15.3 → 2.15.4 | sqli | independent | php-sqli-orderby-identifier | - | - | 1 | 40 / 39 | 0 / 0 | 2.9s / 2.9s |
| CVE-2024-12032 | wordpress-plugin tourfic | 2.15.3 → 2.15.4 | sqli | independent | php-sqli-string-concat | - | - | 1 | 40 / 39 | 0 / 0 | 2.9s / 2.9s |
| CVE-2024-12032 | wordpress-plugin tourfic | 2.15.3 → 2.15.4 | sqli | independent | php-sqli-wpdb-unprepared | caught | - | 1 | 40 / 39 | 0 / 0 | 2.9s / 2.9s |
| CVE-2024-12850 | wordpress-plugin database-backup | 2.32 → 2.33 | path-traversal | independent | php-path-traversal-file-include | - | - | 1 | 8 / 8 | 0 / 0 | 0.1s / 0.1s |
| CVE-2024-12850 | wordpress-plugin database-backup | 2.32 → 2.33 | path-traversal | independent | php-path-traversal-file-read | caught | still reports | 1 | 8 / 8 | 0 / 0 | 0.1s / 0.1s |
| CVE-2024-12850 | wordpress-plugin database-backup | 2.32 → 2.33 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 8 / 8 | 0 / 0 | 0.1s / 0.1s |
| CVE-2024-3136 | wordpress-plugin masterstudy-lms-learning-management-system | 3.3.3 → 3.3.4 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 1 / 1 | 3 / 3 | 7.9s / 8.0s |
| CVE-2024-3136 | wordpress-plugin masterstudy-lms-learning-management-system | 3.3.3 → 3.3.4 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 1 / 1 | 3 / 3 | 7.9s / 8.0s |
| CVE-2024-3136 | wordpress-plugin masterstudy-lms-learning-management-system | 3.3.3 → 3.3.4 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 1 / 1 | 3 / 3 | 7.9s / 8.0s |
| CVE-2024-4359 | wordpress-plugin bdthemes-element-pack-lite | 5.7.2 → 5.7.3 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 0 / 0 | 0 / 0 | 1.3s / 1.2s |
| CVE-2024-4359 | wordpress-plugin bdthemes-element-pack-lite | 5.7.2 → 5.7.3 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 0 / 0 | 0 / 0 | 1.3s / 1.2s |
| CVE-2024-4359 | wordpress-plugin bdthemes-element-pack-lite | 5.7.2 → 5.7.3 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 0 / 0 | 0 / 0 | 1.3s / 1.2s |
| CVE-2024-4887 | wordpress-plugin qi-addons-for-elementor | 1.7.2 → 1.7.3 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 0 / 0 | 0 / 0 | 1.5s / 1.5s |
| CVE-2024-4887 | wordpress-plugin qi-addons-for-elementor | 1.7.2 → 1.7.3 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 0 / 0 | 0 / 0 | 1.5s / 1.5s |
| CVE-2024-4887 | wordpress-plugin qi-addons-for-elementor | 1.7.2 → 1.7.3 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 0 / 0 | 0 / 0 | 1.5s / 1.5s |
| CVE-2024-8392 | wordpress-plugin sogrid | 1.5.6 → 1.5.7 | path-traversal | independent | php-path-traversal-file-include | caught | still reports | 1 | 1 / 1 | 0 / 0 | 0.1s / 0.1s |
| CVE-2024-8392 | wordpress-plugin sogrid | 1.5.6 → 1.5.7 | path-traversal | independent | php-path-traversal-file-read | - | - | 1 | 1 / 1 | 0 / 0 | 0.1s / 0.1s |
| CVE-2024-8392 | wordpress-plugin sogrid | 1.5.6 → 1.5.7 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 1 / 1 | 0 / 0 | 0.1s / 0.1s |
| CVE-2025-13145 | wordpress-plugin wp-ultimate-csv-importer | 7.33.1 → 7.34 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 1 | 85 / 85 | 1 / 1 | 1.8s / 1.8s |
| CVE-2025-13145 | wordpress-plugin wp-ultimate-csv-importer | 7.33.1 → 7.34 | deserialization | independent | php-deserialization-unserialize | - | - | 1 | 85 / 85 | 1 / 1 | 1.8s / 1.8s |
| CVE-2025-13641 | wordpress-plugin nextgen-gallery | 3.59.12 → 4.0.0 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 3 / 4 | 1 / 2 | 3.3s / 4.1s |
| CVE-2025-13641 | wordpress-plugin nextgen-gallery | 3.59.12 → 4.0.0 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 3 / 4 | 1 / 2 | 3.3s / 4.1s |
| CVE-2025-13641 | wordpress-plugin nextgen-gallery | 3.59.12 → 4.0.0 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 3 / 4 | 1 / 2 | 3.3s / 4.1s |
| CVE-2025-14071 | wordpress-plugin live-composer-page-builder | 2.0.2 → 2.0.3 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 2.0s / 2.0s |
| CVE-2025-14071 | wordpress-plugin live-composer-page-builder | 2.0.2 → 2.0.3 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 2.0s / 2.0s |
| CVE-2025-14383 | wordpress-plugin booking | 10.14.8 → 10.14.9 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 8 / 8 | 0 / 0 | 2.4s / 2.6s |
| CVE-2025-14383 | wordpress-plugin booking | 10.14.8 → 10.14.9 | sqli | independent | php-sqli-string-concat | - | - | 0 | 8 / 8 | 0 / 0 | 2.4s / 2.6s |
| CVE-2025-14383 | wordpress-plugin booking | 10.14.8 → 10.14.9 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 8 / 8 | 0 / 0 | 2.4s / 2.6s |
| CVE-2025-54140 | pypi pyload-ng | 0.5.0b3.dev89 → 0.5.0b3.dev90 | path-traversal | independent | python-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.9s / 0.9s |
| CVE-2025-54140 | pypi pyload-ng | 0.5.0b3.dev89 → 0.5.0b3.dev90 | path-traversal | independent | python-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.9s / 0.9s |
| CVE-2025-59681 | pypi Django | 5.2.6 → 5.2.7 | sqli | rule source | python-sqli-dbapi-format | - | - | 0 | 1 / 1 | 0 / 0 | 5.3s / 5.2s |
| CVE-2025-59681 | pypi Django | 5.2.6 → 5.2.7 | sqli | rule source | python-sqli-django-kwargs-alias | - | - | 0 | 1 / 1 | 0 / 0 | 5.3s / 5.2s |
| CVE-2025-59681 | pypi Django | 5.2.6 → 5.2.7 | sqli | rule source | python-sqli-sqlalchemy-text | - | - | 0 | 1 / 1 | 0 / 0 | 5.3s / 5.2s |
| CVE-2025-7036 | wordpress-plugin cleverreach-wp | 1.5.20 → 1.5.21 | sqli | rule source | php-sqli-orderby-identifier | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2025-7036 | wordpress-plugin cleverreach-wp | 1.5.20 → 1.5.21 | sqli | rule source | php-sqli-string-concat | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2025-7036 | wordpress-plugin cleverreach-wp | 1.5.20 → 1.5.21 | sqli | rule source | php-sqli-wpdb-unprepared | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s |
| CVE-2025-9462 | wordpress-plugin wp2leads | 3.5.6 → 3.5.12 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 57 / 57 | 0 / 0 | 2.5s / 2.5s |
| CVE-2025-9462 | wordpress-plugin wp2leads | 3.5.6 → 3.5.12 | sqli | independent | php-sqli-string-concat | - | - | 0 | 57 / 57 | 0 / 0 | 2.5s / 2.5s |
| CVE-2025-9462 | wordpress-plugin wp2leads | 3.5.6 → 3.5.12 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 57 / 57 | 0 / 0 | 2.5s / 2.5s |
| CVE-2026-101325 | wordpress-plugin newsletters-lite | 4.18.1 → 4.18.2 | sqli | independent | php-sqli-orderby-identifier | - | - | 24 | 52 / 52 | 1 / 1 | 7.5s / 6.9s |
| CVE-2026-101325 | wordpress-plugin newsletters-lite | 4.18.1 → 4.18.2 | sqli | independent | php-sqli-string-concat | - | - | 24 | 52 / 52 | 1 / 1 | 7.5s / 6.9s |
| CVE-2026-101325 | wordpress-plugin newsletters-lite | 4.18.1 → 4.18.2 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 24 | 52 / 52 | 1 / 1 | 7.5s / 6.9s |
| CVE-2026-103914 | wordpress-plugin anywhere-elementor | 1.3.0 → 1.3.1 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 0 / 0 | 0 / 1 | 0.7s / 2.7s |
| CVE-2026-103914 | wordpress-plugin anywhere-elementor | 1.3.0 → 1.3.1 | sqli | independent | php-sqli-string-concat | - | - | 0 | 0 / 0 | 0 / 1 | 0.7s / 2.7s |
| CVE-2026-103914 | wordpress-plugin anywhere-elementor | 1.3.0 → 1.3.1 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 0 / 0 | 0 / 1 | 0.7s / 2.7s |
| CVE-2026-104746 | wordpress-plugin motors-car-dealership-classified-listings | 1.4.125 → 1.4.126 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 5 / 5 | 3 / 3 | 13.8s / 15.8s |
| CVE-2026-104746 | wordpress-plugin motors-car-dealership-classified-listings | 1.4.125 → 1.4.126 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 5 / 5 | 3 / 3 | 13.8s / 15.8s |
| CVE-2026-104746 | wordpress-plugin motors-car-dealership-classified-listings | 1.4.125 → 1.4.126 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 5 / 5 | 3 / 3 | 13.8s / 15.8s |
| CVE-2026-104899 | wordpress-plugin geodirectory | 2.8.187 → 2.8.188 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 11 / 11 | 0 / 0 | 4.1s / 4.0s |
| CVE-2026-104899 | wordpress-plugin geodirectory | 2.8.187 → 2.8.188 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 11 / 11 | 0 / 0 | 4.1s / 4.0s |
| CVE-2026-104899 | wordpress-plugin geodirectory | 2.8.187 → 2.8.188 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 11 / 11 | 0 / 0 | 4.1s / 4.0s |
| CVE-2026-110284 | wordpress-plugin lifterlms | 10.3.1 → 10.3.2 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 1 / 1 | 0 / 0 | 2.5s / 2.9s |
| CVE-2026-110284 | wordpress-plugin lifterlms | 10.3.1 → 10.3.2 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 1 / 1 | 0 / 0 | 2.5s / 2.9s |
| CVE-2026-110284 | wordpress-plugin lifterlms | 10.3.1 → 10.3.2 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 1 / 1 | 0 / 0 | 2.5s / 2.9s |
| CVE-2026-114630 | wordpress-plugin elex-helpdesk-customer-support-ticket-system | 3.3.8 → 3.3.9 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 0 / 0 | 0 / 0 | 4.2s / 4.4s |
| CVE-2026-114630 | wordpress-plugin elex-helpdesk-customer-support-ticket-system | 3.3.8 → 3.3.9 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 0 / 0 | 0 / 0 | 4.2s / 4.4s |
| CVE-2026-114630 | wordpress-plugin elex-helpdesk-customer-support-ticket-system | 3.3.8 → 3.3.9 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 0 / 0 | 0 / 0 | 4.2s / 4.4s |
| CVE-2026-118192 | wordpress-plugin joomsport-sports-league-results-management | 5.7.11 → 5.7.14 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 7 / 7 | 0 / 0 | 1.3s / 1.3s |
| CVE-2026-118192 | wordpress-plugin joomsport-sports-league-results-management | 5.7.11 → 5.7.14 | sqli | independent | php-sqli-string-concat | - | - | 0 | 7 / 7 | 0 / 0 | 1.3s / 1.3s |
| CVE-2026-118192 | wordpress-plugin joomsport-sports-league-results-management | 5.7.11 → 5.7.14 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 7 / 7 | 0 / 0 | 1.3s / 1.3s |
| CVE-2026-118698 | wordpress-plugin joomsport-sports-league-results-management | 5.7.14 → 5.7.15 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 7 / 7 | 0 / 0 | 1.3s / 1.3s |
| CVE-2026-118698 | wordpress-plugin joomsport-sports-league-results-management | 5.7.14 → 5.7.15 | sqli | independent | php-sqli-string-concat | - | - | 0 | 7 / 7 | 0 / 0 | 1.3s / 1.3s |
| CVE-2026-118698 | wordpress-plugin joomsport-sports-league-results-management | 5.7.14 → 5.7.15 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 7 / 7 | 0 / 0 | 1.3s / 1.3s |
| CVE-2026-119163 | wordpress-plugin wp-marketing-automations | 3.8.5.2 → 3.8.6 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 1 / 0 | 2 / 2 | 7.3s / 7.1s |
| CVE-2026-119163 | wordpress-plugin wp-marketing-automations | 3.8.5.2 → 3.8.6 | sqli | independent | php-sqli-string-concat | - | - | 0 | 1 / 0 | 2 / 2 | 7.3s / 7.1s |
| CVE-2026-119163 | wordpress-plugin wp-marketing-automations | 3.8.5.2 → 3.8.6 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 1 / 0 | 2 / 2 | 7.3s / 7.1s |
| CVE-2026-120043 | wordpress-plugin slicewp | 1.2.14 → 1.2.15 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 0 / 0 | 0 / 0 | 1.8s / 1.8s |
| CVE-2026-120043 | wordpress-plugin slicewp | 1.2.14 → 1.2.15 | sqli | independent | php-sqli-string-concat | - | - | 0 | 0 / 0 | 0 / 0 | 1.8s / 1.8s |
| CVE-2026-120043 | wordpress-plugin slicewp | 1.2.14 → 1.2.15 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 0 / 0 | 0 / 0 | 1.8s / 1.8s |
| CVE-2026-120530 | wordpress-plugin wp-migration-duplicator | 1.6.1 → 1.6.2 | sqli | independent | php-sqli-orderby-identifier | - | - | 0 | 20 / 20 | 0 / 0 | 0.4s / 0.3s |
| CVE-2026-120530 | wordpress-plugin wp-migration-duplicator | 1.6.1 → 1.6.2 | sqli | independent | php-sqli-string-concat | - | - | 0 | 20 / 20 | 0 / 0 | 0.4s / 0.3s |
| CVE-2026-120530 | wordpress-plugin wp-migration-duplicator | 1.6.1 → 1.6.2 | sqli | independent | php-sqli-wpdb-unprepared | - | - | 0 | 20 / 20 | 0 / 0 | 0.4s / 0.3s |
| CVE-2026-122265 | wordpress-plugin vanquish-upload-files-for-woocommerce | 2.7.13 → 2.8.0 | path-traversal | independent | php-path-traversal-file-include | - | - | 2 | 19 / 19 | 0 / 0 | 0.7s / 0.7s |
| CVE-2026-122265 | wordpress-plugin vanquish-upload-files-for-woocommerce | 2.7.13 → 2.8.0 | path-traversal | independent | php-path-traversal-file-read | - | - | 2 | 19 / 19 | 0 / 0 | 0.7s / 0.7s |
| CVE-2026-122265 | wordpress-plugin vanquish-upload-files-for-woocommerce | 2.7.13 → 2.8.0 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 2 | 19 / 19 | 0 / 0 | 0.7s / 0.7s |
| CVE-2026-13357 | wordpress-plugin houzez-property-feed | 2.5.46 → 2.5.47 | sqli | rule source | php-sqli-orderby-identifier | caught | - | 6 | 8 / 6 | 0 / 0 | 6.6s / 7.8s |
| CVE-2026-13357 | wordpress-plugin houzez-property-feed | 2.5.46 → 2.5.47 | sqli | rule source | php-sqli-string-concat | - | - | 6 | 8 / 6 | 0 / 0 | 6.6s / 7.8s |
| CVE-2026-13357 | wordpress-plugin houzez-property-feed | 2.5.46 → 2.5.47 | sqli | rule source | php-sqli-wpdb-unprepared | caught | still reports | 6 | 8 / 6 | 0 / 0 | 6.6s / 7.8s |
| CVE-2026-24009 | pypi docling-core | 2.48.3 → 2.48.4 | deserialization | rule source | python-deserialization-pickle | - | - | 0 | 0 / 0 | 0 / 0 | 0.7s / 0.8s |
| CVE-2026-24009 | pypi docling-core | 2.48.3 → 2.48.4 | deserialization | rule source | python-deserialization-yaml-load | - | - | 0 | 0 / 0 | 0 / 0 | 0.7s / 0.8s |
| CVE-2026-26198 | pypi ormar | 0.22.0 → 0.23.0 | sqli | rule source | python-sqli-dbapi-format | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2026-26198 | pypi ormar | 0.22.0 → 0.23.0 | sqli | rule source | python-sqli-django-kwargs-alias | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2026-26198 | pypi ormar | 0.22.0 → 0.23.0 | sqli | rule source | python-sqli-sqlalchemy-text | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2026-41228 | composer froxlor/froxlor | 2.3.5 → 2.3.6 | path-traversal | rule source | php-path-traversal-file-include | - | - | 0 | 0 / 0 | 0 / 0 | 1.6s / 1.6s |
| CVE-2026-41228 | composer froxlor/froxlor | 2.3.5 → 2.3.6 | path-traversal | rule source | php-path-traversal-file-read | - | - | 0 | 0 / 0 | 0 / 0 | 1.6s / 1.6s |
| CVE-2026-41228 | composer froxlor/froxlor | 2.3.5 → 2.3.6 | path-traversal | rule source | php-path-traversal-laravel-storage | - | - | 0 | 0 / 0 | 0 / 0 | 1.6s / 1.6s |
| CVE-2026-56738 | composer thorsten/phpMyFAQ | 4.1.5 → 4.1.6 | sqli | rule source | php-sqli-orderby-identifier | - | - | 0 | 0 / 0 | 0 / 0 | 7.7s / 7.9s |
| CVE-2026-56738 | composer thorsten/phpMyFAQ | 4.1.5 → 4.1.6 | sqli | rule source | php-sqli-string-concat | - | - | 0 | 0 / 0 | 0 / 0 | 7.7s / 7.9s |
| CVE-2026-56738 | composer thorsten/phpMyFAQ | 4.1.5 → 4.1.6 | sqli | rule source | php-sqli-wpdb-unprepared | - | - | 0 | 0 / 0 | 0 / 0 | 7.7s / 7.9s |
| CVE-2026-9231 | wordpress-plugin wp-travel-engine | 6.8.0 → 6.8.1 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 1 / 1 | 6 / 5 | 19.2s / 14.6s |
| CVE-2026-9231 | wordpress-plugin wp-travel-engine | 6.8.0 → 6.8.1 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 1 / 1 | 6 / 5 | 19.2s / 14.6s |
| CVE-2026-9231 | wordpress-plugin wp-travel-engine | 6.8.0 → 6.8.1 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 1 / 1 | 6 / 5 | 19.2s / 14.6s |
