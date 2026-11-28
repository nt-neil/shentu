# Changelog

Each release has one section: `## vX.Y.Z — YYYY-MM-DD` (or `## vX.Y.Z (unreleased)`).
The website (`go generate ./cmd/sitegen`) reads this file. The rules added or removed in
a release are not written here: they are worked out from the rule snapshots in
`docs/site-src/rules-history/`. `CHANGELOG.zh-TW.md` holds the same releases in Traditional
Chinese for the zh-TW pages; keep the two in step.

## v0.5.8 (unreleased)

- A new rule tier, `reference`, for a rule about how a call is made rather than about input reaching
  it (only a rule with `sources = []` may have it). app_code_audit and chat list its findings after
  the others, marked as reference; the daily report gives them one line with their count. They are
  never pushed and never given to attack detection. The `info` and `alert` tiers are unchanged.
- A Debian or Ubuntu package held with `apt-mark hold` (dpkg state `hi`), or marked for removal but
  still installed (`ri`, `pi`), is checked as an installed one is. The package list went by dpkg's
  `ii` only, so a held package was neither checked nor said (the v0.5.7 known issue). A package dpkg
  has on the disk but not installed in full marks the package list partial, named there with its
  state (20 at most, the rest counted). One whose files are all unpacked (unpacked, half-configured,
  triggers awaited, triggers pending) is checked at the version dpkg records. One half-installed, or
  in a state not read, is not checked: it is listed in `packages_not_checked` with its state, before
  the ones with only their configuration left (config-files), which are listed only. The first 20
  are listed, the rest counted in `packages_not_checked_more`. The tool's description says both
  fields.
- block_ip reads the server's DNS servers and default gateways (`/etc/resolv.conf`, systemd-resolved's
  copy, `/proc/net/route`, `/proc/net/ipv6_route`) through the host source, as the SSH sessions it
  also checks: a replay or another host's survey is never answered by the machine running it. One of
  them there but not read now refuses the block (`state_error`); before, the error was dropped and the
  list taken for empty, so the gateway or DNS server could be blocked. A file absent (no
  systemd-resolved, no IPv6) is still no entry.
- app_code_audit, app_vulns (lock files and site-packages) and the WordPress plugin list walk the
  host source, as the web roots they start from already came from it: a replay or another host's
  survey is never answered by the machine running the check. Links are still not followed, a file
  is read only if it is the one the walk saw, and the limits are the same. A web root or app path
  there but not read (no permission, or a replay that lacks it) is now listed in the audit's
  `not_checked`; before, it was audited as an empty folder. A replay of a fixture recorded before
  this version says every such path not read, never "not there".
- package_vulns reads every page of OSV's answer: OSV gives at most 1000 advisories a query and
  names the next page; only the first was read, so the kernel's list stopped at 1000 (on Ubuntu
  24.04, 383 CVEs fewer than another scanner found). Past 10 pages a package's rest is said in
  `partial`, never cut quietly.
- package_vulns on Ubuntu: a USN covers every release it fixed, and its aliases name CVEs some other
  release has only (USN-7980-1 names CVE-2025-11187, which OSV has for 25.10 and 26.04, not 24.04).
  Of a USN only the CVEs OSV also lists for that package on the host's release count now, so a CVE
  of another release is no longer marked actively exploited (KEV) on this host, nor counted on the
  surface, nor taken for a CVE OSV already reports when a third-party PHP or nginx is compared with
  upstream. A USN whose package has no CVE-named advisory to tell its CVEs' release by is counted in
  `kev_unchecked` and named, never dropped quietly.
- Windows: Shentu's own files opened without following a link (the dispatch log, the AI budget
  reservations, the auto-incident and audit locks) are checked and used through one handle, opened
  not following a symlink or junction. Before, the file was looked at, then opened by its name, and
  the two compared in a way that cannot tell on Windows: a file swapped for a link in between was
  opened through the link. A deduplicated file (Windows Server Data Deduplication) is still opened;
  another kind of reparse point is said, not opened.
- Windows: site_profile, the processes, listening ports, accounts and SSH tools, log_search and the
  Python site-packages check go by the host read (Windows or not), as the macOS ones do, not by the
  machine running the check. Replaying a Windows host's reads, or checking one from another machine,
  no longer gives the Linux answer, and site-packages matches a Windows venv's `RECORD` paths (without
  case, as Windows names files, and with an old pip's `\`): a genuine `.pth` a package's `RECORD`
  lists is no longer reported as unknown. On a Windows host where Apache shows (an `httpd.exe` process
  or service, `C:\Apache24\conf\httpd.conf` or `C:\xampp\apache`), site_profile's `risks` list one
  more unchecked risk, `unchecked:notyet:apache:windows`: Apache there is not checked yet, so
  CVE-2026-119618 (HTTP/2) is not evaluated. The daily report lists it under "Not checked by this
  release yet", not under the missing-permission heading.
- `app_vulns` and the daily patrol check the Python packages in Docker images against OSV as PyPI,
  with the CISA KEV mark. They are read from Docker's overlay2 image store on disk; no container is
  started and the daemon is not asked. Each tagged image's layers are stacked as overlayfs stacks
  them: a higher layer's file replaces a lower one's, a deleted file (a whiteout) removes only that
  name in its own folder, and an opaque folder hides the lower layers' files in it. Until now a
  package inside an image was not checked at all. A store that is there but could not be read
  (not root, a file not read, past the bounds of 50 images, 200 layers or 200,000 files) is
  reported as not checked, each such line of the daily report on its own; a host with no Docker
  store says so apart. The store's folders are not followed when they are symlinks, and when the
  run is stopped the images left are said not checked. Images in containerd's store (new
  Docker releases keep them there by default: `/var/lib/containerd`, or `containerd-snapshotter`
  turned on in `daemon.json`) are not read by this release: `partial` says so rather than "no
  images", and the daily report lists it under what this release does not check yet. The store is
  read only when the host read is this machine itself: a replay says the images were not checked.
  A `.pth` in an image is never taken as a tool's own.
- package_vulns' overview tells how many of the vulnerabilities a fix is known to be out for
  (`fix_available`, also per package) and how many it is not known for (`fix_unconfirmed`). A
  fix is known when the advisory is a distribution's update notice (DSA, DLA, USN, RLSA, ALSA,
  SUSE-SU) or an ALAS. A php.net or nginx.org entry is counted in `fix_available` too: the fixed
  release is out upstream, though the repository the package came from (sury, for one) may not have
  packaged it yet. The rest, such as
  a CVE entry of Debian's or Ubuntu's tracker, are unconfirmed: the overview does not fetch each
  advisory to tell, and `fix_note` says that unconfirmed is not "no fix". Until now the count
  mixed them; `package` set still gives each one's `fixed_version`, without the counts.
- site_profile on Linux and macOS says two more risks. `sudo:nopasswd` (a warning): sudoers lets
  someone run every command with no password: `ALL` anywhere among the commands a NOPASSWD tag
  covers (it holds up to a PASSWD tag), a command alias that is ALL or cannot be told, a command
  whose path is a folder or holds a wildcard (`/usr/bin/`, `/usr/bin/*`: sh among them; a
  wildcard in the arguments only is not), a command masked as a secret would be, or
  `Defaults !authenticate` for everyone, a user or a run-as account; in any sudoers file, for a
  group or ALL. The one exception is the cloud image's default user: such a rule in
  `/etc/sudoers.d/90-cloud-init-users` (that path only) for cloud-init's `default_user` (read from
  `/etc/cloud/cloud.cfg` and `cloud.cfg.d/*.cfg`, not user-data; one set in a way not read, such as
  `{name: x}`, a quoted key or JSON, is none) alone is `sudo:nopasswd:cloud-init`
  (info, in the report only), whose text says it is safe only while that user logs in with a key
  alone. NOPASSWD for some commands only, or `Defaults!cmd !authenticate` for some, is
  `sudo:nopasswd:some` (info). Each rule is listed with what it runs and the account it runs as.
  The rules are read through every `#include`/`@include` and `includedir` as sudo reads them (names
  with a dot or ending in `~` skipped). A file not read, or sudoers from sss or ldap, is said as
  `unchecked:sudoers`, never taken for no such rule. A recording keeps sudo's tags only in sudoers
  files (`/etc/sudoers`, `/etc/sudoers.d/*` and what they include), in their rule lines, where the
  word after the tag is a command (`ALL=NOPASSWD: /path`, `(root) NOPASSWD: DEPLOY`, `sudoedit`, an
  option), so a replay reads these rules as written; everywhere else the secret masking is as
  before, and now also masks the value in `(x) PASSWD: !<password>` and `FOO: PASSWD: ALL-<password>`. `reboot:pending` (a warning): an update waits
  for a reboot, its old kernel or libraries still running. On Debian and Ubuntu it is
  `/run/reboot-required` (with the packages it names); elsewhere a kernel in `/boot` newer than the
  running one of the same flavor (`+debug`, UEK and the distribution's own kernel compared apart).
  A running kernel not in `/boot` (a container) is not compared.
- file_changes and log_search's hard-link check read the host as the other checks do, through the
  host source: a replay or another host's survey reads that host's files, not the machine running
  the check, a Linux or macOS host's recording read on a Windows machine too (its paths keep their
  "/": the walks, the log allowlist, the site-packages search, the WordPress plugin search,
  app_vulns' and app_code_audit's path argument, and the audit resuming where it stopped spell them
  as the host does). The host source's file details now carry the status-change time (ctime, which
  file_changes counts as before: a file whose mtime was set back still shows) and the hard links;
  these checks are made on Unix only (on Windows the details say they do not apply, never 0).
- A file app_code_audit, app_vulns' lock-file search or the WordPress plugin search would read that
  is not a regular file (a FIFO, a device, a cloud or HSM placeholder such as a OneDrive file not
  on the disk) is said rather than skipped quietly: the audit's `not_checked` and app_vulns'
  `partial` count them and name the first three; a plugin's `.php` file of that kind is named among
  what was not read when no header was found. A link is not followed, as before, and not counted.
- A refused connection to a model outside this host is said "connection refused" on Windows too;
  it was said "connection failed" there (Windows gives WSAECONNREFUSED).
- sudo's risk texts say each rule by its file, whom it is for, what it runs and as whom
  (`/etc/sudoers.d/90-admins: %admin (every command, as root)`), not by its line: a pushed text
  is no longer masked to `[REDACTED]`. A secret in a command's arguments or a run-as list,
  written as `key=value` or in one of the forms below, is masked in the text itself, so the
  survey's own output (onboard, the saved profile) does not hold it either.
- The secret masking (fixtures, logs, what the model is given, Windows checks' command lines)
  now also masks a password given as a command's own argument: `-p<secret>` after a program of
  the mysql family (`mysql`, `mysqldump`, `mysqlcheck`, `mysqladmin`, `mysqlbinlog` and the
  others, `mariadb` and its tools, in any case, `.exe` too), `--password <secret>` or
  `--passwd <secret>` as the next argument, and curl's or wget's `-u user:<secret>` /
  `--user user:<secret>`; also in a JSON argv on one line (`["mysqladmin","ping","-p<secret>"]`,
  `"--password", "<secret>"`, `"-u", "user:<secret>"`, as docker inspect and a healthcheck write
  them). `key=value` was masked before. A process's command line (`/proc`, `ps`, Windows') is
  masked argument by argument, so a `;`, `|` or `&` in a password is masked with it; in other text
  (a log line, a shell's history) a command reaches only to an unquoted `;`, `|` or `&`, so a git
  refspec (`git push -u main:main`) or `tar -pcf` after it is left. `-P 3306`, `docker run -p
  8080:80`, the `mysqld` and `mariadbd` daemons' `-port=`, `--password-file=/path` and a bare `-p`
  are left as they are.
- The host survey parses commands' output as written, not masked first (packages and rpm vendors,
  the firewall's rules, macOS's platform, accounts, processes, listeners, pf and protections,
  nginx's and PHP's package queries): an unclosed private key marker in one process's path, or in
  an iptables rule's comment, no longer hides the processes or rules after it. What is kept from
  the output is parsed fields; a command's error text in a message is masked.
- The cryptominer check matches a process's command line as written (Linux, macOS, Windows): a
  renamed miner whose options follow a password the mask takes whole (`mysql -p' -o stratum+tcp://…
  '`) is still found. Its evidence, and what the model is given, stay masked.
- The site's home page: a section that rises into view (the tally, open source, the latest release
  with the river) no longer stays blank when the page is reached in its middle, as from a link to
  an anchor, by going back to the page, or by a jump. A section shows once any part of it is in the
  window; sections in the window when the page loads, and every section on a page opened at an
  anchor, show at once.
- PHP rules follow `extract()` of an array not written out. After `extract($args)`,
  `extract($_POST)` or `extract(wp_parse_args($atts, [...]))` (which keeps every key of `$atts`),
  each variable of the function may hold that input until it is assigned again: one defined before
  (a template loader's `$template_name`, overwritten by `extract($args)`) and one never assigned
  (`$team_id` after `extract($opts)`). Before, no variable was set, so a shortcode's attributes
  passed this way reached `include` or `call_user_func()` unreported (CVE-2023-6996).
  `extract(shortcode_atts($defaults, $atts))` sets the keys of `$defaults` only, and never
  `$defaults` itself; `EXTR_SKIP` and the `EXTR_PREFIX_*` flags overwrite nothing; a property of a
  value `extract()` set (`$wpdb->prefix` after `global $wpdb`) holds no input, an index of it does.
  The flags count as PHP reads them: `EXTR_SKIP` and `EXTR_PREFIX_SAME` overwrite nothing,
  `EXTR_IF_EXISTS` overwrites but creates nothing, `EXTR_PREFIX_ALL` and `EXTR_PREFIX_IF_EXISTS` set
  only `prefix_` names (any such name when the prefix is not written out). A variable `extract()`
  creates around a closure is seen in it only through its `use (...)`, and its parameters are the
  caller's values.
- PHP rules: after `preg_match($p, $s, $m)`, `preg_match_all()`, `parse_str($q, $out)` or
  `exec($c, $output)`, the variable written by reference is the call's, so a value `extract()` set
  there before is gone; whether it holds the subject's input is still not followed, but a variable
  that is the subject itself (`preg_match($p, $m, $m)`, `parse_str($q, $q)`) keeps what it held.
  A `catch (E $e)` variable is the exception, not what the name held before.
- PHP rules: WordPress's `$wpdb` kept in a property (`$this->wpdb = $wpdb`, `$this->db = &$wpdb`,
  `self::$mysqli =& $wpdb`) is `$wpdb` wherever the same file queries through it
  (`$this->wpdb->get_results(...)`), so request input concatenated into such a query is reported;
  before, only `$wpdb` itself was a sink. The class (or a trait of the file it uses) must show the
  assignment: a property named `wpdb` or `db` alone, one set in another file (a parent class), or
  one another class of the file gives `$wpdb` is not read as `$wpdb`.
- PHP rules: request input passed to `$wpdb->prepare()` for a `%s` placeholder written inside
  backticks, where the value is a column or table name (also a numbered `%2$s`), is reported
  (`php-sqli-prepare-identifier`): `prepare()` quotes the value as a string, which does not protect
  an identifier. Before, `prepare()` counted as escaping every value. A `%s` between quotes, standing
  alone, after `ORDER BY` or in `LIMIT`, `%d` and `%i` are not reported.
- PHP rules: input put in `array(...)` and passed to another function keeps its input, as `[...]`
  did (`edit_status(array($_REQUEST['id']))`); before, `array(...)` read as a call the engine does
  not know, so the input did not cross into that function's sinks.
- Python rules: Tornado request arguments (`self.get_argument()`, `self.get_query_argument()`,
  `self.get_body_argument()`) passed to `self.redirect()` are reported; before, neither the arguments
  nor `self.redirect()` were read by the redirect rule.
- PHP rules: PSR-7 request input (`$request->getQueryParams()`, `->getParsedBody()`) passed to a
  redirect response (`new RedirectResponse($url)`) is reported.
- PHP rules: a Symfony request's body (`$request->getContent()`, `$request->toArray()`) written into
  SQL in the same function is reported, an ORDER BY column too.
- PHP rules: a cell read with `fgetcsv()`, as from an imported CSV file, and passed to `unserialize()`
  without `['allowed_classes' => false]` is reported.
- A new JavaScript rule, `js-file-upload-client-name-write`: an upload written with
  `fs.createWriteStream()`, `fs.writeFile()`, `fs.writeFileSync()` or `fs.promises.writeFile()` under
  the name the client sent (multer's `file.originalname`) is reported. express-fileupload's `.name` is
  not read.
- Route models can name the hook a call registers (`hooks`): the call counts only when its first
  argument is one of those names, written out as one string; a variable, a constant or a joined
  string there does not count. `path` and `hooks` cannot be used together.
- PHP rules: the editor data Elementor passes to `elementor/editor/after_save` callbacks (the second
  parameter, every element's settings, which contributors and up write) is request input. Before,
  a URL read from a widget's settings there and fetched (`getimagesize()`) was not reported.
- cvebench scans as app_code_audit does by default (`-scanpath product`): each file on its own,
  then the calls across files, merged. Before, it decided each flow with the calls across files
  (`Project.Scan`, now `-scanpath project`), so a check written in another file took a finding away
  that app_code_audit still shows. The rules are the same; the bench's fixed false positives
  usually rise, closer to what a user sees (measured on v0.5.8's cases: nothing reported
  fewer). The report's header names the scan path and the project caps.
- bench: the baselines are rerun on the product scan path (`baseline.md` for cves, and now
  `baseline-holdout.md`, `baseline-cves-ts.md`); the one before was the first run, on 59 cases,
  scanned file by file.

### Known issues

- A command's own password is not masked when it is only JSON punctuation (`, : { } [ ]` and
  spaces), past a space in it (a command line joins argv with spaces; quoted in a shell line it is
  masked whole), past an unquoted `;`, `|` or `&` in a log line or a shell's
  history, in a JSON argv printed over several lines or after a string holding `]`, or given to
  another program's option (`sshpass -p`, `redis-cli -a`, `ldapsearch -w`,
  `smbclient -U user%<secret>`, `mongosh -p`, `htpasswd -b`, curl's `--pass` and
  `-E cert:<secret>`).
- Some checks still read texts masked when read in: PHP error logs and journald's messages (L3),
  and on Windows scheduled tasks, services' paths, registry values and event data.
- In text (a log line, a shell's history, a cron line), a user's name of `mysql` given to an option
  (`--user mysql -p5432`, `psql -U mysql -p5432`) is read as the program, and the `-p` after it is
  masked; a process's command line, judged argument by argument, is not.
- log_search matches the masked text: what the mask covers cannot be found. A pattern matched
  against the text as written would tell, match by match, what a masked secret is.
- A recording (a fixture) holds the masked text only, so a check replayed from it can decide
  otherwise than on the live host: the cryptominer check, on options the mask covered, and attack
  detection, which can have less error-log evidence (an error log or journald message whose
  location the mask covered).
- A redirect target checked in another file (a Tornado base class's `self.sanitize_next_url()`) is
  still reported: app_code_audit reads each file on its own first, and that finding stays when the
  calls across files show the check.
- `js-file-upload-client-name-write` reads no allowlist as a check: an upload written under the
  client's name after its extension or MIME type was checked against a list (express-cart 1.1.7) is
  still reported.
- Input handed to a route generator that builds a path on the site is still reported in a redirect
  (PSR-7's `urlFor()`, Flarum's `$url->to(...)->route()`, Tornado's `reverse_url()`).
- `fgetcsv()`: a row assigned in a `while` condition (`while (($row = fgetcsv($h)) !== false)`) is not
  followed into the loop, so that usual way of reading a CSV file is missed. A CSV file the
  application ships itself is reported as well.
- A value escaped with a database library's `->escape()` and written inside quotes is still reported
  (`php-sqli-string-concat`): the rule does not read `->escape(` as a check, as some libraries'
  escape adds no quotes and a numeric position is left open. A Symfony body now reaches it too.
- A Symfony body decoded with `json_decode()` and passed to another function loses its input there,
  so a field decoded in a controller and written into SQL in another class is missed.
- After `extract()` of input, a property of a variable it set (`$cfg->path`) reads as no input:
  `extract()` of request data sets strings and arrays. `extract((array) json_decode($in))` and
  `extract(get_object_vars(json_decode($in)))` can set objects whose properties are input, and these
  are missed.
- A `reference` rule misreads a few forms. A command written out in full is still reported when it
  is split into adjacent string literals (`os.system('ls ' '-l')`, which Python joins into one) or
  joined from a list of literals (`' '.join(['ls', '-l'])`). An attribute receiver
  (`h.env.from_string(s)`) is known by its name only, even where the file assigns it
  (`h.env = Engine()`). `o.system(cmd)` after `import os as o`, and a function imported under
  another name (`m(x)` after `from hashlib import md5 as m`), are not reported.
- On a non-Windows machine replaying a Windows host's recording, the code audit's ASP check, its
  web-root ACL check and its case-insensitive path comparison are not turned on yet, and
  app_vulns' and app_code_audit's path argument is refused unless it is one of the app paths
  exactly (v0.5.9).
- A route model reads a handler only in the file that registers it: an
  `elementor/editor/after_save` callback written in another file than its `add_action()` (the hook in
  the main plugin file, the function in an include) is not read as one, so a fetch there is not
  reported. The other route models share the limit.

## v0.5.7 — 2026-11-26

- PHP rules read `filter_input()`. A value from `filter_input(INPUT_GET, ...)`, `INPUT_POST` or
  `INPUT_COOKIE`, and from an application's own method of that name (`->filterInput(`,
  `->filter_input(`) when its first argument is one of these constants, is request input in each
  PHP rule that reads `$_GET`, `$_POST` or `$_COOKIE`. A first argument that is a variable or
  another constant (such as `INPUT_SERVER`) is not. A number or bool filter (`FILTER_VALIDATE_INT`,
  `FILTER_VALIDATE_BOOL`, `FILTER_SANITIZE_NUMBER_INT` and others, also as a named `filter:`
  argument) gives a value with no input in it, but not with flags or-ed into it
  (`FILTER_VALIDATE_INT | FILTER_NULL_ON_FAILURE` is another filter ID, which PHP 7 reads as
  `FILTER_DEFAULT`); `FILTER_SANITIZE_SPECIAL_CHARS` cleans in the rules that take
  `htmlspecialchars()` as a sanitizer; a URL filter does not clean.
- macOS: a listening socket netstat gives with pid 0 has no owner to name, so the list of listening
  ports is marked partial and says how many, no longer complete as if every owner were known.
- PHP rules know an application's own guard function. A function that returns true only after
  a check of its path parameter (an allowlist, as Welcart's `usces_is_reserved_file()`, or
  `realpath($p)` with `strpos($real, $base) === 0`) cleans the value it was given where its result
  is true (`if (guard($f)) { ... }`, or after `if (!guard($f)) { die(); }`), also as a method of
  another class. A guard that assigns its parameter, returns true before the check, or only checks
  that the file exists does not. `strpos(` and `stripos(` compared `=== 0` or `!== 0` are a prefix
  check in the path rules, of their first argument only (`strpos('/var/logs/', $real)` holds for
  `/` and `/var`). Where `realpath($p)` found the file, `$p` is no longer a URL or a
  `phar://` wrapper for the server-side request and phar rules; the path rules still report it. An
  `in_array()` lookup of `basename($p)` or `intval($id)` no longer validates `$p` or `$id`:
  `../../x/log.txt` and `1 OR 1` pass it.
- `shentu patrol --dry-run` prints all its titles (each attack attempt, the summary past the
  round's limit, the attack detection notice) in the setting's language, as they are sent; they
  were always in English.
- Fixed the v0.5.6 known issue: `new $var(...)` is no longer taken as a call of the parameter
  `$var`. It makes an object of the class `$var` names and calls no callable, as `NEW $var(...)` in
  any case does too. A caller passing a variable there is no longer marked as having calls not all
  followed, and the argument's input no longer reaches the function's return, where it could be
  reported falsely (`echo get_entity($_GET['a'], $c)` reported `php-xss-echo-html`). Plugins that
  bundle the Freemius SDK (`fs_get_entity($entity, $class)`) had the most such files.
- block_ip's login index reads a flood with a lighter read, with the same result as the full read.
  While the index is full, addresses with no event in the window are pruned at most once an hour of
  event time, no longer for every event of an address without a slot. A journal line of string
  fields only is read by a flat reader that gives the same fields as the full one; any other line
  goes to the full reader as before. The patrol reads on past a read cut short by its time, each
  read saved, until it has read to the end or spent 15 minutes, so a check between patrols reads
  only what came since. An address that may be among those past the index's 65,536 is still refused,
  never let through.
- The patrol catches the login index up after its checks, its notice and the attack detection
  alerts, not before them: in a flood the catching up can take up to 15 minutes, and that round's
  notices no longer wait for it.
- block_ip's login index tells journal entries of the same time apart by their numbers in the
  journal (the cursor's `s=` and `i=`). After a vacuum that removed an entry with the same time as
  the first one left, the index took the removed entry as still there. An address whose event was
  removed was then seen as sshd's own, where the whole read sees nothing, and a forged event that
  was removed still refused the block. When a number is not known (an index saved by an older
  version, a cursor not of that form, a journal made anew), times decide on the strict side: an
  entry that refuses the block counts as there at the first entry's own time, and an event that
  lets it through does not.
- The site's release river: a release's peek stays inside the river at every width (at 844px the
  pages scrolled sideways by 3px); the labels under the lamps (version, date, rule count) show only
  where they have room, the newest and the x.y.0 releases first, and a hidden one shows on hover or
  focus of its lamp (they ran into each other at 844px and 1440px); each lamp's link reads out its
  version, date, rule count and bench result.
- A code audit's scan stops on work done, no longer on time: a file's first pass and a project's
  calls passes each have a work cap (60M and 1.5G), and the clock stays only as a safety net. What
  is followed, and so what is reported, no longer depends on how fast or how loaded the machine
  is; a slow machine takes longer instead of stopping sooner. On WordPress 7.1.4 (2,148 PHP files)
  the files left unfinished went from about 800 to 1,100, different on every run, to 16 on every
  run, with no rise in memory.
- `app_vulns` and the daily patrol check the Python packages installed in site-packages folders
  (venvs under the app paths, `/usr/local/lib/python3*`, and what pip installed in
  `/usr/lib/python3*`) against OSV as PyPI, with the CISA KEV mark, as they check a lock file. Until
  now only lock files were read, so a package installed with pip and listed in none was not
  checked. The scan has bounds (8 folders deep, 100 site-packages folders, 5,000 packages in one,
  the first 64 KiB of each METADATA, no symlinks followed); what it did not cover is reported as not
  checked.
- They also list the `.pth` files there with lines Python runs at every start: the file and how many
  such lines, not their text. A file is marked as a tool's own (setuptools, virtualenv, an editable
  install) only when it can be proven: every such line is exactly the tool's, the tool's own record
  of it is there (a RECORD that lists the file itself, and its module, with their hashes,
  virtualenv's key in `pyvenv.cfg`, or the system package manager's folder), and the folder, every
  folder above it and those files can be written by root alone. In a folder a user can write,
  whoever wrote the file could have written the record too: setuptools', virtualenv's and editable
  install files there are listed in the daily report as not proven. The patrol pushes the others as
  warnings.
- PHP XSS in a `<script>` body: a value escaped with `esc_attr()`, `esc_url()`, `esc_html()` or
  `htmlspecialchars(..., ENT_QUOTES)` inside a quoted JS string
  (`var tab = '<?php echo esc_attr($_GET['tab']); ?>';`) is no longer reported when the text after
  the PHP block closes that string on the same line: a `<script>` body decodes no entity, so with
  both quotes and `<` encoded the value stays inside the string. It is still reported in an `on*`
  attribute (which decodes entities first), in a template literal, after a block that writes a
  quote or a backslash, on a line ending in a `\` continuation, with `htmlspecialchars()` without
  `ENT_QUOTES`, and with `sanitize_text_field()`.
- PHP's server-side request rule takes a start that is a local path as fixed: a directory
  constant then a literal with a path segment (`WP_CONTENT_DIR . '/uploads/' . $name`, also through
  a variable that holds it, as in Welcart) or a drive (`'C:\\data\\' . $name`). The input then
  cannot choose a scheme or a host, so `file_get_contents()` of it is no longer reported as a
  server-side request; the path rules still report it. The constants are `__DIR__`,
  `DIRECTORY_SEPARATOR` and the directory constants of WordPress, Drupal and Joomla (`ABSPATH`,
  `WP_CONTENT_DIR`, `DRUPAL_ROOT`, `JPATH_ROOT` and others). Still reported: a plugin's own
  constant, a constant defined from input (also one of these names, as in
  `define('ABSPATH', $_GET['b'])`), a bare `/` or `/a` after the constant, `C:` alone, a `\\`
  start, and an escape such as `\x3a` in the literal.
- SQL injection and XSS rules take arithmetic as a number, which carries no quote or markup:
  a page offset `(max($_GET['paged'], 1) - 1) * 20` in a `LIMIT` (as in Welcart), PHP's
  `$_GET['n'] + 1`, JavaScript's `req.query.n - 1` and Python's `request.args['n'] - 1` are no
  longer reported there. Arithmetic is `-`, `/`, `*`, `%` and `**`, with a `+` next to a number
  in PHP; in Python it is `//`, `**`, and `-` or `/` next to a number. Still input: PHP `+` of two
  arrays (their union), `|` of two strings, `.` next to `-`, JavaScript's binary `+`, Python's `*`
  (which repeats a string), Python's `-` of two sets or two `Counter`s (their difference, as in
  `set(request.args.getlist('id')) - {'0'}`), and a number in the path rules.
- The package vulnerability check (`vulns`) compares third-party PHP and nginx packages (from
  deb.sury.org, the ondrej PPA, Remi's repository or nginx.org) with php.net's and nginx.org's
  releases of 2026-11-19, the tables of the PHP and nginx checks. OSV has only the distributions'
  advisories, so these packages matched nothing there and were only listed in
  `third_party_unchecked`. Now each CVE in a package's range is in the vulnerability surface
  (ecosystem `upstream:php` or `upstream:nginx`, with the fixed version, KEV when CISA lists it)
  and in `third_party_upstream`, and counts in `total_vulns` and `affected_packages`, once per source package and CVE with
  OSV's; one that CISA lists is in `actively_exploited` too (one entry naming the binaries), so the daily patrol sends its critical KEV alert as for a
  distribution's package. A CVE the package's changelog names (a backported fix) is listed as
  backported and not reported. php-fpm also gets the FPM and status page CVEs, php-cgi the CGI
  one; mod_php and the CLI get the engine's only. Each compared package says the tables' date
  (`as_of`). A package whose version cannot be read, on a branch php.net no longer fixes, or newer
  than the tables' newest release (such as PHP 8.3.38, 9.0 or nginx 1.32) stays in
  `third_party_unchecked` with the reason in `why`. The OSV results of these packages are kept: a
  build can also be older than the distribution's fix.

### Known issues

- A value read back from the database is input when the query that read it was given input,
  even escaped (`$row = $db->LoadSingle("... '" . mysqli_real_escape_string($c, $_POST['id']) . "'")`,
  then `$row['tag']` in another query): the engine takes what an unknown function returns as
  carrying its arguments' input. YesWiki's despam.php is reported this way.
- An application's own URL builder for a page of the same site (YesWiki's
  `$this->wiki->Href('', $name)`, `href()`) is not known as one, so a redirect to it reports as an
  open redirect (YesWiki's LoginAction.php and DuplicateHandler.php).
- macOS 27 hides the Internet sockets from netstat for any process started by an ad-hoc signed
  program, as the release binaries are: `netstat -anv` writes nothing there (exit 0). shentu then
  lists the listening ports with lsof, which sees only its own user's processes, and marks the list
  partial. Run from a terminal, netstat shows them. macOS 15 is not affected.
- A Debian or Ubuntu package held with `apt-mark hold` (dpkg status `hi`) is not checked: the
  package list keeps only `ii` packages, so `vulns`, the daily patrol and the vulnerability surface
  do not see it, and it is not listed as not checked either. The next release fixes this.

## v0.5.6 — 2026-11-24

- A file cut short says what cut it (#172). The code audit's unfinished files carry a `cause`:
  the token cap, the file's time limit, nesting, a rule's work cap for following calls, the
  project's cap (its time, memory or tokens), a call that may reach another file with no one
  callee to follow, or a callee's summary cut short (with why: its own work cap, a chain of
  summaries too long, too many parameters, or a cut inside it). The CVE bench counts files whose
  calls were not all followed, which it did not count before, and lists cuts by cause.

- PHP function and method names in sinks and sanitizers match in any case, as PHP calls them
  (#189). `System($_GET['x'])`, `SYSTEM(...)`, `\SYSTEM(...)`, `System(...)` inside a namespace
  and `Shell_Exec($c)` in a function a call reaches now report as the lower-case spelling does,
  and a sanitizer written `EscapeShellArg($x)` cleans. A method that happens to be named `system`
  (`$o->System(...)`, `Task::SYSTEM(...)`) is still no sink. JavaScript and Python names keep
  their case. A builtin named in a string with an escaped backslash (`array_map('\\system', $x)`,
  `"\\system"`), which PHP reads as `\system`, is that builtin as well. A pattern naming a PHP
  function no longer matches a class built with `new` (`new File($p)`, `new System(...)`) or a
  function of a namespace (`Storage\file($p)`, and `namespace\file($p)` in a file that declares a
  namespace), as the lower-case `new file(` and `A\file(` did before; `\file($p)` is still PHP's.
  The method and class names of member patterns match in any case too (#198): `$wpdb->Query(...)`
  and `$wpdb->GET_RESULTS(...)` are `php-sqli-wpdb-unprepared`'s sinks, `$wpdb->Prepare(...)`
  cleans, and `DB::RAW(...)` is a sink; a variable keeps its case (`$WPDB` is not `$wpdb`).

- Calls through callables are followed (#182, #184, #188). A PHP function that calls its own
  parameter (`$cb($v)`, as `tap()` and `Arr::first()` do) is followed at each caller with what the
  caller passes: a closure, a function name (`'run_cmd'`, `'Cmd::run'`), an array callable
  (`[Cmd::class, 'run']`, `[$this, 'run']`) or a first-class callable (`run_cmd(...)`). A closure
  handed to a PHP builtin that calls it (`array_map`, `array_filter`, `array_walk`, `usort`,
  `array_reduce`, `preg_replace_callback`, `call_user_func` and others) is analysed with the input
  the builtin gives it, and a builtin's name given as the callable is that builtin:
  `array_map('system', $_GET['x'])` and `array_map(function ($v) { system($v); }, $_GET['a'])` now
  report. Fewer files are left with calls not followed (#174, #178, #179, #182): Python's
  standard-library imports (`import json` in a package with its own `json.py`) and a closure that
  cannot leave its function are no longer taken as calls of the project's other files. On the E7
  corpus, laravel-framework's unfinished files went from 280 to 115 and Django's from 135 to 24.

- Fewer false findings from checks and fixed values (#185, #187). After `unset($x)`,
  `unset($a['k'])` or `unset($this->p)` the value carries no input; `is_numeric`, `is_int`,
  `is_float`, `ctype_digit` and the other number checks count as checks in every rule
  (`if (is_numeric($p)) { ... "WHERE id = " . $p }` no longer reports). `wp_create_nonce()` and
  `wp_hash()` return a value with no input. A sink inside a function, called after the caller's
  `check_admin_referer()` or another nonce check, is treated as a sink written in the caller is. A
  sink that needs the input at its start (`header("Location: $u")`) is not reached through a
  function when the argument starts with a fixed text (`go(admin_url('x') . '?a=' . $v)`).

- The host survey checks PHP against php.net's releases of 2026-11-19 (8.2.36, 8.3.37, 8.4.28,
  8.5.13; 8.6.0 and later are fixed). The version is the one each PHP binary names itself with
  (`php`, `php-fpm`, `php-cgi` and their versioned names, in the distributions' places,
  `/usr/local` as in the official Docker images, Remi's `/opt/remi`, cPanel's `/opt/cpanel/ea-php*`
  and CloudLinux's `/opt/alt/php*`), read from the file, not by running it; on Windows, the
  `php-cgi.exe` IIS runs as a FastCGI application. This covers PHP the package scan does not see:
  deb.sury.org, the ondrej PPA, Remi's repository, an rpm whose vendor is not the distribution's
  (IUS, cPanel), Docker images, builds from source and IIS. A binary naming several versions, a
  program with none, and a FastCGI path that is not a local absolute one are named as not
  checked. As for nginx, a package whose changelog names a CVE is not warned
  about for it. CVE-2026-129291 and CVE-2026-129289 are warned about only when php-fpm runs, and
  CVE-2026-129292 (the status page) only when a pool's `pm.status_path` can be reached from
  outside: its socket takes connections from other hosts, or nginx (in a server not listening on
  127.0.0.1 only) or Apache passes the path on to FPM without `deny all` or `Require local`. Each
  branch reads its own pools; includes are followed and comments left out. CVE-2026-129538 is warned about only when php-cgi
  runs or IIS runs it. The other fourteen are one line by version. A branch php.net no longer
  fixes (before 8.2) is noted only when no distribution package holds it, and what could not be
  read (the process list, a configuration file, IIS's configuration) is named in a line saying
  which of these could not be checked.

- On Windows, the host survey and the daily vulnerability surface look for php-cgi.exe run by
  Apache as CGI (httpd.conf and what it includes, XAMPP's `httpd-xampp.conf` too: a `ScriptAlias`
  onto php-cgi.exe or its folder, an `Action` through such an alias, or `AddHandler cgi-script .exe`
  in that folder) and check it for CVE-2024-4577 (fixed in 8.1.29, 8.2.20, 8.3.8) and its bypass
  CVE-2024-8926 (8.1.30, 8.2.24, 8.3.12). The system code page (ACP) decides: 932, 936 or 950 for
  CVE-2024-4577, an OEM code page set as the ANSI one for CVE-2024-8926; when it cannot be read,
  they are reported as a warning with "code page unconfirmed". Branches before 8.1 are reported as
  a warning, as the advisories do not list them and they get no fix. The surface marks an entry
  KEV only when the CISA KEV catalog lists it. php-cgi.exe under IIS is not reported for them,
  as the advisories cover Apache only; the version line says so. Apache is the one a service
  runs, or at XAMPP's or Apache Lounge's place when only administrators may write its httpd.conf;
  a network or device path in the configuration (`\\host\share`) is never read, nor an included
  file whose link leads to one. Without a `LoadModule` of cgi_module or cgid_module in what was
  read, Apache would not run CGI, so the entry is a warning, not critical (one inside an
  `<IfModule>` counts as loaded); when some of the configuration could not be read, it stays
  critical and says so. A path whose links cannot be checked, or with `:` or `?` after the drive
  (an alternate data stream), is not read either.

- Attack detection has a signature for CVE-2024-4577 (#199): php-cgi's command-line options sent
  in the query string of a `.php` file (with a PATH_INFO or not), the site's index page (`/`) or
  `/php-cgi/php-cgi.exe` (a soft hyphen, `%AD` or `%C2%AD`, then a one-letter option, or
  a hyphen and an option letter standing alone). It is matched to the host by the CVE, so it
  alerts on a host whose surface has CVE-2024-4577, with the KEV mark that entry carries; on any
  other host its hits are counted as noise.

- What the patrol's own checks found is in Chinese too with a Chinese `language`: new listening ports,
  suspicious processes, UID 0 accounts, authorized_keys changes, links and shared keys, ld.so.preload,
  PAM modules, webshells, certificates, SSH login failures, CISA KEV vulnerabilities and unreadable
  authorized_keys lines. The English text is word for word what it was, and the model is still sent
  the English list. Findings from the tools (survey risks, changes since the last survey, the code
  audit) are still in English.

- The package vulnerability check (`vulns`) names the packages that came from a repository other
  than the distribution's, as `third_party_unchecked` with the repository and how it was told
  apart. OSV covers the distribution's packages only, so these were compared as if the
  distribution had built them and matched nothing: that silence is not "no vulnerabilities".
  A package is told apart by its version (deb.sury.org's `+deb.sury.org`, nginx.org's
  `-N~codename`), by the package index of a third-party apt repository, or by an rpm vendor that
  is not the distribution's. Third-party repositories (apt, and Alpine repositories other than
  main, community and testing) are listed in `third_party_repositories`; when one is configured but its
  packages cannot be told apart, a note says so. A flat repository (a `Packages` with no `Release`)
  is third party. An rpm vendor counts as the distribution's only on that distribution (Oracle's
  MySQL packages on Rocky are third party). Indexes that could not be read, or rpm vendor output
  cut short, are listed in `origin_unread`. An Origin, a vendor and a repository path are written
  by whoever publishes the repository, so a third-party repository that names itself after the
  distribution is taken for it: this check can only add packages to the list, never show that a
  package is the distribution's.

- block_ip's check of an address's SSH logins no longer reads a month of journal each time. The
  login events of sshd's units (ssh, sshd, and the socket-activated ssh@ and sshd@) are kept per
  address in `loginindex.json` in the state directory (0600, written whole and renamed in place),
  and each check, and the patrol every hour, reads on from the journal cursor where the last read
  stopped. The rules are the same: an address's events count only when sshd itself (`_COMM` sshd or
  sshd-session, `_UID` 0) wrote every one of them in the window (the last day if it has any there,
  else 720 hours), and the text logs are read as before for an address journald has none of.
  On a VM journal of 1.2 million entries one check had read for about 37 seconds.

- The index answers as strictly as reading the whole window, and no more so for what that read
  cannot see: with no index (the first run, a file of an older format) it starts from 720 hours
  back, and a window it does not reach back to is read whole, as before. Each read also asks where
  sshd's units now start in the journal: whatever the index kept from before that (vacuumed, or
  flooded out by an attacker) no longer counts for an address or against it. When the cursor's own
  entry is gone, journalctl seeks to the nearest one without an error: the index reads from its
  cursor's entry, sees that it is gone, reads on from the first entry still there (that one
  included), and notes it. Entries are read whole up to the 1 MiB line the whole read takes, so an
  event with a 70 KB user name counts for its address; only an entry past that, which the whole read
  fails on, makes a window holding it unverified for every address. A read cut short by the check's
  time keeps what it read, so a flooded journal is read through over the checks, each within its
  time. Past 65,536 addresses the others' events are counted together, and an address that may be
  among them is refused, never let through. A saved cursor that is not one, or an address saved as
  null, is dropped when the index is read.

- A ✅ press whose checks ran out of time is refused as not checked in time (`timeout`), no longer as
  records that could not be read (`state_error`).

### Known issues

- Only php-cgi.exe that Apache runs as CGI on Windows gets CVE-2024-4577 in the surface (#200).
  php-cgi.exe under IIS's FastCGI does not, as the advisories name Apache only; neither does an
  Apache whose configuration Shentu does not read (not a service's, not at XAMPP's or Apache
  Lounge's place, or writable by other users). On those hosts the signature's hits stay noise.

- On a host whose surface has CVE-2024-4577, a one-word query with no `=` that starts with a byte
  that is not UTF-8 and a letter (a Latin-1, Big5 or Shift-JIS word not sent as UTF-8) matches the
  CVE-2024-4577 signature as `%AD` does: requests are matched decoded, where every such byte reads
  as U+FFFD (`docs/attack-detection-limits.md`).

- `new $var(...)` is taken as a call of the parameter `$var` (#182). A plugin that bundles the
  Freemius SDK has many files whose calls are marked as not all followed, and a false finding may
  come of it. No findings were lost on the E7 and CVE bench measurements. To be fixed in v0.5.7.

## v0.5.5 — 2026-11-23

- What a dispatch in progress has already used no longer counts twice near the budget limit: its
  reservation knows the dispatch and when it started, and the others count only the rest of it,
  from the same read of the log as the month's use. A reservation that cannot be matched counts in
  full, as before.

- The survey (site_profile) checks the Docker and Podman sockets through the host source, like its
  other reads: a replay or a fixture is no longer answered by the machine running the survey.

- The nginx and Apache version checks (and nginx's changelog) read the surveyed host through its
  host source, like every other check: a replay or a fixture is no longer answered by the machine
  running the survey. Their package queries are exact commands in the allowlist.

- macOS: `listening_ports` and `processes` (and the patrol's process checks) read the Mac itself
  (netstat or lsof, and ps; no root needed) instead of Linux's /proc, which found nothing there and
  looked like a host with nothing running. An unreadable table is an error, and a partial one says so.

- macOS: `accounts_audit` reads the Mac's accounts (dscl; no root needed) and the authorized_keys of
  the login accounts and root, and sudoers when it can be read. What could not be read is in a note;
  the Linux-only checks (ld.so.preload, PAM modules not from a package) are listed as not applicable.

- macOS: `file_changes` finds a file by its status-change time (a faked modification time no longer
  hides it) with its owner's name, watches macOS's own places by default (/private/etc, Homebrew,
  launchd jobs), and lists directories it could not read; `cert_expiry` also reads Homebrew's certbot.

- macOS: `ssh_logins` (and the patrol's SSH check) reads sshd's login events from the unified log
  (`/usr/bin/log show --info --style ndjson`) and counts them as on Linux, marked verified: only
  events of sshd-session's or sshd's own image path, logged by root (userID 0), are counted. A
  macOS 15 VM showed both hold: a program copied to /tmp under that name logs its own path, and a
  user's own sshd (the system's binary with a configuration of their own) logs that user's ID, not
  0. The events left out are counted in the result's source with their reason
  (`not_logged_by_root`, `not_sshd_image`, `no_user_id`, `unreadable_event`). An event with no
  userID or one that cannot be read, or output without log show's closing line, makes the result
  incomplete (the counts are a lower bound), not a complete one with fewer events. Only root and the
  admin group can read that log: anyone else gets a permission error saying so, not an empty result.

- macOS: `log_search` reads macOS's text logs (system.log, install.log) by default, not Homebrew's
  nginx and Apache logs, whose directories their user could link root's files into (add them
  knowingly). A log under /var is found by the path log_paths gives it (on macOS /var is a link to
  /private/var, and such a path used to be refused). A log file with more than one hard link is
  refused (a root-only file linked into a log directory looks the same). sshd is in the unified
  log, which log_search does not read: the tool says no match there says nothing about SSH logins.

- The host survey's nginx check covers the rest of nginx's advisories of 2026-11-18 (#190).
  CVE-2026-118899, an infinite loop reading a request body over TLS 1.3, is warned about for nginx
  1.13.0 through 1.31.8 with a TLS server (`listen ... ssl`, or `ssl on`) that speaks TLS 1.3: its
  `ssl_protocols`, its own or else the http block's, names `TLSv1.3`, or it has none and nginx is
  1.23.4 or later, whose default includes TLS 1.3. Turning HTTP/2 off does not avoid it.
  CVE-2026-113425, a use-after-free in the mail proxy, is warned about only when a `mail` block has
  a server. The six medium and minor ones (the resolver, HTTP/3, stream with client certificates or
  `ssl_preread`, `try_files` with `alias`, PROXY protocol v2) are one line of advice by version,
  as the check does not look for those features. All are fixed in 1.31.9 and 1.30.7. As for
  HTTP/2, a distribution package whose changelog names a CVE is not warned about for it, and a
  configuration file that could not be read is named in a line saying which of these could not
  be checked.

- The daily report and the new-findings report follow `language` now: with a Chinese setting their title, section headings
  and fixed lines (what was not checked, incomplete vulnerability checks, attack detection, sub-agent dispatches,
  automatic incident checks, SSH logins) are in Chinese; up to v0.5.4 they were in English whatever `language` said.
  What a check found, error text and the model's answer are not translated: they are added as they came.

- macOS and Windows (#206): `block_ip` is refused as `unsupported` before any check. From Telegram
  on macOS it used to read up to a month of the unified log (about two minutes) before refusing a
  block that nftables cannot make there.

- Proposal buttons (Linux, #206): the checks run before the buttons are sent end together within 90
  seconds; a proposal not checked by then is listed as `timeout`, without a button, instead of
  holding back every button. A check of the dispatch archive cut short by its time limit is
  `timeout` too, not `state_error`. One address's SSH logins are read once for the archive, the
  buttons and Telegram's precheck (the answer is reused for two minutes); `block_ip` itself reads
  them again when it runs.

- Upgrade note (#206): going back to v0.5.4, that version reads a dispatch record whose gate is
  `timeout` or `unsupported` as a bad line, and the automatic incident checks can stop for up to 72
  hours.

## v0.5.4 — 2026-11-23

- Shared AI budget (#161): a dispatch from the bot, `shentu chat` or the automatic incident check
  reserves its whole token cap in `state_dir/reservations.json` while it runs, and every budget
  check counts the others' reservations, so together they overspend `[budget] monthly_tokens` by
  about one dispatch's cap (120k tokens) plus the answer in progress. Upgrading: while a dispatch runs, a question elsewhere
  can be told that its reservation leaves too little of the month's budget (it is released within
  about 17 minutes); a reservations file that cannot be trusted stops every AI answer and dispatch until it is
  moved aside (the bot says which file); and `auto_incident` with `monthly_tokens` of 150000 or less now warns, as no automatic
  check could ever start.

- Model prices (#162): `[agents] price_per_mtok_in` and `price_per_mtok_out` (dollars per million
  tokens) price each dispatch's reservation at its token cap times the higher of the two, so the
  monthly cost limit is shared between dispatches as the token limit is. When only the cost limit
  is filled by the others' reservations, the reply names the dollars reserved.

- `shentu usage` and the bot's /usage count the sub-agents' model calls (and any other actor's) (#164):
  they were left out of the totals, and a dispatch's calls now have a line of their own.

- `auto_incident` on with no `[notify] url` now warns (#165), when the bot starts, on the daily
  patrol and in its report: a check starts only from an L3 alert the patrol pushed, and the patrol
  pushes through the notify url alone, so none would ever start.

- A proposal press cut short by the bot stopping is logged as that (#166): "the bot stopped during
  the checks" or "before it was confirmed", not as a refusal or as declined by the operator.

- `shentu dispatch stats --json` has a versioned form for the weekly summary: `v` (1), `shentu` (the
  release), `until` (the UTC date) besides the days, counts, roles and suggestions, which are always
  lists. It holds numbers and fixed words only: no host name, address, path, dispatch id or trigger.

- One call two rules report stays the rule's it is left to (`yields_to`) also when only one of
  them follows a call in the file (#160). Before, `DB::select(DB::raw("..." . $_GET['a'] . "..." .
  col()))` with a local `col()` returning `get_query_var('o')` (input only
  php-sqli-orderby-identifier reads) was reported by both php-sqli-laravel-raw and
  php-sqli-orderby-identifier; the rules that yield to php-sqli-yii-query had the same gap.

- JavaScript request aliases (#160): after an `if`/`else`, a name holds what it held at the end of
  a branch that goes on, so a name reassigned on every branch (`let q = req; if (a) { q = {...} }
  else { q = {...} }`) is no longer read as the request. A branch that returns or throws drops
  out; one that ends in `break` or `continue` still counts.

- Read-only calls a URL check keeps (#160): `typeof window` (any global object after `typeof`)
  no longer ends them for the whole file. `String` after the colon of a conditional
  (`const S = c ? y : String;`) now does, as `String` used as a value does; before, it was read
  as a TypeScript type.

- PHP: `Request::get(` in a file whose `use` makes `Request` another library's class
  (`use Httpful\Request`, `use Unirest\Request`, `use Httpful\Http as Request`) is no longer read
  as Laravel's request facade (#160).

- The dispatch archive reads fields it does not know (#197): from v0.5.4 a record or feedback
  line written by a later version with a new field is read, its known fields checked as before,
  instead of being refused as unreadable (which stopped the automatic incident checks until a
  repair). Such lines are counted in `shentu dispatch stats` (`unknown_field_lines` in JSON) and in
  the daily report; `repair` leaves them; the unknown fields' content reaches no output.

- Upgrade note: going back to a version before v0.5.4, the dispatch records v0.5.4 wrote with
  items not checked (their `unchecked_why`) cannot be read there. Their proposal buttons answer
  that the dispatch is not in the archive; `shentu dispatch stats` skips them as unreadable lines;
  and automatic incident checks stop, the archive not being trusted, until
  `sudo shentu dispatch repair` moves those lines to `*.jsonl.bad` (kept, not deleted), after which
  they count again from the next patrol.

- Notices follow `language` (F-1, F-4 of the v0.5.3 real-bot round): the automatic incident check,
  "Approved from Telegram", pairing and unpairing, and the attack detection titles were English
  whatever the setting said; they now go out in Chinese when `language` is Chinese, as the bot's
  own messages do. The incident check's notice says in words what it found and what it did not
  check and, with no proposal, "nothing is suggested this time". What was not checked is said in
  fixed words only (the sub-agent's own text stays out of a notice, as before): the sub-agent now
  names the tool and picks a reason (`tool_failed`, `permission_denied`, `not_applicable`,
  `time_limit`; anything else is "other"), the program adds `not_available` and `findings_cut`, the
  archive keeps them (`unchecked_why`), the notice marks the sub-agent's picks as its own word,
  not confirmed, and items with no fixed words are counted, to be treated as unknown. The approval notice says first what happens
  ("blocking 192.0.2.30, lifted after 24 hours; the bot's reply says whether it worked"), the
  nft command after it as a detail. The daily and new-finding reports' own lines are not
  translated yet.

- Sub-agent proposals leave a trace (F-3): every report a role that may propose writes is logged
  as a `proposals` entry (how many it wrote, how many were kept), and each one dropped says why, in
  fixed words: `ip_is_a_network`, `ip_not_one_address`, `action_not_propose_block_ip`,
  `duplicate_ip`, `too_many_proposals`, `role_cannot_propose` (the first 20 listed, in shape only:
  a network in canonical form, otherwise only an address's characters; the total counted; the
  archive's own cap logs as `proposals_cut`). Before, a dropped proposal and no proposal looked
  the same. The sub-agents that may propose are now told to propose only addresses with strong
  evidence (a verified attack group's, or verified SSH logins with many failures), never one
  taken from log text such as headers, and one address per proposal, never a network. The
  automatic check tells its sub-agent it comes from a verified L3 alert, and that alert's address
  is kept first; duplicates no longer take places. A proposal is still only a button: the gate
  and the press are unchanged.

## v0.5.3 — 2026-11-22

- A proposal button pressed always gets an answer (#163): it says at once that it checks the
  address again, the log notes the press (`proposal_press`) before the checks, the checks run
  within a minute and past it the press is refused with the gate's word, and a failure inside is
  answered and logged. As before, a pressed button is used up whatever follows: one refused
  because its checks ran out of time, failed or were cut by a restart cannot be pressed again,
  and the next check's buttons are the ones to use.
- Telegram blocks ask only what the gate would allow (#155, #158): from a chat channel, block_ip
  runs the checks of #108's gate before asking for ✅. An address the gate refuses is refused at
  once, with no ✅ to press; the agent is told the gate's fixed word (and the address), and the
  gate's own message stays in the server's log only. When the block itself fails after the
  confirmation, its error too stays in the log only. Confirmed blocks are checked again when they
  run, as before.
- While the bot waits (#156, #158): a message sent meanwhile is told what it waits for (the ✅
  above, the authenticator code, or the server's approval with `sudo shentu bot approve`) instead
  of "Still working"; a question sent meanwhile is not passed to the agent (the authenticator code
  and the commands /lockdown, /new, /usage and /attacks still work). A proposal or suggestion
  button pressed meanwhile stays, to be pressed again later; a suggestion is no longer used up.
- `shentu dispatch` (#158): wrong arguments get the usage first, before the configuration is read
  and whoever runs it; `stats` and `repair` then ask for root (an elevated prompt on Windows).
  `sudo shentu dispatch repair` keeps each broken line in `*.jsonl.bad` once, and the daily report
  says how many moved lines were new to it.
- Next 15: `const h = await headers(); h.get(name)` and the sync `const h = headers()` are read
  as `headers().get(name)` in a file that imports `next/headers`, so a Host header read this way
  and passed to a redirect is reported by js-open-redirect-next (and by the SSRF and command
  injection rules that read `headers()`) (#157).
- Koa: a middleware a Koa application or router registers with `use` is followed through
  destructuring and aliases of its context, as a route handler is
  (`app.use(async (ctx) => { const { host } = ctx.request.headers; ... })`), when the function
  uses its first parameter as a context. An HTTP client's interceptor or a library's plugin
  registered with `use` is not read as one (#157).
- Laravel: `$request->sort`, a magic property, and the closure of
  `->when($request->input('sort'), fn ($q, $s) => $q->orderBy($s))` (and `->unless`) are read
  by php-sqli-orderby-identifier, where `$request` may be Laravel's request: the file uses a
  class of Illuminate, declares it with a `Request` type, or holds a class extending a
  Controller, or, in a project using Illuminate, it is a function's untyped parameter (#157).
- SSRF: the check of a URL's host is no longer kept at `console.log(u)`, `JSON.stringify(u)` or
  `String(u)` in a file that may replace them unseen in more ways: `Function` as a value,
  `Function.prototype.bind`, `getPrototypeOf`, `Reflect.construct`, vm's runners, `GLOBAL`,
  `top`, `this` other than read through a named member, the `console` module required or
  imported, and a `require(` or `import(` of anything but a plain string, or `createRequire` (#157).

### Upgrade notes

- Files with any of the patterns above report an SSRF finding again at `fetch(u)` after
  `console.log(u)`, as before v0.4.3. With the new Next, Koa and Laravel reads, the routes
  attack detection takes as reachable may change.

### Known issues

- A data object whose type name ends in `Request` (`SearchRequest $request`) is read as
  Laravel's request, as a FormRequest is.
- Next's `headers()` is followed only in a file that imports `next/headers` itself.
- `in_array($request->query('s'), [...], true) ? $request->query('s') : null` is not taken as
  a check of the value, with a request call as the source (the same with a magic property is).
- `shentu usage` leaves out the model calls of an automatic incident check's sub-agents
  (`sub:incident`): on a test server it listed 9 calls where the log held 13. `shentu budget`
  counts them. The fix (#164) is planned for v0.5.4.
- The automatic incident check's notice and the "Approved from Telegram" notice are in English
  whatever `language` is set to.

## v0.5.2 — 2026-11-20

- The sub-agents' own model (#135): `[agents] base_url`, `model` and `api_key_env` give them a
  model of their own; unset, they use `[llm]`. A model outside this host (anything but
  127.0.0.0/8, ::1 and localhost) needs `[budget] monthly_tokens`, or no sub-agent runs and
  nothing is sent; a dispatch that used one says so to the agent, in the archive and in the daily
  report. What it is sent is masked as before. From it, an error answer keeps only its status, as
  its text could quote the key; redirects are not followed, and a request that fails keeps only
  the kind of failure, not its URL. `[llm]`'s errors have the key replaced, as is and in its common
  encodings, before they are cut.
- Sub-agents at once (#136): on a model outside this host they run together, each with an equal
  share of the dispatch's token cap, when this month's token limit has room for a whole dispatch
  and, with `monthly_cost` set, under half of it is spent. On a model at this host, in any address
  form, they still take turns.
- `sudo shentu dispatch repair` (#134): moves the archive's unreadable lines to
  `<date>.jsonl.bad` and drops empty ones, so automatic incident checks resume without waiting up
  to 72 hours. Files are replaced in one rename, and the archive's lock is `dispatch/.lock`. On
  Windows it and `dispatch stats` run from an elevated prompt; run by anyone else, both say so
  before reading the configuration.
- Operator feedback (#137): under a dispatch's report the bot offers 👍 useful and 👎 false
  positive, once, for 7 days, to the paired user. `sudo shentu dispatch stats [--days 7] [--json]`
  adds the numbers up by role and suggests changes within fixed ranges (steps 4 to 10, tokens
  20,000 to 60,000, a prompt review). A tool could only ever be suggested away, never added; no
  tool suggestion is made yet. Shentu applies none itself.
- Platforms (#138): a role gets only the tools that work on this platform, and the others are
  listed as unchecked; proposals only on Linux; on macOS only `surface` runs for now; automatic
  incident checks run on Linux only and take no daily slot elsewhere.

### Upgrade notes

- An `[agents]` model on a LAN address or a host name, Ollama on another machine of the network
  included, counts as outside this host, and so do 127.1, 0.0.0.0, [::] and this host's own LAN
  address: set `[budget] monthly_tokens`.

### Known issues

- With a costly model, a dispatch's cost can pass half of `monthly_cost` in one go; the limit
  stops the next calls, not that one.
- The bot and the patrol each reserve room for their dispatches without seeing the other's.
- Automatic incident checks are off on Windows and macOS for now, the incident role included (on
  Windows it runs with fewer tools and proposes nothing).

## v0.5.1 — 2026-11-20

- Dispatch archive (#112): each sub-agent dispatch is saved to `state_dir/dispatch/<date>.jsonl`
  (0600 in a 0700 directory, kept 30 days) before its reports go back: roles, statuses and
  reasons as fixed words, counts, and the proposed addresses in canonical form with what the
  Telegram gate says of each. No text a sub-agent or a log wrote is kept. Every field is checked
  when a record is written and when it is read; an archive another user could write, or a link,
  is not read. The daily report has a section on the last day's dispatches, with addresses
  masked to /24 (/64 for IPv6).
- Proposal buttons (#116, #122): after a Telegram answer that dispatched, the bot lists the
  proposed blocks, with a button for each one that passes the checks `block_ip` runs from
  Telegram (#108's gate included) at that moment and was written in canonical form, at most
  five; any other gets a fixed word for why. A button carries only the dispatch id and a number.
  Pressing it runs the checks again, then asks for ✅ (with `[bot] confirm = 4` too), then
  blocks. A press is refused for another pairing, after 24 hours, a second time (after a restart
  too), or when the archive's address differs.
- Automatic incident checks (#117), off by default (`[agents] auto_incident`): an L3 group the
  patrol pushed dispatches the read-only `incident` sub-agent on its own. One a round, at most 3
  a day, a group once a day; none for unverified or overflow groups, none without
  `[budget] monthly_tokens` or past 80% of it, and none while the archive or `log.jsonl` cannot
  be read to its end. The notice carries fixed words and numbers; its proposals get the same
  buttons, sent only while the bot service runs and can change the firewall.
- The bot's and `shentu chat`'s monthly AI budget limit counts a `log.jsonl` it could not read
  to its end as used up.

### Known issues

- Sub-agents still run one after another, and they are built and tested for Linux only.
- A line cut short in the archive (a full disk, say) stops automatic incident checks for at most
  72 hours (usually about two days), until its file is out of the window they read; the daily
  report says so.
- With a 7B local model, sub-agents often use up their 6 steps and are reported incomplete.

## v0.5.0 — 2026-11-20

- Sub-agents (Linux, one host): in the Telegram bot and `shentu chat`, the agent can hand
  read-only checks to up to 3 sub-agents with the `dispatch` tool, each in one role: `patrol`,
  `surface`, `attack` or `incident` (#101). Each role has a fixed list of read-only tools; a
  sub-agent cannot block or unblock an address, notify, use a skill or dispatch again. They run
  one after another. Patrol rounds and the eval bot never dispatch.
- Limits: a sub-agent gets at most 6 model calls, 3 tool calls a step, 2048 output tokens a
  call, 40,000 tokens and 5 minutes; a dispatch at most 120,000 tokens and 12 minutes, and the
  monthly budget still applies. Tokens are estimated before each call and counted after it,
  reasoning tokens included. A sub-agent stopped by a limit, or one that does not answer in the
  required report, is reported incomplete with the reason, never as done. A model call cut off
  by a time limit is no longer retried.
- Reports: each sub-agent answers in a fixed JSON shape (findings, proposals, what it did not
  check), checked field by field and masked, and the agent reads it marked untrusted. A proposal
  to block is only a suggestion: after a dispatch, every `block_ip` or `unblock_ip` in that
  conversation asks for the ✅ button even with `[bot] confirm = 4`, until `/new`, and its audit
  log line names the dispatch. The bot's progress message shows the sub-agents' steps (the last
  12), and a tool name it does not know as "unknown tool".

## v0.4.3 — 2026-11-20

- SSRF: after a URL's host is checked, `console.log(u)`, `JSON.stringify(u)` or `String(u)`
  no longer ends the check, while the file uses `console`, `JSON` and `String` only to call
  them (no parameter or declaration of those names, no `console.log = f`) and holds nothing that
  may replace them unseen (a global object such as `globalThis` other than read through a named
  member, `eval`, `Function(`, a `with` statement, anything under a built-in's prototype)
  (#119).
- JavaScript route handlers: destructuring with a string key,
  `const { 'x-forwarded-host': xfh } = req.headers`, is followed, so the value is reported by
  js-ssrf-host-header instead of js-ssrf-http-request. In a Koa route handler, a destructured
  parameter taking `request` (`({ request }) => request.header.host`) is read as Koa's context
  when the file, or another file of the project, imports `koa`, `@koa/router` or `koa-router`
  (#119).
- New sources: Next 15's `(await headers()).get(...)`, so a Host header read that way and passed
  to a redirect is reported by js-open-redirect-next; Laravel's `Request::query(` and
  `Request::get(` in php-sqli-orderby-identifier (`DB::raw`, `->orderBy(`) (#118).
- NestJS: a field of a whole `@Headers()` object written into a response (`h['x-note']` in
  `res.send(`) is reported by js-xss-response (#125).
- Duplicate reports removed. One call, one SQL injection rule: where two rules report the same
  call on the same line, one of them leaves it to the other (`yields_to`). `->where(` with
  Symfony's `$request->query->get(` is php-sqli-doctrine-query-text's, no longer also
  php-sqli-drupal-db-query's; `DB::raw(...)` inside one of php-sqli-laravel-raw's calls is
  laravel-raw's where laravel-raw reports it. Another call on the same line is still reported
  (#125). And in the SSRF rules, after `const x = h` where `h` is a whole NestJS `@Headers()`
  object or Express's `r.headers`, `x.host` (also `x['Host']`, `x['x-forwarded-host']`) is
  reported by js-ssrf-host-header alone, no longer by js-ssrf-http-request too; a name that may
  also hold another value of the request (`r.query` on one branch) is still reported by both
  (#132).

### Upgrade notes

- Some findings move to another rule: `sa.text(...)` built from request input is reported by
  python-sqli-sqlalchemy-text instead of python-sqli-dbapi-format (#118); a string-key
  destructuring of a Host header by js-ssrf-host-header instead of js-ssrf-http-request (#119);
  and a call two SQL injection rules reported is reported once (#125). php-sqli-laravel-raw's fix
  now says an ORDER BY column or direction needs an allowlist. With them, the routes attack
  detection takes as reachable may change.

### Known issues

- A Koa middleware registered with `app.use` is not a route handler: its context is followed
  only as written (`ctx.request.headers['x-forwarded-host']`), not through destructuring
  (`const { host } = ctx.request.headers`) or an alias (`const h = ctx.request.headers`).
- A name reassigned on every branch is still followed after them, which reports more than it
  must.
- Next 15's `const h = await headers(); h.get(name)` and the sync `h = headers()` are not
  sources yet.
- The JavaScript read-only calls do not yet see `Object.getPrototypeOf`, an alias of `Function`,
  `Reflect.construct`, `vm.compileFunction`, or a global object reached through `this`, `GLOBAL`
  or `top`; and `typeof window` sends the whole file back to ending the check at `console.log(u)`.

## v0.4.2 — 2026-11-20

- The JavaScript rules follow a route handler's request whatever it is called: a parameter not
  named `req` (`(r, s) =>`), a Koa context not named `ctx`, an alias (`const q = r`,
  `const h = r.headers`) and destructuring (`({ headers }, res) =>`,
  `const { headers, hostname: hn } = r`, `const { host } = req.headers`). So `r.hostname`,
  `r.get('host')`, `c.host` and a destructured `headers` are reported now; a Host header read this
  way goes to js-ssrf-host-header, other headers to js-ssrf-http-request. A request header index
  is read in lower case, as Node stores it (`r.headers['Host']`). In the SSRF rules, Koa's
  `ctx.header` and `ctx.request.get(` are sources too, and so are `ctx.request.header.host` and
  `ctx.request.headers.host` for the Host header (#106).
- NestJS: `@Request()` counts as the handler's request, as `@Req()` does, in the 13 JavaScript
  rules that read `@Req()` (SSRF, SQL and NoSQL injection, command injection, code evaluation, path
  traversal, LDAP injection, deserialization). Both count as NestJS's only when the file, or another
  file of the project, imports `@nestjs/common` or `@nestjs/core`; elsewhere they are an object like
  any other (#103, #106).
- Python: `global` and `nonlocal` continued with a backslash are read to the end of the
  statement, so a name on the next line is declared too (#103).
- SSRF: after a URL's host is checked, `a = u.valueOf()` followed by a change to `a`, or a method
  of `u` called by a computed name (`u['valueOf']()`, `u[k](...)`), ends the check, as `a = u`
  does (#103).

### Fixed

- A web log owned by the server's own account no longer backs a block when systemd's userdb
  directories (`/etc/userdb`, `/run/userdb`, `/run/host/userdb`, `/usr/local/lib/userdb`,
  `/usr/lib/userdb`) hold any entry or cannot be read: userdb can add accounts and group
  memberships that `/etc/passwd` and `/etc/group` do not show (#113).
- Hardening only: the block check also reads an address in an `inet_aton` form (`3405803788`,
  `0xcb.0.113.12`, ...), and the block check and campaigns read `::ffff:a.b.c.d` as `a.b.c.d`.
  Access logs never yield these forms (since v0.4.0 a client must be a plain address, and
  `::ffff:` is read as IPv4), so nothing changes in practice (#113, #124).

### Upgrade notes

- Some JavaScript findings move to another rule: a Host header read as
  `r.headers['X-Forwarded-Host']` or `const { host } = req.headers` is reported by
  js-ssrf-host-header instead of js-ssrf-http-request; `@Req()` in a project that does not import
  NestJS is reported by js-ssrf-http-request; `const { host } = req.headers` written into a
  response is no longer reported by js-xss-response, as Host has not been XSS input since v0.4.1.
  With them, the routes attack detection takes as reachable may change.
- On a host whose systemd userdb directories hold any entry, the server's own account no longer
  counts as apart after the upgrade: a log that could back a block in v0.4.1 (Rocky 9 nginx's,
  say) is judged `web_user_writable` again. The conditions are in `docs/attack-detection-limits.md`
  under "Which web logs can back a block". Default Ubuntu 24.04 and Rocky 9 installs have none of
  the five directories, so they are not affected (checked on both at 4fcfc52).
- A correction to v0.4.1's notes: "an address logged in another form (brackets, a port, a
  zone, leading zeros) is refused" cannot happen through the access logs, which keep only plain
  addresses. It takes effect only when a log has an IPv4-compatible (`::a.b.c.d`) or NAT64
  (`64:ff9b::a.b.c.d`) client. The released v0.4.1 entry is left as it was.

### Known issues

- A Koa handler's context is recognized by how the handler uses it (`c.request`, `c.response`,
  `c.state`, `c.throw`, `c.assert`, or setting `c.body`, `c.status` or `c.type`); any other
  parameter is read as Express's request. A destructured parameter is read as Express's request,
  so Koa's `({ request }) =>` is not followed. Nested patterns (`{ headers: { host } }`) and
  string keys (`{ 'x-forwarded-host': xfh }`) are not followed either; the latter is still
  reported, by js-ssrf-http-request.
- Request aliases are kept per function, and an alias reassigned on one branch is no longer
  followed on any path.
- `@Req() req` in a file that does not import NestJS, outside a project that does, is not NestJS's:
  its `req.headers.host` is reported by both js-ssrf-host-header and js-ssrf-http-request.
- The URL check fails closed: `global u` or `nonlocal u` anywhere in a file, backslash-continued
  too, ends it for every `u` of the file; `fetch(u.valueOf())` after a check, and a harmless
  `u['toString']()`, are reported.

## v0.4.1 — 2026-11-20

- The host survey warns about nginx 1.9.5 through 1.31.8 serving HTTP/2 (a `listen ... http2`, or
  `http2 on` for a server): CVE-2026-123007 and CVE-2026-123633, HTTP/2 memory corruption that lets
  a client crash the workers. Upgrade to 1.31.9 or 1.30.7, or to the distribution's fixed package;
  until then, turning HTTP/2 off avoids it. It is advice: the configuration is not changed. A
  distribution package whose changelog names the CVEs (a backported fix) is not warned about; the
  package scan reports the distributions' advisories once they reach OSV, and this check covers
  nginx.org's packages and builds from source, which that scan does not.
- A web log owned by the server's own account (`nginx` on Rocky Linux, say) can back a block,
  as a log root owns can, when nothing else runs as that account: no PHP-FPM pool, systemd unit,
  crontab, supervisord program, sudo or doas rule or login shell, and at the patrol no process
  but the server's own; the account databases come only from the files, and everything checked
  was read. Anything unread leaves the log `web_user_writable`. The shared default accounts
  (`www-data`, `apache`, `nobody`) never count. The other conditions are in
  the limits document, `docs/attack-detection-limits.md`, under "Which web logs can back a block".
- nginx's access log sent to journald (`access_log syslog:server=unix:/dev/log,...`) is read and
  verified line by line: a line counts only when it came over syslog from nginx's own program,
  running as nginx's worker account in `nginx.service`. A line another program sent is read but not
  verified.
- `shentu log-trust suggest` prints the changes that would let this host's web logs back a block:
  the journald line for nginx, a drop-in lifting journald's rate limit for nginx,
  `kernel.yama.ptrace_scope = 1`, and PHP-FPM pools of their own account. It only prints them and
  changes nothing.
- Apache's modules are judged against a list: modules that only configure, control access, cache
  or proxy are no concern; those that run programs as the children's account, and `RewriteMap`'s
  `prg:`, want `ptrace_scope` 1 or more; `mod_php`, `mod_cgi` and unknown modules count as
  application code.
- An attack hit in a route placeholder's segment that carries `;` parameters (`/user/42;x` for
  `/user/:id`) now reaches L2; before, it stayed at L1.
- The response-size baseline used for L3 now leaves out only requests taken to L2; requests with
  hits that are unanchored or noise are learned from.
- Rule precision: findings that two rules both reported on one line now have one owner (Host
  header against SSRF, SQL injection, `ORDER BY` identifiers), and an SSRF host checked against a
  fixed allowlist on a parsed URL counts as checked. Some findings appear or go away, and with them
  the routes attack detection takes as reachable.

### Fixed

- From Telegram, `block_ip` now blocks only an address with evidence Shentu verified: a verified L2
  or L3 attack group listing it, or SSH login events sshd itself logged. Any other address is
  refused there, to be checked and blocked on the server with `shentu chat`, as v0.4.0 said of
  unverified attempts. Before, an address its attack groups did not list (past the ten a group
  lists, in a group evicted from the state, or logged in another form) was judged by its SSH logins
  alone, so one with none could be blocked from Telegram on unverified attempts. A group lists at
  most ten addresses, so the eleventh and later of even a verified L2 or L3 group are refused from
  Telegram too, by design, and are to be blocked on the server.
- On the server, an address past the addresses a group lists is refused as a listed one is, also
  after the group is merged into an overflow summary, and so is the rest of its network. So is an
  address logged in another form: brackets, a port, a zone, leading zeros (read both ways), or IPv4
  embedded in IPv6. A verified group allows a block only of the address it lists. Once an overflow
  or sink-wide summary has more sources than it keeps hashes of (64), it refuses every address it
  does not list; the operator may override on the server.

### Upgrade notes

- v0.4.0's known issue that default nginx logs cannot back a block, planned for v0.4.1, now
  stands as follows (`docs/attack-detection-limits.md` has the details):
  Debian 12 and Ubuntu 24.04 nginx stay `web_user_writable` (`www-data` is PHP's account too):
  send the access log to journald, with `ptrace_scope` 1. Debian 12 and Ubuntu 24.04 Apache are
  verified with `ptrace_scope` 1. Rocky 9 nginx stays `web_user_writable`, because the default
  `nsswitch.conf` also asks sss: taken out (where no SSSD is used), with PHP-FPM as `apache`, it
  is verified. Rocky 9 httpd wants `ptrace_scope` 1, and `AllowOverride None` everywhere if
  `mod_lua` stays loaded.
- Once a log is judged verified, new attempts go into verified groups, while the old unverified
  groups expire only after up to 7 days: until then one target may show two groups. A new
  journald source is read the first time from its latest position on, not from the past.

## v0.4.0 — 2026-11-18

- Attack detection (Linux): each patrol round reads the web server's logs and picks out the
  requests aimed at vulnerabilities this host really has. It alerts; it never blocks on its
  own. What it cannot see and what it may miss are listed in
  `docs/attack-detection-limits.md`.
- The vulnerability surface: the daily round saves what this host is known to be vulnerable to
  in `state_dir/surface.json`, and the other rounds read it: code audit findings, with the
  routes registering the handler a finding sits in when the same file shows them (#84);
  advisories of application dependencies and of installed OS packages, compared in dpkg's and
  rpm's version order; installed WordPress plugins and their versions (#91). A surface missing,
  unreadable or older than 26 hours is said in the round's notices and the report, never used quietly.
- Log sources: the access logs nginx and Apache are configured to write, custom formats
  included, PHP-FPM's logs and journald for application units, read from where the last round
  stopped across rotation (#85). A log counts as verified only when root alone could have
  written it; otherwise its attempts are marked unverified and the alert names the reason.
- 27 attack signatures, written for Shentu or drafted from reviewed nuclei-templates (MIT,
  see `detect/sig/NOTICE`), matched after decoding a request at most twice (#87). A request
  that only reaches a route of a vulnerable handler is L1; one that also carries a payload of
  the vulnerability's class is L2; L3 needs a sign it had an effect: a response size far from
  the route's usual one, or an error at the vulnerable file and line (#90). A request cut where
  it may hide a payload is Unknown. A vulnerability the host does not have is noise.
- Alerts are the detector's own plain text, sent through the notify channel, not through the
  model. Attempts are grouped by network (/24 or /64), target and level, and a group is sent
  once a day. L1 is counted in the daily report, never pushed; Unknown is pushed only when one
  target gets 20 of them within 24 hours. Sensitive parameters in samples are masked, and the daily file
  `state_dir/reports/attacks-<date>.txt` (kept 30 days) masks addresses (#90, #91).
  `shentu detect [--since] [--json]` reads and judges a round without sending or saving;
  the `attack_attempts` tool and the bot's `/attacks` list the last day's groups.
- `block_ip` and attack detection: an address the detector saw is blocked, after the operator
  confirms, only for a verified L2 or L3 group of its own. Attempts from unverified logs, at L1
  or Unknown, and internal addresses are refused unless the operator overrides with
  `override_unverified` on the server (`shentu chat`); Telegram never can. An address listed
  only in an overflow summary of many sources is refused, override or not (#91).
  On an Ubuntu VM, an attack in a verified log was judged L3 and could be blocked; one in an
  unverified log reached L2 at most, and its block was refused from Telegram.
- `block_ip`'s SSH evidence counts a login only when sshd's own events in journald confirm it
  (#91): sshd lines that another program in sshd's own unit writes to journald (for example
  with `logger`) no longer back a block; v0.3.1 blocked on them. Lines forged into text logs
  were refused already.
- Engine: summary runs that cannot change the result are skipped, and the analysis copies less.
  Measured as user CPU time on a Mac, WordPress is scanned about 34% faster than v0.3.1 and
  TypeScript projects about 22% faster, with the same findings (#92). Measured as elapsed time
  on an Ubuntu 24.04 VM (arm64, 4 CPUs, 4 GB), one version after another on the same machine,
  the WordPress scan took 97.2 s (v0.3.1 120.0 s, v0.3.0 72.1 s), 19% less than v0.3.1, with
  the same 2279 files and 43 findings and a peak memory of 848–858 MB in all three; the daily
  patrol as root took 126 s (v0.3.1 146 s, v0.3.0 99 s). Benchmark unchanged: published vulnerabilities 16 of 97 caught, 1
  fixed-release false positive; held-out cases 3 of 30; TypeScript cases 1 of 18 with 1
  fixed-release false positive.
- `tools/detecteval`, run in CI, measures attack detection on synthetic requests (#94): requests converted from nuclei-templates v10.5.2: a signature of the same class matched 40.5% of them (1548 of 3822 classified templates). This is a match on the request line, not an alert; ordinary requests for 152 routes of 8 applications: 0 false alerts; 363 of them differ in more than tracking parameters, so the rate can only be said to be below about 0.8% (95% upper bound); templates for vulnerabilities the test host has: 3 of 10 alerted, 2 of them only at L1 (the payload is in the request body).

### Fixed

- When one request hits several rules on the same line of code, you get one alert that lists
  every rule, instead of one alert per rule (#97).
- Alerts for a package's CVE no longer carry the note on what routes mean; that note is for
  alerts about your own code only (#97).
- When an ACL lets another account write a log or a directory above it, the reason names that
  account, for example `ACL grants write to www-data (uid 33)` (#97).
- When the patrol runs as an account that is not root and not in the `systemd-journal` or `adm`
  group, the SSH result is marked as only partly read (#97).

### Upgrade notes

- An attack state saved by a v0.4.0 build from before these fixes (one group per rule) is
  merged into the new format (one group per line of code) when it is loaded (#97, #98). The
  counts from before the upgrade are a lower bound: when rules of different classes on the same
  line were hit by different requests, the count may be too low. This changes only the counts
  shown, not alerts or blocks. v0.3.x keeps no attack state, so an upgrade from it has nothing
  to merge.

### Known issues

- Attack detection is for Linux only.
- Access logs do not record request bodies (POST forms, JSON, uploads): a payload there is
  never seen, and such a request is L1 at most.
- The signatures expect the plain form of an attack. Rewritten forms (other encodings, padded
  paths, comments or other whitespace inside SQL, commands split by quotes) may be missed.
- With nginx as installed by default on Debian, Ubuntu and Rocky Linux, v0.4.0 judges its access
  log `web_user_writable` (the web server's account could write it or a directory above it): its
  attempts are alerted on, but they cannot back a block. On Debian and Ubuntu nginx and PHP both
  run as `www-data`, so the risk is real (on Ubuntu the log is `www-data:adm`, and logrotate
  creates it with `create 0640 www-data adm`). On Rocky Linux nginx runs as `nginx` and PHP-FPM
  as `apache`, which cannot write nginx's log: there v0.4.0 is only being cautious. Changing the
  log's owner by hand is undone at the next rotation. This is planned for v0.4.1. Rocky Linux's default httpd configuration loads modules outside the list
  Shentu knows to be safe, so its Apache logs are always judged `web_user_writable` too; weighing
  those modules is planned for v0.4.1.
- There are no signatures for particular WordPress plugin vulnerabilities yet.
- Scans are still slower than v0.3.0: WordPress about 35% (elapsed time on the Ubuntu VM above),
  TypeScript projects about 20% (user CPU time on a Mac, #92).
- Still open from v0.3.1: CVE-2021-23664's fixed release is reported; `filesize()` on an
  upload's temporary path in WordPress; `markup` not followed through a variable.

## v0.3.1 — 2026-11-16

- Code audit rules: 70 → 127 (PHP 25 → 51, Python 22 → 43, JavaScript and TypeScript
  23 → 33). PHP: WordPress, Laravel, Symfony, Joomla, Drupal, CodeIgniter, Yii and Smarty
  sinks, sockets and HTTP clients, XML DTDs, template strings, crypto keys and shortcodes
  (#76). Python: keyword arguments (`args=`, `search_filter=`, `where=`), ldap3 filters and
  helper flows (#36). JavaScript and TypeScript: Koa and chained Express responses, BSON and
  launder sanitizers, Host-header redirects and SSRF; `.execute(` counts only on a receiver
  that may be a database client (#70).
- The v0.2.5 known false positives are fixed in the engine: TypeORM repository calls in a file
  importing `typeorm` are no MongoDB queries, unless the file uses a MongoDB repository, driver
  or Mongoose (`unless_imports`, #59); `spawn()` and `execFile()` with `shell: true` are reported
  only when the command or its arguments carry input, not the options (several `[[args]]` blocks
  per sink, #62); a Server-Sent Events handler (`Content-Type: text/event-stream` set on every
  path) is no XSS (`unless_content_type`, #58; `unless_at`, #57); `->get_settings()` is Elementor
  widget input only in classes extending `\Elementor\Widget_Base` (#60); a placeholder list built
  by `array_map` with a callback returning a constant is no input (#61);
  `zipfile.ZipFile(request.files[...])` opens the upload's stream, not a path
  (`unless_subscript`, #67).
- `js-ssrf-http-request` now reads the referrer and origin in Koa, hapi and Fetch API spelling
  (`ctx.request.header.referer`, `request.headers.referer`, `request.headers.get('x-callback-url')`;
  not Host), which were missed. Input written into a prepared statement's text is reported once,
  by `php-sqli-prepare-query-text`, instead of also by `php-sqli-string-concat`. The benchmark
  numbers are unchanged.
- Engine: `new URL(a, base)` takes its path and query from `a` when `a` starts with `/` or a
  scheme (#63); method calls on an object of a class in the same file are followed (#64); an
  anchored regex test fixing a value's start (`re.match(re.escape(base) + r'/[a-z]', url)`) is
  a check for redirect and URL rules (#65); a helper returning a string constant is followed
  (#66); `markup` makes an output sink count input only after literal markup (#71); recursive
  cycles are followed until they settle and paid for once, so WordPress files whose calls were
  cut went from 48 to 4 (#72); `route_input = false` for the Host-header rules, and Koa's `ctx`
  in the Express model (#50).
- Survey warns about Apache 2.4.55–2.4.70 with `mod_http2` loaded and `h2` or `h2c` in
  `Protocols` (CVE-2026-119618; upgrade to 2.4.71, or set `Protocols http/1.1` until then)
  (#54). When a file that could load `mod_http2` or turn on h2 cannot be read (no rights, a link
  not trusted), the check is listed as not checked instead of passed over; the warning says it
  can be ignored when the distribution has backported the fix.
- Code audit: a resumed walk cut before its stored position keeps that position, and the
  position is stored by the root's path; vendor, node_modules and WordPress code folders count
  only below the site root; `wp-content/blogs.dir/*/files` and `/var/www/<uploads|files>`
  without a site's index are upload folders; `authorized_key_unparsed` lists the first 20 line
  numbers (#73).
- The hourly and daily reports list SSH logins as not checked when the login logs could not
  be read in full (journald hiding the system's entries from a non-root user, `auth.log` or
  `secure` unreadable, a log cut short). Before, such a run said "nothing new" (#80).
  The reason given is what kept the logs from counting (on a quiet host: a journal with no sshd
  entry and no text auth log), and running as root is advised only when rights were missing; on
  macOS, which keeps sshd's events where Shentu does not read, the report says it has no sshd log
  source there.
- Linux builds no longer send an EDNS(0) record with DNS queries, as glibc does not: some
  DNS servers, VMware's NAT DNS among them, answered such queries without the address, so
  every lookup (OSV, GitHub) failed with "no such host". When a lookup still fails, the daily
  report's Not checked line says to check the host's DNS (#80).
- `block_ip` refuses an IP whose SSH login events come only from text
  logs anyone on the host can write to (`verified` false), or whose logins cannot be read;
  `override_unverified` goes ahead after the operator has checked them, from `shentu chat`
  only. From the Telegram bot it is always refused, at every confirm level.
  The check covers SSH login evidence only: a block based on other logs (syslog, nginx, an
  application log through `log_search`) is not checked and is the operator's to judge.
  On a host whose journald has no sshd entries (text logs only), `block_ip` refuses every IP
  with SSH login events, whatever the date of the lines; such a block cannot be made from
  Telegram, only on the server with `shentu chat` and `override_unverified`. `ssh_logins`
  looks back at most 720 hours, as far as the check (#80). A refusal for login events that may
  be forged names the text logs they are in.
- macOS: binary plists count array and dictionary entries, and UTF-16 strings at 9 bytes a
  character, against the decoding limit; a program path ending in a space is kept as it is;
  a process named on two `ps` lines is marked `parse_error`; `periodic_conf_files` past 16
  files are listed as not read (#80). CI runs `go vet` and `go test` on macOS 15 (#81); no
  macOS binary is published yet.
- Tests build credential-shaped fake values at run time, so the tree has no secret-shaped
  literals (#77).
- Benchmark against v0.3.0: published vulnerabilities 16 of 97 caught (was 15), 1 fixed-release
  false positive (was 0, see below); held-out cases 3 of 30 (was 2), no fixed-release false
  positive; TypeScript cases 1 of 18 with 1 fixed-release false positive
  (n8n), both unchanged.

### Known issues

- CVE-2021-23664 (`@isomorphic-git/cors-proxy`): `js-ssrf-http-request` still reports the
  fixed release. The proxy forwards `req.url` after an allow check the engine does not yet read
  as a sanitizer; reading such checks before a request is planned.
- Scans take longer with the added rules, as each file is run through more rules: WordPress
  about 40–60% depending on the machine (on an Ubuntu VM the code audit went from 73.8 s to
  120.0 s and the daily patrol from 100 s to 144 s, with the same findings and peak RSS),
  TypeScript projects about 43%. The fix at the root is planned after v0.3.1.
- `block_ip`'s check covers SSH login evidence only (see above): a block based on other logs
  is the operator's to judge.
- `php-deserialization-phar-wrapper` still reports `filesize()` on an upload's temporary path
  in WordPress's REST attachments controller: the engine cannot yet tell an upload's
  `tmp_name` from its client-set `name`.
- `markup` does not follow markup put together in a variable first
  (`const h = '<p>' + x; ctx.body = h`).

## v0.3.0 — 2026-11-13

- Windows Server 2022 and 2025, verified on GitHub-hosted windows-2022/2025 runners (amd64;
  arm64 built too): a Windows collector reads the host
  through the Windows APIs only (registry, services, processes, sockets, accounts, scheduled
  tasks, the event log, WMI and the firewall), no PowerShell and no external commands.
- Windows checks: autostart entries (Run keys, services, scheduled tasks, startup folders, WMI
  event subscriptions), RDP without NLA, SMB signing and SMBv1, insecure WinRM, firewall
  profiles, Defender state and exclusions, logon failures and cleared logs.
- Missing Windows updates against Microsoft's monthly security releases (MSRC), with the
  CISA KEV list marking the exploited ones first.
- IIS: web roots from `applicationHost.config`; the code audit reads ASP and ASP.NET pages and
  flags webshells and scripts in upload folders, UTF-16 pages included.
- Two Windows services, `Shentu` (patrol) and `ShentuBot` (Telegram), installed with
  `shentu service install [--bot]` from `%ProgramFiles%\Shentu`; configuration and state in
  `%ProgramData%\Shentu`, open to SYSTEM and Administrators only.
- The `ssh_logins`, `processes`, `accounts_audit` and `log_search` tools work on Windows
  (logon events, process list, local accounts, event logs).
- Failed SSH logins are read from journald first: its ssh and sshd units are labelled by
  journald itself, so a local user cannot forge them. The text logs (`auth.log`, `secure`)
  are read when journald is missing, times out (60 s), or has no sshd entries; anyone on the
  host can write an sshd line to them with `logger`, so `auth_events` is then partial with
  the new reason `unverified_source`, and brute-force findings and patrol SSH alerts carry a
  note saying so.
  A journal that hides the system's entries from a non-root user is no longer reported as
  "no failed logins".
- Amazon Linux 2 and 2023: package vulnerabilities come from Amazon's ALAS advisories
  (the repositories' `updateinfo`, checked against the sha256 in `repomd.xml` and cached),
  Amazon Linux 2's extras topics included. Amazon Linux 1, past its end of life, answers
  "cannot tell". Recorded on an Amazon Linux 2023 VM; Amazon Linux 2 is covered by tests only.
- Alpine Linux: packages from the apk database (OSV), OpenRC services and runlevels,
  `/etc/local.d`, busybox crond (`/etc/crontabs`, `/etc/periodic`) and `/etc/inittab` as
  persistence, and sshd lines of busybox syslog's auth facilities, marked unverified.
  Recorded on an Alpine 3.22 VM, as root and as a user.
- SUSE: openSUSE Leap and Tumbleweed, and SLES, SLED and SLES for SAP (one OSV ecosystem per
  SLE 15 module; the ones OSV does not carry are listed as not queried). Leap is tested with
  a synthetic fixture and SLES on no real host yet.
- The daily report says when a vulnerability check failed or covered only part, and a
  package list that parsed to nothing is "cannot tell" instead of "no vulnerabilities".
- macOS (new, read-only, never with sudo): platform, accounts (dscl), processes, listeners
  (netstat, or lsof when macOS hides sockets), the application firewall, SIP, Gatekeeper,
  FileVault, XProtect, launchd jobs and other persistence, sshd settings, and installed apps
  and Homebrew packages. The OS version is checked against Apple's software update catalog
  (gdmf.apple.com); packages answer "cannot tell", since OSV has no Homebrew ecosystem.
  Tested only with a synthetic fixture (an invented host); not yet verified on a real Mac.
  Login items are not parsed (the Background Task Management store), so macOS persistence is
  always partial.
  periodic.conf and daily/weekly/monthly.local are listed line by line, every line but blanks
  and plain comments (a # line with no quote, $ or backtick: in a heredoc such a line is data
  and runs its commands); they are short. A stock /etc/defaults/periodic.conf is left out, and
  the files periodic_conf_files names are read too.
- A code audit root written with a trailing slash (`/var/www/html/`) or as `/` is no longer
  skipped when an audit resumes inside it. Roots are now cleaned, so the first audit after
  the upgrade does not find the place the last one stopped and walks from the start once.
- sshd settings: a `Match` block inside an included file (`Include sshd_config.d/*.conf`) no
  longer hides the settings that follow the Include in the main file (sshd restores the Match
  state after each Include), so e.g. a later `PermitRootLogin yes` is reported. An Include
  nested more than 4 deep, or past 256 config files, is listed as unread.

### Known issues

- Building from source now needs Go 1.26 or later (was 1.23): the Windows collector uses
  golang.org/x/sys, the second dependency.
- Windows is read-only: `block_ip` and `unblock_ip` are not supported there.
- Windows Server 2019 is best effort: expected to work (the same Windows APIs, build 17763)
  but not verified on GitHub-hosted runners (they offer no 2019 image).
- `shentu setup` does not run on Windows yet; the configuration is written by hand.
- The Windows binary is not code-signed and there is no MSI; SmartScreen or an antivirus may
  warn about it.

## v0.2.5 — 2026-11-13

- `app_code_audit` follows calls across files: input read in one file and used in a sink
  of another is reported at the sink, with the file it came from.
- Framework route models: the parameters of WordPress hooks, shortcodes and REST routes,
  Laravel routes, Django URLs, Flask and FastAPI views and Express handlers are input,
  also when the route is registered in another file.
- New rule classes: LDAP injection, NoSQL operator injection, dangerous file uploads,
  weak cryptography and hard-coded credentials; TypeScript files are checked with the
  JavaScript rules.
- Audits keep their results between runs, so a large application is covered over a few
  patrols instead of one.
- The audit sizes itself to the server: heap at most min(1 GiB, 25% of available memory,
  50% of the service's cgroup), workers from the CPU count and the load.
- Fewer false positives: `wp_send_json` output, `JSON_HEX_TAG` data blocks, MongoDB queries
  on objects that are not collections, and Django `_meta.get_field` checks.

### Known issues

- An audit spread over several runs can still report a few findings that differ from one
  run without a time limit; a fix is in progress.
- `php-deserialization-phar-wrapper` reports `filesize()` on an upload's temporary path in
  WordPress's REST attachments controller, a false positive: the path is PHP's own, but the
  engine cannot yet tell an upload's `tmp_name` from its client-set `name`.
- js-nosqli-mongo-query reports TypeORM repository calls on SQL databases (find/findOne whose
  options hold a where built from request values, e.g. n8n's public API and credential
  lookups) as MongoDB queries; TypeORM sends those values as SQL parameters, so these are
  false positives, to be told apart by a TypeORM-aware receiver check in v0.2.6.
- `js-cmdi-spawn-shell` still reports `spawn()` and `execFile()` calls whose command and
  arguments are fixed when only the options (such as `cwd` or `env`) carry request values.
- js-xss-response has no Server-Sent Events exception: res.write("data: " + value) in a
  text/event-stream handler is reported as XSS (a false positive), and nothing is missed
  because of SSE; telling streams apart by the handler's Content-Type is planned for v0.2.6.
- `->get_settings()` counts as Elementor widget input in every class, so `WP_Widget::get_settings()`
  and WooCommerce `WC_Settings_Page::get_settings()` values (saved by administrators) are reported
  too. Limiting the source to classes extending `\Elementor\Widget_Base` needs class-scoped sources
  in the engine (planned for v0.2.6). Values read through ->get_settings() can also be followed
  into WordPress admin field definitions and into a few SQL sinks that are already guarded (an
  isset() check, or a value bound through $wpdb->prepare() inside ORDER BY FIELD()), which gives
  extra false positives there. Narrowing the source to Elementor widgets is planned for v0.2.6.
- In `$wpdb->prepare()`/`->prepare()` formats, a placeholder list built by a callback that returns
  a constant (`implode(',', array_map(fn($v) => '%d', $ids))`, or the same with
  `function ($v) { return '%d'; }`) is still treated as input and reported when `$ids` comes from
  the request. `array_fill(0, count($ids), '%d')` and `sizeof()` are recognised. Reading a callback's
  return value needs an engine change (planned for v0.2.6).
- `python-path-traversal-send-file` reports `zipfile.ZipFile(request.files[...])`, which opens the
  uploaded stream rather than a path, a false positive. Telling a request's file stream from a
  client-set file name inside one argument needs an engine change (planned for v0.2.6).

## v0.2.4 — 2026-11-09

- Rules move to their own format, checked in CI, starting with 33 rules.
- `accounts_audit` reports shared SSH keys, `ld.so.preload` and PAM modules that belong
  to no package.
- `processes` flags cryptominers.
- Patrol reports one line per webshell.

## v0.2.3 — 2026-11-09

- `app_code_audit`: an offline audit of the applications' own files.

## v0.2.2 — 2026-11-08

- `package_vulns` reports each actively exploited CVE once.

## v0.2.1 — 2026-11-08

- `shentu bot`: talk to Shentu from Telegram, with guarded pairing and four ranges of levels.
- Usage tracking and an optional monthly AI budget.
- Round 2 of the model comparison: 14 models, 11 scenarios.

## v0.2.0 — 2026-11-07

- One command from install to running: a guided setup.
- Site survey and an application dependency scan.

## v0.1.1 — 2026-11-07

- `package_vulns` marks actively exploited vulnerabilities (CISA KEV).
- Slack and Discord webhooks.
- Security invariant tests, a prompt-injection suite and govulncheck before each release.

## v0.1.0 — 2026-11-07

- First release: `shentu chat` and `shentu patrol` for Linux servers, with `shentu setup`
  for a local model or an API key.
