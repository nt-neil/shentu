package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// php.net's releases of 2026-11-19: 8.2.36 (12 CVEs), 8.3.37 (13: and
// Session 129481), 8.4.28 (14: and DOM 129501), 8.5.13 and 8.6.0 (18: and
// Core 129474, 129182, URI 48841, 129438).
func TestPHPAffected(t *testing.T) {
	all := slices.Concat(phpFPMCVEs, phpStatusCVE, phpCGICVE, phpOtherCVEs)
	count := map[string]int{
		"8.2.35": 12, "8.2.36": 0, "8.3.36": 13, "8.3.37": 0, "8.4.27": 14, "8.4.28": 0,
		"8.5.12": 18, "8.5.13": 0, "8.6.0": 0, "8.7.1": 0, "9.0.0": 0,
		"8.4.20-1+deb.sury.org+1": 14, "8.3.6-0ubuntu0.24.04.5": 13, "1:8.2.20-1.el9.remi": 12,
		"8.1.2": 0, "7.4.33": 0, "": 0, "8.3": 0, "8.3.x": 0, "8.3.0RC1": 0,
	}
	for v, want := range count {
		rel, _ := phpRelease(v)
		if got := phpAffected(rel, all); len(got) != want {
			t.Errorf("%q: %d CVEs %v, want %d", v, len(got), got, want)
		}
	}
	rel, _ := phpRelease("8.2.10")
	for _, id := range []string{"CVE-2026-129481", "CVE-2026-129501", "CVE-2026-129474", "CVE-2026-48841"} {
		if slices.Contains(phpAffected(rel, all), id) {
			t.Errorf("8.2 is not in %s", id)
		}
	}
	rel, _ = phpRelease("8.4.1")
	if got := phpAffected(rel, all); !slices.Contains(got, "CVE-2026-129501") || slices.Contains(got, "CVE-2026-129474") {
		t.Errorf("8.4: %v", got)
	}
}

// phpHost is a hand-written host under a temporary root: PHP binaries
// (only the bytes the version is read from), FPM pools, web server files.
type phpHost struct {
	t     *testing.T
	root  string
	run   map[string]string // "/usr/bin/dpkg-query -S /usr/sbin/php-fpm8.4" → its output
	procs []hostenv.Process
	known bool
}

func newPHPHost(t *testing.T) *phpHost {
	h := &phpHost{t: t, root: t.TempDir(), run: map[string]string{}, known: true}
	run, procs, win := phpRun, phpProcs, phpWindows
	t.Cleanup(func() { phpRun, phpProcs, phpWindows = run, procs, win })
	phpWindows = false
	withHost(t, &hostenv.Live{Remap: map[string]string{"/": h.root}}) // the host's files are under h.root
	phpRun = func(_ context.Context, argv []string) ([]byte, error) {
		if out, ok := h.run[strings.Join(argv, " ")]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("not found")
	}
	phpProcs = func() ([]hostenv.Process, bool) { return h.procs, h.known }
	return h
}

func (h *phpHost) file(p, content string) {
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// bin writes a PHP binary that names version in its X-Powered-By header.
func (h *phpHost) bin(p, version string) {
	h.file(p, "\x7fELF\x02\x01\x01\x00padding\x00X-Powered-By: PHP/"+version+"\x00PHP_SELF\x00")
}

// dpkg says package pkg, at version, holds the binary at p.
func (h *phpHost) dpkg(p, pkg, version string) {
	h.run[strings.Join(hostenv.DpkgSearchArgv(p), " ")] = pkg + ": " + p + "\n"
	h.run[strings.Join(hostenv.DpkgStatusArgv(pkg), " ")] = "installed " + version
}

// rpm says package pkg, at version, from vendor, holds the binary at p.
func (h *phpHost) rpm(p, pkg, version, vendor string) {
	h.run[strings.Join(hostenv.RPMOwnerArgv(p), " ")] = pkg + " " + version + " " + vendor + "\n"
}

func (h *phpHost) running(name, exe string) {
	h.procs = append(h.procs, hostenv.Process{PID: 100 + len(h.procs), Name: name, Exe: exe, ExeKnown: exe != ""})
}

func phpKeys(r []Risk) []string {
	var out []string
	for _, x := range r {
		out = append(out, x.Key)
	}
	return out
}

func phpFind(r []Risk, key string) *Risk {
	for i := range r {
		if r[i].Key == key {
			return &r[i]
		}
	}
	return nil
}

func TestPHPRisksFPM(t *testing.T) {
	h := newPHPHost(t)
	// Debian 12 with deb.sury.org's php8.4: the distribution has no php8.4,
	// so the package scan has nothing to compare it with.
	h.bin("/usr/sbin/php-fpm8.4", "8.4.20")
	h.dpkg("/usr/sbin/php-fpm8.4", "php8.4-fpm", "8.4.20-1+deb.sury.org+1")
	h.file("/etc/php/8.4/fpm/pool.d/www.conf", "[www]\nlisten = /run/php/php8.4-fpm.sock\n;pm.status_path = /status\n")
	h.running("php-fpm8.4", "/usr/sbin/php-fpm8.4")
	r := phpRisks(context.Background())
	fpm := phpFind(r, "php8.4:CVE-2026-129291")
	if fpm == nil || fpm.Severity != "warning" || Unchecked(*fpm) {
		t.Fatalf("FPM running: %v", phpKeys(r))
	}
	for _, s := range []string{"PHP 8.4.20", "php-fpm", "CVE-2026-129291 and CVE-2026-129289", "8.4.28", "deb.sury.org"} {
		if !strings.Contains(fpm.Summary, s) {
			t.Errorf("FPM summary lacks %q: %s", s, fpm.Summary)
		}
	}
	if strings.Contains(fpm.Summary, "129292") {
		t.Errorf("no status page, yet 129292: %s", fpm.Summary)
	}
	// The status page is commented out: no 129292; not a php-cgi: no 129538.
	if phpFind(r, "php8.4:CVE-2026-129292") != nil || phpFind(r, "php8.4:CVE-2026-129538") != nil {
		t.Errorf("status or CGI without them: %v", phpKeys(r))
	}
	// The others, one line by version: 8.4 has DOM's, not 8.5's Core and URI ones.
	other := phpFind(r, "php8.4:CVE-2026-129496")
	if other == nil || len(r) != 2 {
		t.Fatalf("version line: %v", phpKeys(r))
	}
	if !strings.Contains(other.Summary, "CVE-2026-129501") || strings.Contains(other.Summary, "129474") ||
		strings.Contains(other.Summary, "129291") || strings.Contains(other.Summary, "129538") {
		t.Errorf("version line: %s", other.Summary)
	}

	// Installed, not running: the FPM ones are not reported.
	h.procs = nil
	if r := phpRisks(context.Background()); phpFind(r, "php8.4:CVE-2026-129291") != nil || phpFind(r, "php8.4:CVE-2026-129496") == nil {
		t.Errorf("FPM not running: %v", phpKeys(r))
	}
	// Which processes run is not known: not "not running".
	h.known = false
	r = phpRisks(context.Background())
	if u := phpFind(r, uncheckedPrefix+"php8.4:CVE-2026-129291"); u == nil || u.Severity != "info" || !strings.Contains(u.Summary, "129289") {
		t.Errorf("processes unknown: %v", phpKeys(r))
	}
}

func TestPHPRisksStatusPage(t *testing.T) {
	setup := func(t *testing.T, pool string) *phpHost {
		h := newPHPHost(t)
		h.bin("/usr/local/sbin/php-fpm", "8.3.30") // the official image's place, no package
		h.file("/usr/local/etc/php-fpm.d/www.conf", pool)
		h.running("php-fpm", "/usr/local/sbin/php-fpm")
		return h
	}
	status := func(r []Risk) bool { return phpFind(r, "php8.3:CVE-2026-129292") != nil }
	// FastCGI on every address: the status page is reachable from outside.
	setup(t, "[www]\nlisten = 9000\npm.status_path = /status\n")
	if r := phpRisks(context.Background()); !status(r) || !strings.Contains(phpFind(r, "php8.3:CVE-2026-129292").Summary, "/status") {
		t.Errorf("listen 9000: %v", phpKeys(r))
	}
	for _, pool := range []string{
		"[www]\nlisten = 127.0.0.1:9000\npm.status_path = /status\n",
		"[www]\nlisten = /run/php-fpm.sock\npm.status_path = /status\n",
		"[www]\nlisten = 0.0.0.0:9000\n",                                                  // no status page
		"[www]\nlisten = 9000\npm.status_path = /status\npm.status_listen = [::1]:9001\n", // a local status socket
	} {
		setup(t, pool)
		if r := phpRisks(context.Background()); status(r) {
			t.Errorf("not exposed, yet 129292 (%q): %v", pool, phpKeys(r))
		}
	}
	setup(t, "[www]\nlisten = 127.0.0.1:9000\npm.status_listen = 0.0.0.0:9001\npm.status_path = /fpm-status\n")
	if !status(phpRisks(context.Background())) {
		t.Error("status_listen on every address")
	}

	// A local socket, but nginx passes the status path on to it.
	h := setup(t, "[www]\nlisten = /run/php-fpm.sock\npm.status_path = /status\n")
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  listen 80;\n  location ~ \\.php$ { fastcgi_pass unix:/run/php-fpm.sock; }\n"+
		"  location ~ ^/(status|ping)$ {\n    include fastcgi_params;\n    fastcgi_pass unix:/run/php-fpm.sock;\n  }\n}\n")
	if !status(phpRisks(context.Background())) {
		t.Error("nginx passes /status on")
	}
	// The same, allowed to the host only.
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  location = /status {\n    allow 127.0.0.1;\n    deny all;\n"+
		"    fastcgi_pass unix:/run/php-fpm.sock;\n  }\n}\n")
	if status(phpRisks(context.Background())) {
		t.Error("nginx: deny all")
	}
	// Kept to nginx itself (internal): not reachable from outside either.
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  location /status {\n    internal;\n"+
		"    fastcgi_pass unix:/run/php-fpm.sock;\n  }\n}\n")
	if status(phpRisks(context.Background())) {
		t.Error("nginx: internal")
	}
	// A location that only serves .php files does not reach /status.
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  location ~ \\.php$ { fastcgi_pass unix:/run/php-fpm.sock; }\n}\n")
	if status(phpRisks(context.Background())) {
		t.Error("nginx: .php only")
	}
	// Apache: a Location that hands the path to FPM, then one kept local.
	h.file("/etc/nginx/conf.d/site.conf", "")
	h.file("/etc/apache2/sites-enabled/site.conf", "<VirtualHost *:80>\n<Location \"/status\">\n  SetHandler \"proxy:unix:/run/php-fpm.sock|fcgi://localhost\"\n</Location>\n</VirtualHost>\n")
	if !status(phpRisks(context.Background())) {
		t.Error("apache passes /status on")
	}
	h.file("/etc/apache2/sites-enabled/site.conf", "<LocationMatch \"^/(status|ping)$\">\n  Require local\n  SetHandler \"proxy:fcgi://127.0.0.1:9000\"\n</LocationMatch>\n")
	if status(phpRisks(context.Background())) {
		t.Error("apache: Require local")
	}
	h.file("/etc/apache2/sites-enabled/site.conf", "ProxyPassMatch ^/(status|ping)$ fcgi://127.0.0.1:9000\n")
	if !status(phpRisks(context.Background())) {
		t.Error("apache: ProxyPassMatch")
	}
	// FPM not running: no 129292 either.
	h.procs = nil
	if status(phpRisks(context.Background())) {
		t.Error("status page of an FPM not running")
	}
}

func TestPHPRisksCGI(t *testing.T) {
	h := newPHPHost(t)
	h.bin("/usr/bin/php-cgi8.2", "8.2.30")
	h.bin("/usr/bin/php8.2", "8.2.30")
	h.dpkg("/usr/bin/php-cgi8.2", "php8.2-cgi", "8.2.30-1~deb12u1")
	h.dpkg("/usr/bin/php8.2", "php8.2-cli", "8.2.30-1~deb12u1")
	// Installed, not in use: only the version line, once for both binaries.
	r := phpRisks(context.Background())
	if len(r) != 1 || r[0].Key != "php8.2:CVE-2026-129496" || strings.Contains(r[0].Summary, "129538") {
		t.Fatalf("php-cgi not running: %v", phpKeys(r))
	}
	if !strings.Contains(r[0].Summary, "/usr/bin/php-cgi8.2") || !strings.Contains(r[0].Summary, "/usr/bin/php8.2") {
		t.Errorf("binaries not named: %s", r[0].Summary)
	}
	h.running("php-cgi8.2", "/usr/bin/php-cgi8.2")
	cgi := phpFind(phpRisks(context.Background()), "php8.2:CVE-2026-129538")
	if cgi == nil || cgi.Severity != "warning" || !strings.Contains(cgi.Summary, "PATH_INFO") || !strings.Contains(cgi.Summary, "8.2.36") {
		t.Errorf("php-cgi running: %+v", cgi)
	}
	// The distribution backported the CGI fix (the version stays): its changelog names it.
	h.file("/usr/share/doc/php8.2-cgi/changelog.Debian.gz", phpGzip(t, "php8.2 (8.2.30-1~deb12u2) bookworm-security\n  * Fix CVE-2026-129538\n"))
	if r := phpRisks(context.Background()); phpFind(r, "php8.2:CVE-2026-129538") != nil {
		t.Errorf("backported: %v", phpKeys(r))
	}
}

func TestPHPRisksOrigins(t *testing.T) {
	// Fixed versions, whatever the source.
	for _, v := range []string{"8.2.36", "8.3.37", "8.4.28", "8.5.13", "8.6.0", "8.6.2"} {
		h := newPHPHost(t)
		h.bin("/usr/sbin/php-fpm", v)
		h.running("php-fpm", "/usr/sbin/php-fpm")
		if r := phpRisks(context.Background()); len(r) != 0 {
			t.Errorf("%s: %v", v, phpKeys(r))
		}
	}
	// Remi's repository on RHEL (a software collection under /opt/remi).
	h := newPHPHost(t)
	h.bin("/opt/remi/php85/root/usr/sbin/php-fpm", "8.5.12")
	h.rpm("/opt/remi/php85/root/usr/sbin/php-fpm", "php85-php-fpm", "0:8.5.12-1.el9.remi", "Remi's RPM repository")
	h.run[strings.Join(hostenv.RPMChangelogArgv("php85-php-fpm"), " ")] = "* Tue Nov 18 2026 Packager - 8.5.12-1\n- update to 8.5.12\n"
	r := phpRisks(context.Background())
	if v := phpFind(r, "php8.5:CVE-2026-129496"); v == nil || !strings.Contains(v.Summary, "Remi") || !strings.Contains(v.Summary, "CVE-2026-129474") ||
		!strings.Contains(v.Summary, "8.5.13") {
		t.Errorf("remi 8.5: %v", r)
	}
	// Ubuntu with the ondrej PPA, two branches side by side: one line each.
	h = newPHPHost(t)
	h.bin("/usr/bin/php8.3", "8.3.30")
	h.dpkg("/usr/bin/php8.3", "php8.3-cli", "8.3.30-1+ubuntu24.04.1+deb.sury.org+1")
	h.bin("/usr/bin/php8.4", "8.4.20")
	h.dpkg("/usr/bin/php8.4", "php8.4-cli", "8.4.20-1+ubuntu24.04.1+deb.sury.org+1")
	if r := phpRisks(context.Background()); len(r) != 2 || phpFind(r, "php8.3:CVE-2026-129496") == nil || phpFind(r, "php8.4:CVE-2026-129496") == nil {
		t.Errorf("two branches: %v", phpKeys(r))
	}
	// A branch php.net no longer fixes: from the distribution, its advisories
	// (the package scan) speak for it; built from source, nothing does.
	h = newPHPHost(t)
	h.bin("/usr/bin/php8.1", "8.1.2")
	h.dpkg("/usr/bin/php8.1", "php8.1-cli", "8.1.2-1ubuntu2.20")
	if r := phpRisks(context.Background()); len(r) != 0 {
		t.Errorf("distribution 8.1: %v", phpKeys(r))
	}
	h = newPHPHost(t)
	h.bin("/usr/local/bin/php", "7.4.33")
	if r := phpRisks(context.Background()); len(r) != 1 || r[0].Key != "php7.4:eol" || r[0].Severity != "info" {
		t.Errorf("source 7.4: %v", r)
	}
	// Not PHP binaries: scripts and tools next to them; no PHP at all.
	h = newPHPHost(t)
	h.file("/usr/bin/php-config8.3", "#! /bin/sh\necho X-Powered-By\n")
	h.file("/usr/bin/phpize8.3", "#! /bin/sh\n")
	if r := phpRisks(context.Background()); len(r) != 0 {
		t.Errorf("no PHP: %v", phpKeys(r))
	}
}

// The package scan covers a distribution's own packages; the line says when
// it does not (deb.sury.org, the PPA, Remi, no package, IIS).
func TestPHPRisksNotCoveredNote(t *testing.T) {
	const note = "which the package scan does not cover"
	for _, c := range []struct {
		why, bin, binVersion, pkg, version string
		covered                            bool
	}{
		{"deb.sury.org", "/usr/bin/php8.4", "8.4.20", "php8.4-cli", "8.4.20-1+deb.sury.org+1", false},
		{"ondrej PPA", "/usr/bin/php8.3", "8.3.30", "php8.3-cli", "8.3.30-1+ubuntu24.04.1+deb.sury.org+1", false},
		{"no package", "/usr/local/bin/php", "8.3.30", "", "", false},
		{"Debian", "/usr/bin/php8.2", "8.2.30", "php8.2-cli", "8.2.30-1~deb12u1", true},
		{"Ubuntu", "/usr/bin/php8.3", "8.3.6", "php8.3-cli", "8.3.6-0ubuntu0.24.04.5", true},
	} {
		h := newPHPHost(t)
		h.bin(c.bin, c.binVersion)
		if c.pkg != "" {
			h.dpkg(c.bin, c.pkg, c.version)
		}
		r := phpRisks(context.Background())
		if len(r) != 1 || strings.Contains(r[0].Summary, note) == c.covered {
			t.Errorf("%s: covered %v: %v", c.why, c.covered, r)
		}
	}
	h := newPHPHost(t)
	h.bin("/opt/remi/php83/root/usr/bin/php", "8.3.30")
	h.rpm("/opt/remi/php83/root/usr/bin/php", "php83-php-cli", "0:8.3.30-1.el9.remi", "Remi's RPM repository")
	if r := phpRisks(context.Background()); len(r) != 1 || !strings.Contains(r[0].Summary, "Remi's repository, "+note) {
		t.Errorf("remi: %v", r)
	}
}

func TestPHPRisksWindowsIIS(t *testing.T) {
	newPHPHost(t)
	phpWindows = true
	fcgi, read := phpWinFastCGI, phpReadBin
	defer func() { phpWinFastCGI, phpReadBin = fcgi, read }()
	files := map[string]string{`C:\PHP\php8ts.dll`: "MZ\x00X-Powered-By: PHP/8.3.20\x00"}
	phpReadBin = func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	phpWinFastCGI = func() ([]string, error) { return []string{`C:\PHP\php-cgi.exe`, `C:\Python\python.exe`}, nil }
	r := phpRisks(context.Background())
	cgi := phpFind(r, "php8.3:CVE-2026-129538")
	if cgi == nil || cgi.Severity != "warning" || !strings.Contains(cgi.Summary, "IIS") || !strings.Contains(cgi.Summary, "package scan does not cover") ||
		phpFind(r, "php8.3:CVE-2026-129496") == nil {
		t.Fatalf("IIS php-cgi: %v", r)
	}
	if phpFind(r, "php8.3:CVE-2026-129291") != nil {
		t.Errorf("no FPM on Windows: %v", phpKeys(r))
	}
	// The DLL not there: the version is read from php-cgi.exe itself.
	files = map[string]string{`D:\php83\php-cgi.exe`: "MZ\x00X-Powered-By: PHP/8.3.37\x00"}
	phpWinFastCGI = func() ([]string, error) { return []string{`D:\php83\php-cgi.exe`}, nil }
	if r := phpRisks(context.Background()); len(r) != 0 {
		t.Errorf("fixed 8.3.37: %v", r)
	}
	// php-cgi.exe whose version cannot be read: not known.
	files = map[string]string{}
	if r := phpRisks(context.Background()); len(r) != 1 || !Unchecked(r[0]) || !strings.Contains(r[0].Summary, `D:\php83\php-cgi.exe`) {
		t.Errorf("version unread: %v", r)
	}
	// applicationHost.config unreadable.
	phpWinFastCGI = func() ([]string, error) { return nil, errors.New("access denied") }
	if r := phpRisks(context.Background()); len(r) != 1 || !Unchecked(r[0]) {
		t.Errorf("config unread: %v", r)
	}
}

func TestParseIISFastCGI(t *testing.T) {
	cfg := "\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n<system.webServer>\n<fastCgi>\n" +
		"  <application fullPath=\"%SystemDrive%\\PHP\\php-cgi.exe\" maxInstances=\"4\" />\n" +
		"  <application fullPath=\"E:\\tools\\php-cgi.exe\" arguments=\"-d x=1\" />\n" +
		"</fastCgi>\n</system.webServer>\n</configuration>\n"
	got, err := hostenv.ParseIISFastCGI([]byte(cfg), `D:\Windows`)
	if err != nil || !slices.Equal(got, []string{`D:\PHP\php-cgi.exe`, `E:\tools\php-cgi.exe`}) {
		t.Errorf("%q %v", got, err)
	}
	if got, err := hostenv.ParseIISFastCGI([]byte("<configuration><system.webServer/></configuration>"), `C:\Windows`); err != nil || len(got) != 0 {
		t.Errorf("no FastCGI: %q %v", got, err)
	}
}

func phpGzip(t *testing.T, text string) string {
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
