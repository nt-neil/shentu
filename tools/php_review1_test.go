package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #195 review 1. Hand-written hosts under t.TempDir, as in php_test.go.

// N-1: a binary naming several different versions is not taken by its first.
func TestPHPReview1SeveralVersions(t *testing.T) {
	for _, order := range [][2]string{{"8.3.37", "8.3.30"}, {"8.3.30", "8.3.37"}} {
		h := newPHPHost(t)
		h.file("/usr/sbin/php-fpm8.3", "\x7fELF\x00X-Powered-By: PHP/"+order[0]+"\x00pad\x00X-Powered-By: PHP/"+order[1]+"\x00")
		h.running("php-fpm8.3", "/usr/sbin/php-fpm8.3")
		r := phpRisks(context.Background())
		u := phpFind(r, uncheckedPrefix+"php:version")
		if len(r) != 1 || u == nil || !strings.Contains(u.Summary, "8.3.37") || !strings.Contains(u.Summary, "8.3.30") {
			t.Errorf("%v: %v", order, r)
		}
	}
	// The same version twice is one version.
	h := newPHPHost(t)
	h.file("/usr/sbin/php-fpm8.3", "\x7fELF\x00X-Powered-By: PHP/8.3.30\x00X-Powered-By: PHP/8.3.30\x00")
	if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2026-129496") == nil {
		t.Errorf("one version twice: %v", phpKeys(r))
	}
	// Windows: in php8ts.dll too.
	newPHPHost(t)
	phpWindows = true
	fcgi, read := phpWinFastCGI, phpReadBin
	defer func() { phpWinFastCGI, phpReadBin = fcgi, read }()
	phpWinFastCGI = func() ([]string, error) { return []string{`C:\PHP\php-cgi.exe`}, nil }
	phpReadBin = func(p string) ([]byte, error) {
		if p == `C:\PHP\php8ts.dll` {
			return []byte("MZ\x00X-Powered-By: PHP/8.3.37\x00X-Powered-By: PHP/8.3.20\x00"), nil
		}
		return nil, os.ErrNotExist
	}
	if r := phpRisks(context.Background()); len(r) != 1 || !Unchecked(r[0]) || !strings.Contains(r[0].Summary, "several versions") {
		t.Errorf("Windows: %v", r)
	}
}

// N-2: a program with no version, or one read only up to phpBinMax, is not
// skipped; a script still is.
func TestPHPReview1NoVersion(t *testing.T) {
	h := newPHPHost(t)
	h.file("/usr/local/sbin/php-fpm", "\x7fELF\x02\x01\x01\x00no header here\x00")
	h.running("php-fpm", "/usr/local/sbin/php-fpm")
	if r := phpRisks(context.Background()); len(r) != 1 || !Unchecked(r[0]) || !strings.Contains(r[0].Summary, "/usr/local/sbin/php-fpm (no version found)") {
		t.Errorf("ELF without a version: %v", r)
	}
	max := phpBinMax
	defer func() { phpBinMax = max }()
	phpBinMax = 64
	h = newPHPHost(t)
	h.file("/usr/bin/php8.3", "#!"+strings.Repeat("x", 100)+"\x00X-Powered-By: PHP/8.3.30\x00")
	if r := phpRisks(context.Background()); len(r) != 1 || !Unchecked(r[0]) {
		t.Errorf("version past the read limit: %v", r)
	}
	phpBinMax = max
	h = newPHPHost(t)
	h.file("/usr/bin/php-wrapper", "#!/bin/sh\nexec /usr/bin/php8.3 \"$@\"\n")
	h.file("/usr/bin/php", "#!/bin/sh\nexec /usr/bin/php8.3 \"$@\"\n")
	if r := phpRisks(context.Background()); len(r) != 0 {
		t.Errorf("a shell wrapper: %v", r)
	}
}

// N-3: [www] of 8.2 is not [www] of 8.3; each branch reads its own pools,
// and the answer is the same every time.
func TestPHPReview1PoolsByBranch(t *testing.T) {
	setup := func(t *testing.T, pool82, pool83 string, run ...string) {
		h := newPHPHost(t)
		h.bin("/usr/sbin/php-fpm8.2", "8.2.30")
		h.bin("/usr/sbin/php-fpm8.3", "8.3.30")
		h.file("/etc/php/8.2/fpm/pool.d/www.conf", pool82)
		h.file("/etc/php/8.3/fpm/pool.d/www.conf", pool83)
		for _, b := range run {
			h.running("php-fpm"+b, "/usr/sbin/php-fpm"+b)
		}
	}
	for i := 0; i < 30; i++ {
		// 8.2's pool is open, 8.3's has the status page on a socket; only 8.3 runs.
		setup(t, "[www]\nlisten = 0.0.0.0:9002\n", "[www]\nlisten = /run/php/php8.3-fpm.sock\npm.status_path = /status\n", "8.3")
		if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2026-129292") != nil {
			t.Fatalf("run %d: 8.2's listen taken for 8.3's pool: %v", i, phpKeys(r))
		}
		// 8.3's pool is open with the page, 8.2's [www] has neither: 8.3 is reported.
		setup(t, "[www]\nlisten = /run/php/php8.2-fpm.sock\n", "[www]\nlisten = 9000\npm.status_path = /status\n", "8.3")
		if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2026-129292") == nil {
			t.Fatalf("run %d: 8.3's open status page lost: %v", i, phpKeys(r))
		}
		// 8.2's page is open, 8.3 runs alone: not 8.3's; 8.2 running: 8.2's.
		setup(t, "[www]\nlisten = 9000\npm.status_path = /status\n", "[www]\nlisten = /run/php/php8.3-fpm.sock\n", "8.3")
		if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2026-129292") != nil {
			t.Fatalf("run %d: 8.2's page taken for 8.3: %v", i, phpKeys(r))
		}
		setup(t, "[www]\nlisten = 9000\npm.status_path = /status\n", "[www]\nlisten = /run/php/php8.3-fpm.sock\n", "8.2", "8.3")
		if r := phpRisks(context.Background()); phpFind(r, "php8.2:CVE-2026-129292") == nil || phpFind(r, "php8.3:CVE-2026-129292") != nil {
			t.Fatalf("run %d: both running: %v", i, phpKeys(r))
		}
	}
}

// N-3: pools of one name in two shared files are two pools.
func TestPHPReview1PoolsByFile(t *testing.T) {
	for i := 0; i < 30; i++ {
		h := newPHPHost(t)
		h.bin("/usr/sbin/php-fpm", "8.3.30")
		h.running("php-fpm", "/usr/sbin/php-fpm")
		h.file("/etc/php-fpm.d/a.conf", "[www]\nlisten = /run/php-fpm/a.sock\npm.status_path = /status\n")
		h.file("/etc/php-fpm.d/b.conf", "[www]\nlisten = 0.0.0.0:9000\n")
		if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2026-129292") != nil {
			t.Fatalf("run %d: b.conf's listen taken for a.conf's pool: %v", i, phpKeys(r))
		}
	}
}

// statusHost is an FPM with a status page on a local socket, for the web
// server cases.
func statusHost(t *testing.T) *phpHost {
	h := newPHPHost(t)
	h.bin("/usr/local/sbin/php-fpm", "8.3.30")
	h.file("/usr/local/etc/php-fpm.d/www.conf", "[www]\nlisten = /run/php-fpm.sock\npm.status_path = /status\n")
	h.running("php-fpm", "/usr/local/sbin/php-fpm")
	return h
}

func statusKey(r []Risk) string {
	switch {
	case phpFind(r, "php8.3:CVE-2026-129292") != nil:
		return "reported"
	case phpFind(r, uncheckedPrefix+"php8.3:CVE-2026-129292") != nil:
		return "unknown"
	}
	return "no"
}

// N-4: a restriction commented out does not count; neither does a commented
// fastcgi_pass; a # inside quotes is not a comment.
func TestPHPReview1Comments(t *testing.T) {
	for _, c := range []struct{ why, file, conf, want string }{
		{"nginx: deny all commented out", "/etc/nginx/conf.d/s.conf",
			"server {\n  location = /status {\n    # allow 127.0.0.1;\n    # deny all;\n    fastcgi_pass unix:/run/php-fpm.sock;\n  }\n}\n", "reported"},
		{"nginx: deny all after a comment on its line", "/etc/nginx/conf.d/s.conf",
			"server {\n  location = /status { fastcgi_pass unix:/run/php-fpm.sock; # deny all;\n  }\n}\n", "reported"},
		{"nginx: fastcgi_pass commented out", "/etc/nginx/conf.d/s.conf",
			"server {\n  location = /status {\n    # fastcgi_pass unix:/run/php-fpm.sock;\n    return 404;\n  }\n}\n", "no"},
		{"nginx: # in quotes", "/etc/nginx/conf.d/s.conf",
			"server {\n  location = /status {\n    fastcgi_pass unix:/run/php-fpm.sock;\n    add_header X-Note \"#1\"; deny all;\n  }\n}\n", "no"},
		{"nginx: # in single quotes", "/etc/nginx/conf.d/s.conf",
			"server {\n  location = /status {\n    fastcgi_pass unix:/run/php-fpm.sock;\n    add_header X-Note '#1'; deny all;\n  }\n}\n", "no"},
		{"apache: Require local commented out", "/etc/apache2/sites-enabled/s.conf",
			"<Location \"/status\">\n  #Require local\n  SetHandler \"proxy:unix:/run/php-fpm.sock|fcgi://localhost\"\n</Location>\n", "reported"},
		{"apache: SetHandler commented out", "/etc/apache2/sites-enabled/s.conf",
			"<Location \"/status\">\n  # SetHandler \"proxy:unix:/run/php-fpm.sock|fcgi://localhost\"\n</Location>\n", "no"},
	} {
		h := statusHost(t)
		h.file(c.file, c.conf)
		if got := statusKey(phpRisks(context.Background())); got != c.want {
			t.Errorf("%s: %s, want %s", c.why, got, c.want)
		}
	}
}

// N-5: cPanel's ea-php and CloudLinux's alt-php are found; an rpm's vendor
// says whether a distribution speaks for it (IUS does not).
func TestPHPReview1HostingLayouts(t *testing.T) {
	for _, bin := range []string{"/opt/cpanel/ea-php83/root/usr/bin/php", "/opt/cpanel/ea-php83/root/usr/sbin/php-fpm",
		"/opt/alt/php83/usr/bin/php", "/opt/alt/php83/usr/sbin/php-fpm"} {
		h := newPHPHost(t)
		h.bin(bin, "8.3.30")
		if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2026-129496") == nil {
			t.Errorf("%s: %v", bin, phpKeys(r))
		}
	}
	h := newPHPHost(t)
	h.bin("/opt/cpanel/ea-php83/root/usr/bin/php", "8.3.30")
	h.rpm("/opt/cpanel/ea-php83/root/usr/bin/php", "ea-php83-php-cli", "0:8.3.30-1.el9", "cPanel, L.L.C.")
	if r := phpRisks(context.Background()); len(r) != 1 || !strings.Contains(r[0].Summary, "cPanel, L.L.C., which the package scan does not cover") {
		t.Errorf("cPanel vendor: %v", r)
	}
	for vendor, want := range map[string]bool{"IUS": true, "(none)": true, "CloudLinux": true, "Rocky Enterprise Software Foundation": false,
		"Red Hat, Inc.": false, "AlmaLinux": false} {
		h := newPHPHost(t)
		h.bin("/usr/bin/php", "7.4.33")
		h.rpm("/usr/bin/php", "php74-cli", "0:7.4.33-1.el7", vendor)
		if r := phpRisks(context.Background()); (len(r) == 1 && r[0].Key == "php7.4:eol") != want {
			t.Errorf("7.4 from %q: %v", vendor, r)
		}
	}
}

// S-1: IIS's fullPath with forward slashes is read; a relative or network
// path is not checked and said so.
func TestPHPReview1WindowsPaths(t *testing.T) {
	newPHPHost(t)
	phpWindows = true
	fcgi, read := phpWinFastCGI, phpReadBin
	defer func() { phpWinFastCGI, phpReadBin = fcgi, read }()
	phpReadBin = func(p string) ([]byte, error) {
		if p == `C:\PHP\php8ts.dll` {
			return []byte("MZ\x00X-Powered-By: PHP/8.3.20\x00"), nil
		}
		return nil, os.ErrNotExist
	}
	phpWinFastCGI = func() ([]string, error) { return []string{`C:/PHP/php-cgi.exe`}, nil }
	if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2026-129538") == nil {
		t.Errorf("forward slashes: %v", r)
	}
	for _, p := range []string{`php\php-cgi.exe`, `\\files\share\php\php-cgi.exe`, `\\?\C:\PHP\php-cgi.exe`} {
		phpWinFastCGI = func() ([]string, error) { return []string{p}, nil }
		if r := phpRisks(context.Background()); len(r) != 1 || !Unchecked(r[0]) || !strings.Contains(r[0].Summary, "not a local absolute path") {
			t.Errorf("%s: %v", p, r)
		}
	}
}

// S-2: an nginx or Apache include is followed (under the server's own
// folder); one that could not be read, or is outside, is said so.
func TestPHPReview1Includes(t *testing.T) {
	h := statusHost(t)
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  listen 80;\n  include /etc/nginx/snippets/status.conf;\n}\n")
	h.file("/etc/nginx/snippets/status.conf", "location = /status {\n  fastcgi_pass unix:/run/php-fpm.sock;\n}\n")
	if got := statusKey(phpRisks(context.Background())); got != "reported" {
		t.Errorf("nginx include: %s", got)
	}
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  include snippets/*.conf;\n}\n") // relative to /etc/nginx, a glob
	if got := statusKey(phpRisks(context.Background())); got != "reported" {
		t.Errorf("nginx relative glob include: %s", got)
	}
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  include /srv/conf/status.conf;\n}\n")
	h.file("/srv/conf/status.conf", "location = /status { fastcgi_pass unix:/run/php-fpm.sock; }\n")
	if r := phpRisks(context.Background()); statusKey(r) != "unknown" ||
		!strings.Contains(phpFind(r, uncheckedPrefix+"php8.3:CVE-2026-129292").Summary, "/srv/conf/status.conf (included by /etc/nginx/conf.d/site.conf, not read: outside") {
		t.Errorf("nginx include outside /etc/nginx (its folder is not even listed): %v", r)
	}
	if err := os.MkdirAll(filepath.Join(h.root, "/etc/nginx/snippets/dir.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  include /etc/nginx/snippets/dir.conf;\n}\n")
	if got := statusKey(phpRisks(context.Background())); got != "unknown" {
		t.Errorf("nginx include not a regular file: %s", got)
	}
	h = statusHost(t)
	h.file("/etc/apache2/sites-enabled/site.conf", "<VirtualHost *:80>\nInclude conf-available/status.conf\n</VirtualHost>\n")
	h.file("/etc/apache2/conf-available/status.conf", "<Location \"/status\">\n  SetHandler \"proxy:fcgi://127.0.0.1:9000\"\n</Location>\n")
	if got := statusKey(phpRisks(context.Background())); got != "reported" {
		t.Errorf("apache include: %s", got)
	}
	// An include loop ends.
	h = statusHost(t)
	h.file("/etc/nginx/conf.d/a.conf", "include /etc/nginx/conf.d/b.inc;\n")
	h.file("/etc/nginx/conf.d/b.inc", "include /etc/nginx/conf.d/a.conf;\n")
	if got := statusKey(phpRisks(context.Background())); got != "unknown" {
		t.Errorf("include loop: %s", got)
	}
}

// S-3: a hard link of a packaged binary is that binary; two builds of one
// branch keep a risk each.
func TestPHPReview1OneBranchTwice(t *testing.T) {
	h := newPHPHost(t)
	h.bin("/usr/bin/php8.3", "8.3.30")
	h.dpkg("/usr/bin/php8.3", "php8.3-cli", "8.3.30-1+deb.sury.org+1")
	if err := os.MkdirAll(filepath.Join(h.root, "/usr/local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(h.root, "/usr/bin/php8.3"), filepath.Join(h.root, "/usr/local/bin/php")); err != nil {
		t.Fatal(err)
	}
	r := phpRisks(context.Background())
	if len(r) != 1 || !strings.Contains(r[0].Summary, "package php8.3-cli") || strings.Contains(r[0].Summary, "not from a package") {
		t.Errorf("hard link: %v", r)
	}
	h = newPHPHost(t)
	h.bin("/usr/bin/php8.3", "8.3.6")
	h.dpkg("/usr/bin/php8.3", "php8.3-cli", "8.3.6-0ubuntu0.24.04.5")
	h.bin("/usr/local/bin/php", "8.3.30")
	r = phpRisks(context.Background())
	seen := map[string]bool{}
	for _, x := range r {
		if seen[x.Key] {
			t.Errorf("key twice: %s", x.Key)
		}
		seen[x.Key] = true
	}
	if len(r) != 2 {
		t.Errorf("two builds of 8.3: %v", phpKeys(r))
	}
}

// S-4: a configuration file past phpConfMax is not read, and said so.
func TestPHPReview1ConfLimit(t *testing.T) {
	max := phpConfMax
	defer func() { phpConfMax = max }()
	h := statusHost(t)
	h.file("/etc/nginx/conf.d/big.conf", strings.Repeat("# padding\n", 100))
	phpConfMax = 200
	if got := statusKey(phpRisks(context.Background())); got != "unknown" {
		t.Errorf("too large: %s", got)
	}
}

// S-5: a server on 127.0.0.1 only is not from outside; a ProxyPass kept to
// the host by its Location is not either; a regular expression Go cannot
// read is not "no match".
func TestPHPReview1Scope(t *testing.T) {
	for _, c := range []struct{ why, file, conf, want string }{
		{"nginx: 127.0.0.1 only", "/etc/nginx/conf.d/s.conf",
			"server {\n  listen 127.0.0.1:8080;\n  listen [::1]:8080;\n  location = /status { fastcgi_pass unix:/run/php-fpm.sock; }\n}\n", "no"},
		{"nginx: 127.0.0.1 and every address", "/etc/nginx/conf.d/s.conf",
			"server {\n  listen 127.0.0.1:8080;\n  listen 80;\n  location = /status { fastcgi_pass unix:/run/php-fpm.sock; }\n}\n", "reported"},
		{"nginx: no listen", "/etc/nginx/conf.d/s.conf",
			"server {\n  location = /status { fastcgi_pass unix:/run/php-fpm.sock; }\n}\n", "reported"},
		{"apache: ProxyPass kept local by its Location", "/etc/apache2/sites-enabled/s.conf",
			"ProxyPass /status fcgi://127.0.0.1:9000/status\n<Location /status>\n  Require local\n</Location>\n", "no"},
		{"apache: ProxyPass, another path kept local", "/etc/apache2/sites-enabled/s.conf",
			"ProxyPass /status fcgi://127.0.0.1:9000/status\n<Location /admin>\n  Require local\n</Location>\n", "reported"},
		{"nginx: a lookahead", "/etc/nginx/conf.d/s.conf",
			"server {\n  location ~ ^/(?!health)st {\n    fastcgi_pass unix:/run/php-fpm.sock;\n  }\n}\n", "unknown"},
	} {
		h := statusHost(t)
		h.file(c.file, c.conf)
		if got := statusKey(phpRisks(context.Background())); got != c.want {
			t.Errorf("%s: %s, want %s", c.why, got, c.want)
		}
	}
}

// #195 review 2, S-2: more distributions' rpm vendors.
func TestPHPReview2Vendors(t *testing.T) {
	for _, vendor := range []string{"OpenAnolis Community", "openEuler", "EuroLinux", "Cybertrust Japan Co., Ltd."} {
		h := newPHPHost(t)
		h.bin("/usr/bin/php", "7.4.33")
		h.rpm("/usr/bin/php", "php-cli", "0:7.4.33-1", vendor)
		if r := phpRisks(context.Background()); len(r) != 0 {
			t.Errorf("7.4 from %q is the distribution's: %v", vendor, r)
		}
	}
}
