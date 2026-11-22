//go:build unix

package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// #195 review 2. FIFOs and links are made in t.TempDir; nothing of the host.

// within runs f and fails the test if it takes a second or more (a FIFO
// opened for reading waits for a writer that never comes).
func within(t *testing.T, why string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s: still reading after 1s", why)
	}
}

func (h *phpHost) fifo(p string) {
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := syscall.Mkfifo(full, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *phpHost) symlink(target, p string) {
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h.root, target), full); err != nil {
		h.t.Fatal(err)
	}
}

// N-1: a FIFO where a configuration file, an included file, a pool or a
// changelog is expected is not waited on; it is named as not read.
func TestPHPReview2FIFO(t *testing.T) {
	h := statusHost(t)
	h.fifo("/etc/nginx/conf.d/fifo.conf")
	within(t, "conf.d", func() {
		if r := phpRisks(context.Background()); statusKey(r) != "unknown" || !strings.Contains(phpFind(r, uncheckedPrefix+"php8.3:CVE-2026-129292").Summary, "not a regular file") {
			t.Errorf("conf.d FIFO: %v", r)
		}
	})
	h = statusHost(t)
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  include /etc/nginx/snippets/status.conf;\n}\n")
	h.fifo("/etc/nginx/snippets/status.conf")
	within(t, "include", func() {
		if got := statusKey(phpRisks(context.Background())); got != "unknown" {
			t.Errorf("include FIFO: %s", got)
		}
	})
	h = statusHost(t)
	h.fifo("/usr/local/etc/php-fpm.d/zz.conf")
	within(t, "pool", func() {
		if got := statusKey(phpRisks(context.Background())); got != "unknown" {
			t.Errorf("pool FIFO: %s", got)
		}
	})
	h = newPHPHost(t)
	h.bin("/usr/bin/php-cgi8.2", "8.2.30")
	h.dpkg("/usr/bin/php-cgi8.2", "php8.2-cgi", "8.2.30-1~deb12u1")
	h.running("php-cgi8.2", "/usr/bin/php-cgi8.2")
	h.fifo("/usr/share/doc/php8.2-cgi/changelog.Debian.gz")
	within(t, "changelog", func() {
		if r := phpRisks(context.Background()); phpFind(r, "php8.2:CVE-2026-129538") == nil {
			t.Errorf("changelog FIFO: %v", phpKeys(r))
		}
	})
	h = newPHPHost(t)
	h.fifo("/usr/bin/php8.3")
	within(t, "binary", func() {
		if r := phpRisks(context.Background()); len(r) != 0 {
			t.Errorf("binary FIFO: %v", r)
		}
	})
	// phpReadLimited itself, on a FIFO.
	within(t, "phpReadLimited", func() {
		if _, err := phpReadLimited(filepath.Join(h.root, "/usr/bin/php8.3"), phpConfMax); err != errNotRegular {
			t.Errorf("phpReadLimited on a FIFO: %v", err)
		}
	})
}

// S-1: an include is judged by where it leads: a link out of the server's
// folders is not read.
func TestPHPReview2IncludeLinks(t *testing.T) {
	h := statusHost(t)
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  include /etc/nginx/snippets/status.conf;\n}\n")
	h.file("/srv/conf/status.conf", "location = /status { fastcgi_pass unix:/run/php-fpm.sock; }\n")
	h.symlink("/srv/conf/status.conf", "/etc/nginx/snippets/status.conf")
	r := phpRisks(context.Background())
	if u := phpFind(r, uncheckedPrefix+"php8.3:CVE-2026-129292"); u == nil || !strings.Contains(u.Summary, "/srv/conf/status.conf") {
		t.Errorf("link out of /etc/nginx: %v", r)
	}
	// A link that stays in /etc/nginx is read.
	h = statusHost(t)
	h.file("/etc/nginx/conf.d/site.conf", "server {\n  include /etc/nginx/snippets/status.conf;\n}\n")
	h.file("/etc/nginx/snippets-available/status.conf", "location = /status { fastcgi_pass unix:/run/php-fpm.sock; }\n")
	h.symlink("/etc/nginx/snippets-available/status.conf", "/etc/nginx/snippets/status.conf")
	if got := statusKey(phpRisks(context.Background())); got != "reported" {
		t.Errorf("link in /etc/nginx: %s", got)
	}
	// A file of an Apache include glob linked out (snippets/ is no folder
	// read on its own, as conf-enabled/ is).
	h = statusHost(t)
	h.file("/etc/apache2/sites-enabled/site.conf", "Include snippets/*.conf\n")
	h.file("/opt/other/status.conf", "<Location /status>\n  SetHandler \"proxy:fcgi://127.0.0.1:9000\"\n</Location>\n")
	h.symlink("/opt/other/status.conf", "/etc/apache2/snippets/status.conf")
	if got := statusKey(phpRisks(context.Background())); got != "unknown" {
		t.Errorf("apache link out of /etc/apache2: %s", got)
	}
}
