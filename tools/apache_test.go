package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CVE-2026-119618: Apache 2.4.55 through 2.4.70 serving HTTP/2 with mod_http2.
func TestApacheH2Affected(t *testing.T) {
	for v, want := range map[string]bool{
		"2.4.55-1": true, "2.4.62-1~deb12u2": true, "1:2.4.57-5.el9": true, "0:2.4.70-1.el9": true, "2.4.70": true,
		"2.4.54-1": false, "2.4.71-1": false, "2.2.34": false, "2.5.0": false, "": false, "garbage": false,
	} {
		if got := apacheH2Affected(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}

func TestApacheH2Risk(t *testing.T) {
	etc, _ := filepath.EvalSymlinks(t.TempDir())
	root, owner := webConfRoot, webConfOwner
	ver := apacheVersion
	defer func() { webConfRoot, webConfOwner, apacheVersion = root, owner, ver }()
	webConfRoot, webConfOwner = etc, uint32(os.Getuid())
	avail, enabled := filepath.Join(etc, "mods-available"), filepath.Join(etc, "mods-enabled")
	os.MkdirAll(avail, 0o755)
	os.MkdirAll(enabled, 0o755)
	os.WriteFile(filepath.Join(avail, "http2.load"), []byte("LoadModule http2_module /usr/lib/apache2/modules/mod_http2.so\n"), 0o644)
	os.Symlink("../mods-available/http2.load", filepath.Join(enabled, "http2.load")) // Debian enables by a symlink
	site := filepath.Join(etc, "site.conf")
	glob := []string{filepath.Join(enabled, "*.load"), site}
	risk := func(v, conf string) []Risk {
		apacheVersion = func(context.Context) string { return v }
		os.WriteFile(site, []byte(conf), 0o644)
		return apacheH2Risk(context.Background(), glob)
	}
	if r := risk("2.4.62-1~deb12u2", "<VirtualHost *:443>\n  Protocols h2 http/1.1\n</VirtualHost>\n"); len(r) != 1 || r[0].Severity != "warning" ||
		!strings.Contains(r[0].Summary, "2.4.71") || !strings.Contains(r[0].Summary, "http/1.1 only") {
		t.Errorf("affected and h2 on: %+v", r)
	}
	if r := risk("2.4.62-1", "Protocols h2c http/1.1\n"); len(r) != 1 {
		t.Errorf("h2c: %+v", r)
	}
	for _, c := range []struct{ v, conf, why string }{
		{"2.4.71-1", "Protocols h2 http/1.1\n", "fixed version"},
		{"2.4.62-1", "Protocols http/1.1\n", "HTTP/1.1 only"},
		{"2.4.62-1", "# Protocols h2 http/1.1\n", "commented out"},
		{"", "Protocols h2\n", "no Apache"},
	} {
		if r := risk(c.v, c.conf); len(r) != 0 {
			t.Errorf("%s: %+v", c.why, r)
		}
	}
	// mod_http2 not loaded: not exposed.
	os.Remove(filepath.Join(enabled, "http2.load"))
	if r := risk("2.4.62-1", "Protocols h2\n"); len(r) != 0 {
		t.Errorf("mod_http2 not loaded: %+v", r)
	}
}
