package tools

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// CVE-2026-123007 (1.9.5 through 1.31.8) and CVE-2026-123633 (1.19.7 through
// 1.31.8), fixed in 1.31.9 and 1.30.7 (nginx.org's security advisories).
func TestNginxH2Affected(t *testing.T) {
	both := []string{"CVE-2026-123007", "CVE-2026-123633"}
	first := []string{"CVE-2026-123007"}
	for v, want := range map[string][]string{
		"1.9.4": nil, "1.9.5": first, "1.19.6": first, "1.19.7": both,
		"1.22.1-9+deb12u2": both, "1:1.20.1-14.el9_2.1": both, "1.24.0-2ubuntu7.1": both,
		"1.30.6": both, "1.30.7": nil, "1.30.8-1~bookworm": nil,
		"1.31.0": both, "1.31.8-1~bookworm": both, "1.31.9": nil, "1.31.9-1~noble": nil, "1.32.0": nil, "2.0.0": nil,
		"": nil, "garbage": nil, "1.24": nil, "1.24.x": nil,
		// OpenResty: nginx's version and its own release
		"1.25.3.1-1~jammy": both, "1.27.1.2": both, "1.31.9.1": nil, "1.25.3.1.1": nil,
	} {
		if got := nginxH2Affected(v); !slices.Equal(got, want) {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}

func TestNginxH2Risk(t *testing.T) {
	ver, chlog, h2 := nginxVersion, nginxChangelog, nginxHTTP2
	defer func() { nginxVersion, nginxChangelog, nginxHTTP2 = ver, chlog, h2 }()
	risk := func(v, pkg, dist, log string, on, found bool, unread ...string) []Risk {
		nginxVersion = func(context.Context) (string, string, string) { return v, pkg, dist }
		nginxChangelog = func(context.Context, string, string) string { return log }
		nginxHTTP2 = func() (bool, bool, []string) { return on, found, unread }
		return nginxH2Risk(context.Background())
	}
	r := risk("1.22.1-9+deb12u2", "nginx", "dpkg", "", true, true)
	if len(r) != 1 || r[0].Severity != "warning" || r[0].Key != "nginx:CVE-2026-123007" || Unchecked(r[0]) {
		t.Fatalf("affected, HTTP/2 on: %+v", r)
	}
	for _, s := range []string{"CVE-2026-123007 and CVE-2026-123633", "1.31.9", "1.30.7", "http2 off", "HTTP/1.1"} {
		if !strings.Contains(r[0].Summary, s) {
			t.Errorf("summary lacks %q: %s", s, r[0].Summary)
		}
	}
	// A build from source no package holds: no changelog to ask.
	if r := risk("1.25.4", "", "", "", true, true); len(r) != 1 || !strings.Contains(r[0].Summary, "nginx 1.25.4") {
		t.Errorf("binary only: %+v", r)
	}
	// 1.9.5 through 1.19.6: CVE-2026-123007 only.
	if r := risk("1.18.0-6ubuntu14", "nginx", "dpkg", "", true, true); len(r) != 1 || strings.Contains(r[0].Summary, "123633") {
		t.Errorf("1.18.0: %+v", r)
	}
	// The distribution backported the fix (the version stays): its changelog names the CVEs.
	if r := risk("1.22.1-9+deb12u3", "nginx", "dpkg", "  * Fix CVE-2026-123007 and CVE-2026-123633\n", true, true); len(r) != 0 {
		t.Errorf("backported: %+v", r)
	}
	if r := risk("1:1.20.1-14.el9_2.2", "nginx", "rpm", "- Resolves: CVE-2026-123007\n", true, true); len(r) != 1 ||
		r[0].Key != "nginx:CVE-2026-123633" || strings.Contains(r[0].Summary, "123007") {
		t.Errorf("one of two backported: %+v", r)
	}
	for _, c := range []struct {
		why       string
		v         string
		on, found bool
	}{
		{"fixed version", "1.31.9-1~bookworm", true, true},
		{"HTTP/1.1 only", "1.24.0-2ubuntu7", false, true},
		{"no nginx", "", true, false},
		{"before HTTP/2", "1.9.4", true, true},
	} {
		if r := risk(c.v, "nginx", "dpkg", "", c.on, c.found); len(r) != 0 {
			t.Errorf("%s: %+v", c.why, r)
		}
	}
	// A longer CVE id that starts the same is not a backport of this one (review S-1).
	if r := risk("1.22.1-9+deb12u3", "nginx", "dpkg", "  * CVE-2026-1230071, CVE-2026-1236330: other fixes\n", true, true); len(r) != 1 ||
		!strings.Contains(r[0].Summary, "CVE-2026-123007 and CVE-2026-123633") {
		t.Errorf("longer ids: %+v", r)
	}
	if r := risk("1.22.1-9+deb12u3", "nginx", "dpkg", "CVE-2026-123007\nCVE-2026-123633", true, true); len(r) != 0 {
		t.Errorf("ids at the end of the text: %+v", r)
	}
	// nginx configured, its version not found (review S-3): not known.
	if r := risk("", "", "", "", true, true); len(r) != 1 || !Unchecked(r[0]) || r[0].Key != uncheckedPrefix+"nginx:version" {
		t.Errorf("configured, no version: %+v", r)
	}
	// The warning says the distribution's advisory counts (review S-2).
	if r := risk("1.24.0-2ubuntu7", "nginx", "dpkg", "", true, true); len(r) != 1 || !strings.Contains(r[0].Summary, "minimized") {
		t.Errorf("distribution note: %+v", r)
	}
	// Not known: no configuration found, or a file of it not read.
	if r := risk("1.25.4", "", "", "", false, false); len(r) != 1 || r[0].Severity != "info" || !Unchecked(r[0]) ||
		!strings.HasPrefix(r[0].Key, uncheckedPrefix) {
		t.Errorf("no nginx.conf: %+v", r)
	}
	if r := risk("1.24.0-2ubuntu7", "nginx", "dpkg", "", false, true, "/etc/nginx/sites-enabled/shop (permission denied)"); len(r) != 1 ||
		!Unchecked(r[0]) || !strings.Contains(r[0].Summary, "sites-enabled/shop") {
		t.Errorf("a file unread: %+v", r)
	}
	// On in what could be read: the warning, not the unknown.
	if r := risk("1.24.0-2ubuntu7", "nginx", "dpkg", "", true, true, "/etc/nginx/conf.d/x.conf (permission denied)"); len(r) != 1 || Unchecked(r[0]) {
		t.Errorf("on with a file unread: %+v", r)
	}
}

func TestNginxVersionString(t *testing.T) {
	bin := []byte("\x00\x7fELF...nginx version: \x00nginx/1.24.0\x00Server: \x00")
	if m := ngxVersionString.FindSubmatch(bin); m == nil || string(m[1]) != "1.24.0" {
		t.Errorf("version in the binary: %q", m)
	}
	if m := ngxVersionString.FindSubmatch([]byte("\x00openresty/1.25.3.1\x00")); m == nil || string(m[1]) != "1.25.3.1" {
		t.Errorf("OpenResty's version in the binary: %q", m)
	}
}

func TestMentionsCVE(t *testing.T) {
	for text, want := range map[string]bool{
		"CVE-2026-123007": true, "fix CVE-2026-123007.": true, "CVE-2026-123007, CVE-2026-1": true,
		"CVE-2026-1230071": false, "CVE-2026-1230071 and CVE-2026-123007": true, "": false, "CVE-2026-12300": false,
	} {
		if got := mentionsCVE(text, "CVE-2026-123007"); got != want {
			t.Errorf("%q: %v, want %v", text, got, want)
		}
	}
}
