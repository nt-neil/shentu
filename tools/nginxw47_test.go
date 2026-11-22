package tools

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// nginxOn is the keys of what nginxRisks reports for nginx version v with
// the configuration conf (nginx.conf) and site (conf.d/site.conf), read from
// a temporary directory where /etc is; log is the package changelog.
func nginxOn(t *testing.T, v, log, conf, site string) []Risk {
	t.Helper()
	// all of /etc: on macOS /etc is a link, which the trust check would follow
	// out of the temporary directory
	etc := filepath.Join(t.TempDir(), "etc")
	dir := filepath.Join(etc, "nginx")
	if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for p, s := range map[string]string{"nginx.conf": conf, "conf.d/site.conf": site} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ver, chlog, hs := nginxVersion, nginxChangelog, hostSource
	t.Cleanup(func() { nginxVersion, nginxChangelog, hostSource = ver, chlog, hs })
	run, _ := hostenv.NewRunner(nil)
	hostSource = func() hostenv.Source { return &hostenv.Live{Runner: run, Remap: map[string]string{"/etc": etc}} }
	pkg := ""
	if log != "" {
		pkg = "nginx"
	}
	nginxVersion = func(context.Context) ngxInstall {
		return ngxInstall{version: v, pkg: pkg, dist: "dpkg", conf: hostenv.NginxConf}
	}
	nginxChangelog = func(context.Context, string, string) string { return log }
	return nginxRisks(context.Background())
}

func keys(r []Risk) []string {
	var out []string
	for _, x := range r {
		out = append(out, x.Key)
	}
	return out
}

// CVE-2026-118899 (1.13.0 through 1.31.8) reaches a server that speaks
// TLS 1.3, HTTP/2 or not; CVE-2026-113425 (0.5.33 through 1.31.8) one with a
// mail block. Fixed in 1.31.9 and 1.30.7 (nginx.org's security advisories).
func TestNginxTLS13AndMail(t *testing.T) {
	const (
		http = "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n"
		tls  = "CVE-2026-118899"
		mail = "CVE-2026-113425"
	)
	for _, c := range []struct {
		why, v, log, conf, site string
		want                    []string // warnings among the keys, as "nginx:" + the CVE
	}{
		{"HTTP/2 turned off is not safe: TLS 1.3 named", "1.31.8", "", http,
			"server {\n  listen 443 ssl;\n  http2 off;\n  ssl_protocols TLSv1.2 TLSv1.3;\n}\n", []string{tls}},
		{"TLS 1.3 by default from 1.23.4", "1.24.0", "", http, "server {\n  listen 443 ssl;\n}\n", []string{tls}},
		{"before 1.23.4 the default leaves TLS 1.3 out", "1.22.1", "", http, "server {\n  listen 443 ssl;\n}\n", nil},
		{"named in the http block, inherited", "1.22.1", "",
			"http {\n  ssl_protocols TLSv1.2 TLSv1.3;\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  listen 443 ssl;\n}\n", []string{tls}},
		{"the server's own ssl_protocols wins", "1.24.0", "",
			"http {\n  ssl_protocols TLSv1.2 TLSv1.3;\n  include /etc/nginx/conf.d/*.conf;\n}\n",
			"server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.2;\n}\n", nil},
		{"TLS 1.2 only", "1.24.0", "", http, "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.2;\n}\n", nil},
		{"ssl on without ssl in listen", "1.22.1", "", http, "server {\n  listen 443;\n  ssl on;\n  ssl_protocols TLSv1.3;\n}\n", []string{tls}},
		{"no TLS server", "1.24.0", "", "http {\n  ssl_protocols TLSv1.3;\n  include /etc/nginx/conf.d/*.conf;\n}\n",
			"server {\n  listen 80;\n}\n", nil},
		{"commented out", "1.24.0", "", http, "server {\n  listen 80;\n  # listen 443 ssl;\n}\n", nil},
		{"before 1.13.0", "1.12.2", "", http, "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.3;\n}\n", nil},
		{"fixed in 1.30.7", "1.30.7", "", http, "server {\n  listen 443 ssl;\n}\n", nil},
		{"fixed in 1.31.9", "1.31.9", "", http, "server {\n  listen 443 ssl;\n}\n", nil},
		{"backported by the package", "1.24.0-2ubuntu7.6", "  * SECURITY UPDATE: CVE-2026-118899\n", http,
			"server {\n  listen 443 ssl;\n}\n", nil},
		{"a mail block with a server", "1.22.1", "", "mail {\n  server {\n    listen 25;\n    protocol smtp;\n  }\n}\n" + http,
			"server {\n  listen 80;\n}\n", []string{mail}},
		{"mail and TLS 1.3 both", "1.26.3", "", "mail {\n  server {\n    listen 993 ssl;\n    protocol imap;\n  }\n}\n" + http,
			"server {\n  listen 443 ssl;\n}\n", []string{tls, mail}},
		{"no mail block", "1.22.1", "", http, "server {\n  listen 80;\n}\n", nil},
	} {
		t.Run(c.why, func(t *testing.T) {
			r := nginxOn(t, c.v, c.log, c.conf, c.site)
			var got []string
			for _, x := range r {
				if x.Severity == "warning" {
					got = append(got, strings.TrimPrefix(x.Key, "nginx:"))
				}
				if Unchecked(x) {
					t.Errorf("unexpected unknown: %+v", x)
				}
			}
			slices.Sort(got)
			want := slices.Sorted(slices.Values(c.want))
			if !slices.Equal(got, want) {
				t.Errorf("warnings %v, want %v (all: %v)", got, want, keys(r))
			}
			for _, x := range r {
				if x.Key == "nginx:"+tls && (!strings.Contains(x.Summary, "HTTP/2 off does not avoid it") || !strings.Contains(x.Summary, "1.30.7")) {
					t.Errorf("TLS 1.3 advice: %s", x.Summary)
				}
			}
		})
	}
}

// The other six advisories of 2026-11-18 are one line by version: the
// resolver, HTTP/3, stream SNI, ssl_preread, try_files with alias, and PROXY
// protocol v2, which only mainline 1.31.4 through 1.31.8 has.
func TestNginxOtherAdvisories(t *testing.T) {
	const site = "server {\n  listen 80;\n}\n"
	conf := "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n"
	six := []string{"CVE-2026-123634", "CVE-2026-121810", "CVE-2026-120967", "CVE-2026-123640", "CVE-2026-125283", "CVE-2026-120993"}
	for v, want := range map[string][]string{
		"1.31.8": six, "1.31.4": six, "1.31.3": six[:5], "1.30.6": six[:5], "1.26.3": six[:5],
		"1.24.0": {six[0], six[3], six[4]}, "0.9.6": {six[0], six[4]}, "0.6.17": nil,
		"1.30.7": nil, "1.31.9": nil, "1.32.0": nil,
	} {
		var line *Risk
		r := nginxOn(t, v, "", conf, site)
		for i := range r {
			if strings.Contains(r[i].Summary, "medium and minor") {
				line = &r[i]
			}
		}
		switch {
		case want == nil && line != nil:
			t.Errorf("%s: %+v", v, *line)
		case want == nil:
		case line == nil:
			t.Errorf("%s: no line, want %v (all: %v)", v, want, keys(r))
		case line.Severity != "info" || line.Key != "nginx:"+want[0] || !strings.Contains(line.Summary, strings.Join(want, ", ")+" (") ||
			!strings.Contains(line.Summary, "1.31.9"):
			t.Errorf("%s: %+v, want %v", v, *line, want)
		}
	}
}
