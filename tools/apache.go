package tools

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// CVE-2026-119618 (CVE.org, NVD; not in OSV when this was written, so the
// package scan does not report it yet): mod_http2's assign_headers() in Apache
// HTTP Server 2.4.55 through 2.4.70 can corrupt the heap and lead to remote
// code execution. Only a server that loads mod_http2 and speaks HTTP/2
// (Protocols h2 or h2c) is exposed. Once the distributions' advisories reach
// OSV, package_vulns reports it too and this check can go.

// apacheConfGlob are the Apache configuration files read for mod_http2.
var apacheConfGlob = []string{
	"/etc/apache2/apache2.conf", "/etc/apache2/mods-enabled/*.load", "/etc/apache2/mods-enabled/*.conf",
	"/etc/apache2/sites-enabled/*", "/etc/apache2/conf-enabled/*",
	"/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf", "/etc/httpd/conf.modules.d/*.conf",
}

var (
	loadH2    = regexp.MustCompile(`(?mi)^\s*LoadModule\s+http2_module\s`)
	protocols = regexp.MustCompile(`(?mi)^\s*Protocols\s+(.*)$`)
)

// apacheH2Affected reports whether an Apache version (a package's version:
// "2.4.62-1~deb12u2", "1:2.4.57-5.el9") is one CVE-2026-119618 affects.
func apacheH2Affected(version string) bool {
	if i := strings.IndexByte(version, ':'); i >= 0 {
		version = version[i+1:] // the epoch
	}
	if i := strings.IndexAny(version, "-~+"); i >= 0 {
		version = version[:i] // the distribution's revision
	}
	f := strings.Split(version, ".")
	if len(f) < 3 || f[0] != "2" || f[1] != "4" {
		return false
	}
	n, err := strconv.Atoi(f[2])
	return err == nil && n >= 55 && n <= 70
}

// apacheH2Enabled reports whether the configuration loads mod_http2 and turns
// on HTTP/2 (Protocols h2 or h2c) somewhere.
func apacheH2Enabled(confs [][]byte) bool {
	loaded, h2 := false, false
	for _, b := range confs {
		loaded = loaded || loadH2.Match(b)
		for _, m := range protocols.FindAllSubmatch(b, -1) {
			for _, p := range strings.Fields(strings.ToLower(string(m[1]))) {
				if p == "h2" || p == "h2c" {
					h2 = true
				}
			}
		}
	}
	return loaded && h2
}

// apacheVersion is the installed Apache package's version ("" when none).
var apacheVersion = func(ctx context.Context) string {
	for _, c := range [][]string{{"dpkg-query", "-W", "-f", "${Version}", "apache2"}, {"rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", "httpd"}} {
		if out, err := exec.CommandContext(ctx, c[0], c[1:]...).Output(); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" && !strings.Contains(v, "not installed") {
				return v
			}
		}
	}
	return ""
}

// apacheH2Risk is the risk of CVE-2026-119618 on this server, if any.
func apacheH2Risk(ctx context.Context, confGlob []string) []Risk {
	v := apacheVersion(ctx)
	if !apacheH2Affected(v) {
		return nil
	}
	var confs [][]byte
	src, conf := hostSource(), hostenv.WebConf{Root: webConfRoot, Owner: int(webConfOwner)}
	for _, g := range confGlob {
		for _, f := range hostenv.Glob(src, g) {
			if b, why := hostenv.ReadWebConf(src, f, conf); why == "" {
				confs = append(confs, b)
			}
		}
	}
	if !apacheH2Enabled(confs) {
		return nil
	}
	return []Risk{{"apache:CVE-2026-119618", "warning", "Apache " + v + " serves HTTP/2 with mod_http2, which CVE-2026-119618 affects " +
		"(heap corruption in assign_headers(), remote code execution); upgrade to 2.4.71; until then, set Protocols to http/1.1 only"}}
}
