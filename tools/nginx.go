package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// CVE-2026-123007 (memory corruption in HTTP/2 flow control, nginx 1.9.5
// through 1.31.8) and CVE-2026-123633 (a use-after-free in HTTP/2, 1.19.7
// through 1.31.8), nginx.org's security advisories: fixed in 1.31.9 and
// 1.30.7. Only a server that speaks HTTP/2 is exposed. The package scan
// reports them once the distributions' advisories reach OSV, but not for
// nginx.org's own packages (their versions compare as newer than the
// distribution's fix), a PPA's, or an nginx built from source: this check
// covers those, by version and configuration, until the advisories are in
// OSV everywhere.

// nginxH2CVE is one HTTP/2 advisory: affected from first up to the fix.
type nginxH2CVE struct {
	id    string
	first [3]int
}

var nginxH2CVEs = []nginxH2CVE{{"CVE-2026-123007", [3]int{1, 9, 5}}, {"CVE-2026-123633", [3]int{1, 19, 7}}}

// nginxRelease is the upstream version in a package's or the binary's
// version ("1.22.1-9+deb12u2", "1:1.20.1-14.el9_2.1", "1.31.8-1~bookworm").
func nginxRelease(version string) ([3]int, bool) {
	if i := strings.IndexByte(version, ':'); i >= 0 {
		version = version[i+1:] // the epoch
	}
	if i := strings.IndexAny(version, "-~+"); i >= 0 {
		version = version[:i] // the packager's revision
	}
	var v [3]int
	f := strings.Split(version, ".")
	if len(f) == 4 {
		f = f[:3] // OpenResty's 1.25.3.1 is nginx 1.25.3 and its own release
	}
	if len(f) != 3 {
		return v, false
	}
	for i, s := range f {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// nginxH2Affected is the HTTP/2 advisories a version of nginx is in.
func nginxH2Affected(version string) []string {
	v, ok := nginxRelease(version)
	if !ok || v[0] != 1 || v[1] > 31 || v[1] == 31 && v[2] >= 9 || v[1] == 30 && v[2] >= 7 {
		return nil // 1.31.9 and 1.30.7 are fixed, and what comes after them
	}
	var out []string
	for _, c := range nginxH2CVEs {
		if v[1] > c.first[1] || v[1] == c.first[1] && v[2] >= c.first[2] {
			out = append(out, c.id)
		}
	}
	return out
}

// nginxPackages are the package names nginx is installed under (Debian and
// Ubuntu split it into nginx-core, -full, -light and -extras before 1.24;
// OpenResty is nginx with its own release number after nginx's).
var nginxPackages = []string{"nginx", "nginx-core", "nginx-full", "nginx-light", "nginx-extras", "openresty"}

// nginxBinaries are where nginx is found when no package holds it: the
// distributions' places (Arch's /usr/bin), a build from source's, and
// OpenResty's.
var nginxBinaries = []string{"/usr/sbin/nginx", "/usr/bin/nginx", "/usr/local/sbin/nginx", "/usr/local/nginx/sbin/nginx",
	"/usr/local/openresty/nginx/sbin/nginx"}

// ngxVersionString is the version a binary names itself with: nginx/1.24.0,
// openresty/1.25.3.1.
var ngxVersionString = regexp.MustCompile(`(?:nginx|openresty)/(\d+\.\d+\.\d+(?:\.\d+)?)\x00`)

// nginxVersion is the installed nginx's version, and the package holding it
// ("" for a binary no package holds; version "" when there is no nginx).
// The binary's version is read from the file, not by running it.
var nginxVersion = func(ctx context.Context) (version, pkg, dist string) {
	for _, p := range nginxPackages {
		out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${db:Status-Status} ${Version}", p).Output()
		if f := strings.Fields(string(out)); err == nil && len(f) == 2 && f[0] == "installed" {
			return f[1], p, "dpkg"
		}
	}
	for _, p := range []string{"nginx", "openresty"} {
		if out, err := exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", p).Output(); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" && !strings.Contains(v, "not installed") {
				return v, p, "rpm"
			}
		}
	}
	for _, b := range nginxBinaries {
		f, err := os.Open(b)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, 64<<20))
		f.Close()
		if m := ngxVersionString.FindSubmatch(data); err == nil && m != nil {
			return string(m[1]), "", ""
		}
	}
	return "", "", ""
}

// nginxChangelog is the installed package's changelog, where a distribution
// names the CVEs it backported a fix of without changing the version.
var nginxChangelog = func(ctx context.Context, pkg, dist string) string {
	switch dist {
	case "dpkg":
		for _, n := range []string{pkg, "nginx-common", "nginx"} {
			if b, err := os.ReadFile("/usr/share/doc/" + n + "/changelog.Debian.gz"); err == nil {
				if z, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
					text, _ := io.ReadAll(io.LimitReader(z, 16<<20))
					return string(text)
				}
			}
		}
	case "rpm":
		if out, err := exec.CommandContext(ctx, "rpm", "-q", "--changelog", pkg).Output(); err == nil {
			return string(out)
		}
	}
	return ""
}

// mentionsCVE reports whether text names the CVE id, not one it is the start
// of (CVE-2026-123007 in CVE-2026-1230071).
func mentionsCVE(text, id string) bool {
	for i := 0; ; {
		j := strings.Index(text[i:], id)
		if j < 0 {
			return false
		}
		end := i + j + len(id)
		if end == len(text) || text[end] < '0' || text[end] > '9' {
			return true
		}
		i = end
	}
}

// nginxHTTP2 reports whether nginx's configuration speaks HTTP/2.
var nginxHTTP2 = func() (on, found bool, unread []string) { return hostenv.NginxHTTP2(hostSource()) }

// nginxH2Risk is the risk of nginx's HTTP/2 advisories on this server, if any.
func nginxH2Risk(ctx context.Context) []Risk {
	v, pkg, dist := nginxVersion(ctx)
	cves := nginxH2Affected(v)
	if pkg != "" && len(cves) > 0 {
		log := nginxChangelog(ctx, pkg, dist)
		var open []string
		for _, c := range cves {
			if !mentionsCVE(log, c) {
				open = append(open, c) // not backported by the package
			}
		}
		cves = open
	}
	on, found, unread := nginxHTTP2()
	if v == "" && found {
		// nginx is configured, but neither a package nor a binary where one is
		// looked for gives its version (a build installed elsewhere, a fork)
		return []Risk{{uncheckedPrefix + "nginx:version", "info", "/etc/nginx/nginx.conf is there, but the version of nginx could not be found " +
			"(no package, no binary in " + strings.Join(nginxBinaries, ", ") + "), so whether CVE-2026-123007 and CVE-2026-123633 affect it is unknown"}}
	}
	if len(cves) == 0 {
		return nil
	}
	ids, affect := strings.Join(cves, " and "), " affect"
	if len(cves) == 1 {
		affect = " affects"
	}
	switch {
	case on:
		return []Risk{{"nginx:" + cves[0], "warning", "nginx " + v + " serves HTTP/2, which " + ids + affect + " (HTTP/2 memory corruption: " +
			"a client can crash the worker processes; a public proof of concept exists). Upgrade to 1.31.9 (mainline) or 1.30.7 (stable), " +
			"or to your distribution's fixed package; until then, turning HTTP/2 off (remove http2 from listen, or http2 off;) avoids it, " +
			"and clients fall back to HTTP/1.1. If your distribution has published a fixed package, its advisory is what counts " +
			"(an image without package changelogs, such as Ubuntu's minimized ones, keeps this warning after the fix)"}}
	case !found:
		return []Risk{{uncheckedPrefix + "nginx:" + cves[0], "info", "nginx " + v + " is in the range of " + ids +
			", but /etc/nginx/nginx.conf was not found, so whether it serves HTTP/2 is unknown"}}
	case len(unread) > 0:
		// A file not read may be the one turning HTTP/2 on: not "not exposed".
		return []Risk{{uncheckedPrefix + "nginx:" + cves[0], "info", "nginx " + v + " is in the range of " + ids +
			", but whether it serves HTTP/2 is unknown: " + strings.Join(unread, ", ") + " could not be read"}}
	}
	return nil
}
