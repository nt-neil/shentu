package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// nginx.org's security advisories of 2026-11-18, fixed in 1.31.9 and 1.30.7:
// CVE-2026-123007 (memory corruption in HTTP/2 flow control) and
// CVE-2026-123633 (a use-after-free in HTTP/2) reach a server that speaks
// HTTP/2; CVE-2026-118899 (an infinite loop reading a request body over
// TLS 1.3) one that speaks TLS 1.3, HTTP/2 or not; CVE-2026-113425 (a
// use-after-free in the mail proxy) one with a mail block. The other six,
// medium and minor, need features this check does not read (a resolver,
// HTTP/3, stream, PROXY protocol, alias): they are one line of advice by
// version. The package scan reports them once the distributions' advisories
// reach OSV, but not for nginx.org's own packages (their versions compare as
// newer than the distribution's fix), a PPA's, or an nginx built from
// source: this check covers those, by version and configuration, until the
// advisories are in OSV everywhere.

// nginxCVE is one advisory: affected from first up to the fix.
type nginxCVE struct {
	id    string
	first [3]int
}

var (
	nginxH2CVEs   = []nginxCVE{{"CVE-2026-123007", [3]int{1, 9, 5}}, {"CVE-2026-123633", [3]int{1, 19, 7}}}
	nginxTLS13CVE = []nginxCVE{{"CVE-2026-118899", [3]int{1, 13, 0}}}
	nginxMailCVE  = []nginxCVE{{"CVE-2026-113425", [3]int{0, 5, 33}}}
	// resolver, HTTP/3, stream SNI with client certificates, stream
	// ssl_preread, try_files with alias, PROXY protocol v2 (mainline only)
	nginxOtherCVEs = []nginxCVE{{"CVE-2026-123634", [3]int{0, 6, 18}}, {"CVE-2026-121810", [3]int{1, 25, 0}},
		{"CVE-2026-120967", [3]int{1, 25, 5}}, {"CVE-2026-123640", [3]int{1, 15, 2}}, {"CVE-2026-125283", [3]int{0, 9, 6}},
		{"CVE-2026-120993", [3]int{1, 31, 4}}}
)

// nginxTLS13Default is the first nginx whose default ssl_protocols holds TLSv1.3.
var nginxTLS13Default = [3]int{1, 23, 4}

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

// atLeast reports whether version v is first or later.
func atLeast(v, first [3]int) bool {
	for i := range v {
		if v[i] != first[i] {
			return v[i] > first[i]
		}
	}
	return true
}

// nginxAffected is the advisories of list a version of nginx is in.
func nginxAffected(version string, list []nginxCVE) []string {
	v, ok := nginxRelease(version)
	if !ok || v[0] > 1 || v[0] == 1 && (v[1] > 31 || v[1] == 31 && v[2] >= 9 || v[1] == 30 && v[2] >= 7) {
		return nil // 1.31.9 and 1.30.7 are fixed, and what comes after them
	}
	var out []string
	for _, c := range list {
		if atLeast(v, c.first) {
			out = append(out, c.id)
		}
	}
	return out
}

// nginxH2Affected is the HTTP/2 advisories a version of nginx is in.
func nginxH2Affected(version string) []string { return nginxAffected(version, nginxH2CVEs) }

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

// ngxInstall is the nginx this host has: its version ("" when none is
// found), the package holding it ("" for a binary no package holds), the
// package manager, and its configuration file. removed: a package of it was
// removed and its configuration left behind (dpkg's config-files, rpm's
// .rpmsave), so a configuration without a version is no nginx.
type ngxInstall struct {
	version, pkg, dist, conf string
	removed                  bool
}

// ngxRun, ngxRead and ngxExists run a package manager's query, read a binary
// (up to 64 MiB) and look for a file: variables for the tests.
var (
	ngxRun = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	}
	ngxRead = func(p string) ([]byte, error) {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 64<<20))
	}
	ngxExists = func(p string) bool { _, err := os.Stat(p); return err == nil }
)

// ngxConfOf is the configuration of nginx installed by pkg or at bin:
// OpenResty keeps its own under its prefix.
func ngxConfOf(pkg, bin string) string {
	if pkg == "openresty" || strings.HasPrefix(bin, "/usr/local/openresty/") {
		return hostenv.OpenRestyConf
	}
	return hostenv.NginxConf
}

// nginxVersion finds the installed nginx. The binary's version is read from
// the file, not by running it.
var nginxVersion = func(ctx context.Context) ngxInstall {
	removed := false
	for _, p := range nginxPackages {
		out, err := ngxRun(ctx, "dpkg-query", "-W", "-f", "${db:Status-Status} ${Version}", p)
		switch f := strings.Fields(string(out)); {
		case err == nil && len(f) == 2 && f[0] == "installed":
			return ngxInstall{version: f[1], pkg: p, dist: "dpkg", conf: ngxConfOf(p, "")}
		case len(f) > 0 && f[0] == "config-files":
			removed = true // dpkg -r without --purge: the configuration stays
		}
	}
	for _, p := range []string{"nginx", "openresty"} {
		if out, err := ngxRun(ctx, "rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", p); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" && !strings.Contains(v, "not installed") {
				return ngxInstall{version: v, pkg: p, dist: "rpm", conf: ngxConfOf(p, "")}
			}
		}
	}
	for _, b := range nginxBinaries {
		if data, err := ngxRead(b); err == nil {
			if m := ngxVersionString.FindSubmatch(data); m != nil {
				return ngxInstall{version: string(m[1]), conf: ngxConfOf("", b)}
			}
		}
	}
	// rpm -e keeps a changed configuration as nginx.conf.rpmsave
	for _, c := range []string{hostenv.NginxConf, hostenv.OpenRestyConf} {
		removed = removed || ngxExists(c+".rpmsave")
	}
	return ngxInstall{removed: removed}
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

// nginxFeatures reads what of nginx's configuration at conf the advisories need.
var nginxFeatures = func(conf string) hostenv.NginxFeatures { return hostenv.NginxFeaturesAt(hostSource(), conf) }

// nginxRisks is the risk of nginx's 2026-11-18 advisories on this server, if any.
func nginxRisks(ctx context.Context) []Risk {
	in := nginxVersion(ctx)
	v, conf := in.version, in.conf
	if conf == "" {
		conf = hostenv.NginxConf
	}
	f := nginxFeatures(conf)
	if v == "" && f.Found && !in.removed {
		// nginx is configured, but neither a package nor a binary where one is
		// looked for gives its version (a build installed elsewhere, a fork);
		// a package removed without its configuration is no nginx
		return []Risk{{uncheckedPrefix + "nginx:version", "info", conf + " is there, but the version of nginx could not be found " +
			"(no package, no binary in " + strings.Join(nginxBinaries, ", ") + "), so whether CVE-2026-123007, CVE-2026-118899 " +
			"and the other nginx advisories of 2026-11-18 affect it is unknown"}}
	}
	log := ""
	if in.pkg != "" && len(nginxAffected(v, slices.Concat(nginxH2CVEs, nginxTLS13CVE, nginxMailCVE, nginxOtherCVEs))) > 0 {
		log = nginxChangelog(ctx, in.pkg, in.dist)
	}
	open := func(list []nginxCVE) []string {
		var out []string
		for _, c := range nginxAffected(v, list) {
			if !mentionsCVE(log, c) {
				out = append(out, c) // not backported by the package
			}
		}
		return out
	}
	rel, _ := nginxRelease(v)
	tls13 := f.TLS13 || f.TLSDefault && atLeast(rel, nginxTLS13Default)
	var out []Risk
	var unknown []string // in range, but the configuration that decides could not all be read
	for _, g := range []struct {
		cves []string
		on   bool
		why  string
	}{
		{open(nginxH2CVEs), f.HTTP2, " serves HTTP/2, which %s (HTTP/2 memory corruption: " +
			"a client can crash the worker processes; a public proof of concept exists). Upgrade to 1.31.9 (mainline) or 1.30.7 (stable), " +
			"or to your distribution's fixed package; until then, turning HTTP/2 off (remove http2 from listen, or http2 off;) avoids it, " +
			"and clients fall back to HTTP/1.1"},
		{open(nginxTLS13CVE), tls13, " serves TLS 1.3, which %s (an infinite loop while reading a request body over TLS 1.3: " +
			"a client can tie up the worker processes). Turning HTTP/2 off does not avoid it; an nginx built with OpenSSL older than 1.1.1 has no TLS 1.3 and is not affected. Upgrade to 1.31.9 (mainline) or 1.30.7 (stable), " +
			"or to your distribution's fixed package"},
		{open(nginxMailCVE), f.Mail, " runs the mail proxy (a mail block with a server), which %s (a use-after-free in the mail proxy module). " +
			"Upgrade to 1.31.9 (mainline) or 1.30.7 (stable), or to your distribution's fixed package; a mail block not needed can be removed"},
	} {
		switch {
		case len(g.cves) == 0:
		case g.on:
			out = append(out, Risk{"nginx:" + g.cves[0], "warning", "nginx " + v + fmt.Sprintf(g.why, affects(g.cves)) +
				". If your distribution has published a fixed package, its advisory is what counts " +
				"(an image without package changelogs, such as Ubuntu's minimized ones, keeps this warning after the fix)"})
		case !f.Found || len(f.Unread) > 0:
			unknown = append(unknown, g.cves...)
		}
	}
	if len(unknown) > 0 {
		why := conf + " was not found"
		if f.Found {
			why = strings.Join(f.Unread, ", ") + " could not be read"
		}
		out = append(out, Risk{uncheckedPrefix + "nginx:" + unknown[0], "info", "nginx " + v + " is in the range of " +
			strings.Join(unknown, ", ") + ", but whether it serves HTTP/2, TLS 1.3 or the mail proxy, which they need, is unknown: " + why})
	}
	if other := open(nginxOtherCVEs); len(other) > 0 {
		out = append(out, Risk{"nginx:" + other[0], "info", "nginx " + v + " is in the range of " + strings.Join(other, ", ") +
			" (medium and minor: the resolver, HTTP/3, stream with client certificates or ssl_preread, try_files with alias, " +
			"PROXY protocol v2), which this check does not look for in the configuration. Upgrade to 1.31.9 (mainline) or 1.30.7 (stable), " +
			"or to your distribution's fixed package"})
	}
	return out
}

// affects is "X affects" or "X and Y affect".
func affects(cves []string) string {
	if len(cves) == 1 {
		return cves[0] + " affects"
	}
	return strings.Join(cves, " and ") + " affect"
}
