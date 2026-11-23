package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
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
var nginxPackages = hostenv.NginxPackages

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
// (up to 64 MiB) and look for a file, all through the host source (a
// replay, or another host's survey, is never answered by the machine
// running it); variables for the tests. ngxRun takes the query's argv
// (hostenv's, allowlisted exactly); a command that exits non-zero is an
// error, its output kept (dpkg-query's "config-files").
var (
	ngxRun = func(ctx context.Context, argv []string) ([]byte, error) {
		res, err := hostSource().Run(ctx, argv)
		if err == nil && res.ExitCode != 0 {
			err = fmt.Errorf("%s exited %d", argv[0], res.ExitCode)
		}
		return res.Stdout, err
	}
	ngxRead   = func(p string) ([]byte, error) { return hostenv.ReadFileMax(hostSource(), p, 64<<20) }
	ngxExists = func(p string) bool { _, err := hostenv.Stat(hostSource(), p); return err == nil }
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
		out, err := ngxRun(ctx, hostenv.DpkgStatusArgv(p))
		switch f := strings.Fields(string(out)); {
		case err == nil && len(f) == 2 && f[0] == "installed":
			return ngxInstall{version: f[1], pkg: p, dist: "dpkg", conf: ngxConfOf(p, "")}
		case len(f) > 0 && f[0] == "config-files":
			removed = true // dpkg -r without --purge: the configuration stays
		}
	}
	for _, p := range hostenv.NginxRPMs {
		if out, err := ngxRun(ctx, hostenv.RPMVersionArgv(p)); err == nil {
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
			if b, err := hostSource().ReadFile("/usr/share/doc/" + n + "/changelog.Debian.gz"); err == nil {
				if z, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
					text, _ := io.ReadAll(io.LimitReader(z, 16<<20))
					return string(text)
				}
			}
		}
	case "rpm":
		if out, err := ngxRun(ctx, hostenv.RPMChangelogArgv(pkg)); err == nil {
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

// nginxHTTP2 reports whether nginx's configuration at conf speaks HTTP/2.
var nginxHTTP2 = func(conf string) (on, found bool, unread []string) { return hostenv.NginxHTTP2At(hostSource(), conf) }

// nginxH2Risk is the risk of nginx's HTTP/2 advisories on this server, if any.
func nginxH2Risk(ctx context.Context) []Risk {
	in := nginxVersion(ctx)
	v, conf := in.version, in.conf
	if conf == "" {
		conf = hostenv.NginxConf
	}
	cves := nginxH2Affected(v)
	if in.pkg != "" && len(cves) > 0 {
		log := nginxChangelog(ctx, in.pkg, in.dist)
		var open []string
		for _, c := range cves {
			if !mentionsCVE(log, c) {
				open = append(open, c) // not backported by the package
			}
		}
		cves = open
	}
	on, found, unread := nginxHTTP2(conf)
	if v == "" && found && !in.removed {
		// nginx is configured, but neither a package nor a binary where one is
		// looked for gives its version (a build installed elsewhere, a fork);
		// a package removed without its configuration is no nginx
		return []Risk{{uncheckedPrefix + "nginx:version", "info", conf + " is there, but the version of nginx could not be found " +
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
			", but " + conf + " was not found, so whether it serves HTTP/2 is unknown"}}
	case len(unread) > 0:
		// A file not read may be the one turning HTTP/2 on: not "not exposed".
		return []Risk{{uncheckedPrefix + "nginx:" + cves[0], "info", "nginx " + v + " is in the range of " + ids +
			", but whether it serves HTTP/2 is unknown: " + strings.Join(unread, ", ") + " could not be read"}}
	}
	return nil
}
