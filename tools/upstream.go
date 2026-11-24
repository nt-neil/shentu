package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/hostenv"
)

// Third-party packages compared with their upstream's advisories (plan
// cd58fb, PR-B). OSV publishes the distributions' advisories only, so PHP
// from deb.sury.org, the ondrej PPA or Remi's repository, and nginx from
// nginx.org, matched nothing there. For these two the upstream versions are
// known here (php.net's and nginx.org's of 2026-11-19, the tables of the
// PHP and nginx checks): a third-party package of them is compared with
// those, and a CVE its changelog names (a backported fix) is not reported.
// The package scan's own OSV results are kept: an outdated build can be
// older than the distribution's fix, and OSV then says so rightly.

// upstreamHit is a third-party package compared with its upstream.
type upstreamHit struct {
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	Origin     string   `json:"origin"`
	Upstream   string   `json:"upstream"` // php or nginx
	Affected   []string `json:"affected,omitempty"`
	Fixed      string   `json:"fixed,omitempty"`
	Backported []string `json:"backported,omitempty"` // in the range, named in the package's changelog
	AsOf       string   `json:"as_of"`                // the tables' date: CVEs published since are not known
}

// upstreamAsOf is the date of the PHP and nginx checks' tables.
const upstreamAsOf = "2026-11-19"

// newerThanTables: a version past the newest release the tables know (PHP
// 8.2.36, 8.3.37, 8.4.28, 8.5.13; nginx 1.30.7, 1.31.9) may have CVEs
// published since; it is not compared, never "none affected".
var newerThanTables = "newer than the " + upstreamAsOf + " tables: CVEs published since are not known here"

func phpNewer(v [3]int) bool {
	newest := 0
	for m := range phpFixed {
		newest = max(newest, m)
	}
	return v[0] > 8 || v[1] > newest || v[2] > phpFixed[v[1]]
}

func nginxNewer(v [3]int) bool {
	return v[0] > 1 || v[1] > 31 || v[1] == 31 && v[2] > 9 || v[1] == 30 && v[2] > 7
}

// phpSAPIPackage: Debian's and sury's php8.3-cli, -fpm, -cgi and
// libapache2-mod-php8.3; Remi's php83-php-cli...; Remi's modular php-cli.
var phpSAPIPackage = regexp.MustCompile(`^(?:php\d\.\d-(cli|fpm|cgi)|libapache2-mod-php\d\.\d|php\d\d-php-(cli|fpm|cgi)|php-(cli|fpm|cgi))(?::[a-z0-9]+)?$`)

// upstreamCompare compares the set's third-party PHP and nginx packages
// with their upstream. why names, for a third-party package of them that
// could not be compared, the reason; the other third-party packages are
// neither in hits nor in why.
func upstreamCompare(ctx context.Context, set hostenv.PackageSet) (hits []upstreamHit, why map[string]string) {
	why = map[string]string{}
	for _, it := range set.Items {
		if it.Origin == "" {
			continue
		}
		h := upstreamHit{Package: it.Name, Version: it.Version, Origin: it.Origin, AsOf: upstreamAsOf}
		var ids []string
		switch m := phpSAPIPackage.FindStringSubmatch(it.Name); {
		case m != nil:
			h.Upstream = "php"
			v, ok := phpRelease(it.Version)
			switch {
			case !ok:
				why[it.Name] = "the PHP version could not be read"
				continue
			case phpEOL(v):
				why[it.Name] = fmt.Sprintf("PHP %d.%d is a branch php.net no longer fixes", v[0], v[1])
				continue
			case phpNewer(v):
				why[it.Name] = newerThanTables
				continue
			}
			sapi := m[1] + m[2] + m[3] // "" for mod_php: the engine only
			ids = phpAffected(v, phpOtherCVEs)
			if sapi == "fpm" {
				ids = append(ids, phpAffected(v, phpFPMCVEs)...)
				ids = append(ids, phpAffected(v, phpStatusCVE)...)
			}
			if sapi == "cgi" {
				ids = append(ids, phpAffected(v, phpCGICVE)...)
			}
			if len(ids) > 0 {
				h.Fixed = fmt.Sprintf("%d.%d.%d", v[0], v[1], phpFixed[v[1]])
			}
		case strings.TrimSuffix(it.Name, ":"+archOf(it.Name)) == "nginx":
			h.Upstream = "nginx"
			v, ok := nginxRelease(it.Version)
			if !ok {
				why[it.Name] = "the nginx version could not be read"
				continue
			}
			if nginxNewer(v) {
				why[it.Name] = newerThanTables
				continue
			}
			for _, l := range [][]nginxCVE{nginxH2CVEs, nginxTLS13CVE, nginxMailCVE, nginxOtherCVEs} {
				ids = append(ids, nginxAffected(it.Version, l)...)
			}
			if len(ids) > 0 {
				h.Fixed = "1.31.9"
				if v[0] == 1 && v[1] <= 30 {
					h.Fixed = "1.30.7"
				}
			}
		default:
			continue
		}
		if len(ids) > 0 {
			cl := upstreamChangelog(ctx, it.Name, set.Manager)
			for _, id := range ids {
				if mentionsCVE(cl, id) {
					h.Backported = append(h.Backported, id)
				} else {
					h.Affected = append(h.Affected, id)
				}
			}
		}
		hits = append(hits, h)
	}
	return hits, why
}

// archOf is the ":arm64" of a multiarch package name, "" for none.
func archOf(name string) string {
	if _, a, ok := strings.Cut(name, ":"); ok {
		return a
	}
	return ""
}

// upstreamChangelog is a package's changelog on the host read: Debian's
// changelog.Debian.gz, or rpm's.
func upstreamChangelog(ctx context.Context, name, manager string) string {
	name, _, _ = strings.Cut(name, ":")
	switch manager {
	case "dpkg":
		if b, err := hostenv.ReadFileMax(hostSource(), "/usr/share/doc/"+name+"/changelog.Debian.gz", 16<<20); err == nil {
			if z, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
				text, _ := io.ReadAll(io.LimitReader(z, 16<<20))
				return string(text)
			}
		}
	case "rpm":
		if out, err := phpRun(ctx, hostenv.RPMChangelogArgv(name)); err == nil {
			return string(out)
		}
	}
	return ""
}

// upstreamSurface is the vulnerability surface's entries of hits: one per
// CVE, in the upstream's ecosystem, marked KEV from kev (nil: unknown).
func upstreamSurface(hits []upstreamHit, kev map[string]kevEntry) []detect.PackageVuln {
	var out []detect.PackageVuln
	for _, h := range hits {
		for _, id := range h.Affected {
			v := detect.PackageVuln{Source: "os", Ecosystem: "upstream:" + h.Upstream, Package: h.Package, Version: h.Version,
				ID: id, CVE: id, CVEs: []string{id}, Fixed: h.Fixed}
			if e, ok := kev[id]; ok {
				v.KEV, v.KEVSince, v.KEVCVE = true, e.Added, id
			}
			out = append(out, v)
		}
	}
	return out
}
