package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// php.net's releases of 2026-11-19, 8.2.36, 8.3.37, 8.4.28, 8.5.13 and
// 8.6.0, fix 18 CVEs (ChangeLog-8). Three are in PHP-FPM: CVE-2026-129291
// (an epoll use-after-free, local privilege escalation) and CVE-2026-129289
// (request smuggling through an unread request body) reach a host whose
// php-fpm runs, CVE-2026-129292 (XSS in the status page) one whose
// pm.status_path can be reached from outside. CVE-2026-129538 (out-of-bounds
// read and write while correcting PATH_INFO) is in php-cgi, the CGI and
// FastCGI binary, which is how IIS runs PHP. The other fourteen are in the
// engine and the extensions every PHP has: one line by version. The package
// scan has none of this for PHP from deb.sury.org, the ondrej PPA or Remi's
// repository (the distribution has no such source package, or the fixed
// version compares older), from the official Docker images, a build from
// source, or under IIS. This check reads the version each PHP binary names
// itself with (its X-Powered-By header; the binary is read, not run, so no
// extension's code runs) and a package's changelog for the CVEs it
// backported.

// phpCVE is one advisory: from is the first 8.x branch it is in.
type phpCVE struct {
	id   string
	from int
}

var (
	phpFPMCVEs   = []phpCVE{{"CVE-2026-129291", 2}, {"CVE-2026-129289", 2}}
	phpStatusCVE = []phpCVE{{"CVE-2026-129292", 2}}
	phpCGICVE    = []phpCVE{{"CVE-2026-129538", 2}}
	// Date, Phar, Session, SOAP, Standard (streams, HTTP headers) from 8.2;
	// a Session one from 8.3, DOM from 8.4, Core and URI from 8.5
	phpOtherCVEs = []phpCVE{{"CVE-2026-129496", 2}, {"CVE-2026-128090", 2}, {"CVE-2026-126714", 2}, {"CVE-2026-115560", 2},
		{"CVE-2026-15353", 2}, {"CVE-2026-129506", 2}, {"CVE-2026-128064", 2}, {"CVE-2026-127960", 2}, {"CVE-2026-129481", 3},
		{"CVE-2026-129501", 4}, {"CVE-2026-129474", 5}, {"CVE-2026-129182", 5}, {"CVE-2026-48841", 5}, {"CVE-2026-129438", 5}}
	// phpFixed is the fixed release of each 8.x branch; 8.6 came out fixed.
	phpFixed = map[int]int{2: 36, 3: 37, 4: 28, 5: 13}
)

// phpRelease is the upstream version in a binary's or a package's version
// ("8.4.20-1+deb.sury.org+1", "1:8.2.20-1.el9.remi", "8.3.6-0ubuntu0.24.04.5").
func phpRelease(version string) ([3]int, bool) {
	if i := strings.IndexByte(version, ':'); i >= 0 {
		version = version[i+1:] // the epoch
	}
	if i := strings.IndexAny(version, "-~+"); i >= 0 {
		version = version[:i] // the packager's revision
	}
	var v [3]int
	f := strings.Split(version, ".")
	if len(f) != 3 {
		return v, false
	}
	for i, s := range f {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return [3]int{}, false // 8.3.0RC1, 8.3.x: not read as 8.3.0 or 8.3
		}
		v[i] = n
	}
	return v, true
}

// phpAffected is the advisories of list a PHP version is in.
func phpAffected(v [3]int, list []phpCVE) []string {
	if v[0] != 8 || v[1] < 2 || v[1] > 5 || v[2] >= phpFixed[v[1]] {
		return nil // fixed, a later branch, or one php.net no longer fixes
	}
	var out []string
	for _, c := range list {
		if v[1] >= c.from {
			out = append(out, c.id)
		}
	}
	return out
}

// phpEOL reports whether v is a branch php.net no longer fixes (before 8.2).
func phpEOL(v [3]int) bool { return v[0] > 0 && (v[0] < 8 || v[0] == 8 && v[1] < 2) }

// phpInstall is one PHP binary: its version (as it names itself), its SAPI
// (fpm, cgi or cli), the package holding it ("" for none) and, under IIS,
// that IIS is configured to run it.
type phpInstall struct {
	bin, version, sapi    string
	pkg, pkgVersion, dist string
	iis                   bool
}

// phpBinGlobs are where PHP binaries are: the distributions' (Debian's
// php8.3, php-fpm8.3, php-cgi8.3 and /usr/lib/cgi-bin), the official Docker
// images' and a build from source's (/usr/local), Remi's collections.
var phpBinGlobs = []string{"/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/lib/cgi-bin/php*", "/usr/local/bin/php*",
	"/usr/local/sbin/php-fpm*", "/opt/remi/php*/root/usr/bin/php*", "/opt/remi/php*/root/usr/sbin/php-fpm*"}

// phpBinName is a PHP binary's name, not php-config's, phpize's or phpdbg's.
var phpBinName = regexp.MustCompile(`^php(-cgi|-fpm)?(\d+(\.\d+)?)?$`)

// phpVersionString is the X-Powered-By header PHP's core keeps as one string.
var phpVersionString = regexp.MustCompile(`X-Powered-By: PHP/(\d+\.\d+\.\d+[0-9A-Za-z.+~-]*)\x00`)

// The host for the tests: the root the Linux paths are under, the package
// manager, the process list, IIS's FastCGI applications and reading a binary.
var (
	phpRoot    = "/"
	phpWindows = runtime.GOOS == "windows"
	phpRun     = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	}
	phpProcs = func() ([]hostenv.Process, bool) {
		o, _ := linux.Processes(hostSource(), nil)
		return o.Value, o.Known()
	}
	phpWinFastCGI = func() ([]string, error) { return hostenv.IISFastCGI(winSource()) }
	phpReadBin    = func(p string) ([]byte, error) {
		if phpWindows {
			return hostenv.ReadFileMax(winSource(), p, 64<<20)
		}
		return ngxRead(filepath.Join(phpRoot, p))
	}
)

// phpInstalls finds the PHP binaries; unread are the ones that could not be
// checked (IIS's configuration, a php-cgi.exe without a version).
func phpInstalls(ctx context.Context) (ins []phpInstall, unread []string) {
	if phpWindows {
		apps, err := phpWinFastCGI()
		if err != nil {
			return nil, []string{"applicationHost.config could not be read (" + err.Error() + ")"}
		}
		for _, a := range apps {
			i := strings.LastIndex(a, `\`)
			if !strings.EqualFold(a[i+1:], "php-cgi.exe") {
				continue
			}
			v := ""
			for _, p := range []string{a[:i+1] + "php8ts.dll", a[:i+1] + "php8.dll", a[:i+1] + "php7ts.dll", a[:i+1] + "php7.dll", a} {
				if data, err := phpReadBin(p); err == nil {
					if m := phpVersionString.FindSubmatch(data); m != nil {
						v = string(m[1])
						break
					}
				}
			}
			if v == "" {
				unread = append(unread, a+" (no version found)")
				continue
			}
			ins = append(ins, phpInstall{bin: a, version: v, sapi: "cgi", iis: true})
		}
		return ins, unread
	}
	root, err := filepath.EvalSymlinks(phpRoot)
	if err != nil {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, g := range phpBinGlobs {
		matches, _ := filepath.Glob(filepath.Join(root, g))
		for _, m := range matches {
			if !phpBinName.MatchString(filepath.Base(m)) {
				continue
			}
			real, err := filepath.EvalSymlinks(m) // /usr/bin/php → /etc/alternatives/php → /usr/bin/php8.3
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(root, real)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			p := "/" + filepath.ToSlash(rel)
			if seen[p] {
				continue
			}
			seen[p] = true
			if st, err := os.Stat(real); err != nil || !st.Mode().IsRegular() {
				continue
			}
			data, err := phpReadBin(p)
			if err != nil {
				continue
			}
			v := phpVersionString.FindSubmatch(data)
			if v == nil {
				continue // a script, or not PHP
			}
			in := phpInstall{bin: p, version: string(v[1]), sapi: "cli"}
			switch base := filepath.Base(p); {
			case strings.Contains(base, "fpm"):
				in.sapi = "fpm"
			case strings.Contains(base, "cgi") || strings.Contains(p, "/cgi-bin/"):
				in.sapi = "cgi"
			}
			in.pkg, in.pkgVersion, in.dist = phpPackage(ctx, p)
			ins = append(ins, in)
		}
	}
	return ins, nil
}

// phpPackage is the package holding the binary at p, its version and the
// package manager; "" when none does.
func phpPackage(ctx context.Context, p string) (pkg, version, dist string) {
	if out, err := phpRun(ctx, "dpkg-query", "-S", p); err == nil {
		line, _, _ := strings.Cut(string(out), "\n")
		if name, _, ok := strings.Cut(line, ": "); ok {
			name, _, _ = strings.Cut(name, ", ")
			if o, err := phpRun(ctx, "dpkg-query", "-W", "-f", "${db:Status-Status} ${Version}", name); err == nil {
				if f := strings.Fields(string(o)); len(f) == 2 && f[0] == "installed" {
					return name, f[1], "dpkg"
				}
			}
		}
	}
	if out, err := phpRun(ctx, "rpm", "-qf", "--qf", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}", p); err == nil {
		if f := strings.Fields(string(out)); len(f) == 2 && !strings.Contains(string(out), "not owned") {
			return f[0], f[1], "rpm"
		}
	}
	return "", "", ""
}

// phpChangelog is a package's changelog, where its packager names the CVEs
// it backported a fix of without changing the version.
func phpChangelog(ctx context.Context, in phpInstall, branch string) string {
	switch in.dist {
	case "dpkg":
		name, _, _ := strings.Cut(in.pkg, ":") // php8.3-cli:amd64
		for _, n := range []string{name, "php" + branch + "-common"} {
			if b, err := os.ReadFile(filepath.Join(phpRoot, "/usr/share/doc", n, "changelog.Debian.gz")); err == nil {
				if z, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
					text, _ := io.ReadAll(io.LimitReader(z, 16<<20))
					return string(text)
				}
			}
		}
	case "rpm":
		if out, err := phpRun(ctx, "rpm", "-q", "--changelog", in.pkg); err == nil {
			return string(out)
		}
	}
	return ""
}

// phpGroup is the binaries of one PHP build: one version from one source.
type phpGroup struct {
	version string
	ins     []phpInstall
}

func phpGroups(ins []phpInstall) []phpGroup {
	var out []phpGroup
	at := map[string]int{}
	for _, in := range ins {
		k := in.version + "|" + in.pkgVersion
		if i, ok := at[k]; ok {
			out[i].ins = append(out[i].ins, in)
			continue
		}
		at[k] = len(out)
		out = append(out, phpGroup{version: in.version, ins: []phpInstall{in}})
	}
	return out
}

// where names the group's binaries and where they come from.
func (g phpGroup) where() string {
	var bins []string
	for _, in := range g.ins {
		bins = append(bins, in.bin)
	}
	in := g.ins[0]
	from := "not from a package, which the package scan does not cover"
	switch {
	case in.iis:
		from = "run by IIS as its FastCGI application, which the package scan does not cover"
	case strings.Contains(in.pkgVersion, "deb.sury.org"):
		from = "package " + in.pkg + " " + in.pkgVersion + " from deb.sury.org or the ondrej PPA, which the package scan does not cover"
	case strings.Contains(in.pkgVersion, "remi") || strings.HasPrefix(in.bin, "/opt/remi/"):
		from = "package " + in.pkg + " " + in.pkgVersion + " from Remi's repository, which the package scan does not cover"
	case in.pkg != "":
		from = "package " + in.pkg + " " + in.pkgVersion
	}
	return strings.Join(bins, ", ") + ": " + from
}

// thirdParty reports whether no distribution's advisories speak for the
// group: not from a package, or from deb.sury.org, the PPA, Remi, IIS.
func (g phpGroup) thirdParty() bool {
	in := g.ins[0]
	return in.pkg == "" || in.iis || strings.Contains(in.pkgVersion, "deb.sury.org") || strings.Contains(in.pkgVersion, "remi") ||
		strings.HasPrefix(in.bin, "/opt/remi/")
}

func (g phpGroup) has(sapi string) bool {
	return slices.ContainsFunc(g.ins, func(in phpInstall) bool { return in.sapi == sapi })
}

// runs reports whether a binary of the group with the SAPI runs: IIS is
// configured with it, or a process is it (by name when its path is unknown).
func (g phpGroup) runs(sapi string, procs []hostenv.Process) bool {
	for _, in := range g.ins {
		if in.sapi != sapi {
			continue
		}
		if in.iis {
			return true
		}
		for _, p := range procs {
			if exe := strings.TrimSuffix(p.Exe, " (deleted)"); exe == in.bin || exe == "" && strings.HasPrefix(p.Name, "php-"+sapi) {
				return true
			}
		}
	}
	return false
}

// phpPoolGlobs are PHP-FPM's configuration and pools: Debian's, RHEL's,
// Remi's collections', the official Docker images' and a source build's.
var phpPoolGlobs = []string{"/etc/php/*/fpm/php-fpm.conf", "/etc/php/*/fpm/pool.d/*.conf", "/etc/php-fpm.conf", "/etc/php-fpm.d/*.conf",
	"/etc/opt/remi/*/php-fpm.conf", "/etc/opt/remi/*/php-fpm.d/*.conf", "/usr/local/etc/php-fpm.conf", "/usr/local/etc/php-fpm.d/*.conf"}

// phpWebGlobs are the web servers' files that may pass a path on to FPM.
var phpWebGlobs = []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
	"/usr/local/openresty/nginx/conf/nginx.conf", "/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*",
	"/etc/apache2/conf-enabled/*", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf"}

// phpReadGlobs reads the files of globs under phpRoot; unread are those that
// are there but could not be read.
func phpReadGlobs(globs []string) (files map[string]string, unread []string) {
	files = map[string]string{}
	for _, g := range globs {
		matches, _ := filepath.Glob(filepath.Join(phpRoot, g))
		for _, m := range matches {
			p := "/" + strings.TrimPrefix(filepath.ToSlash(strings.TrimPrefix(m, filepath.Clean(phpRoot))), "/")
			b, err := os.ReadFile(m)
			switch {
			case err == nil:
				files[p] = string(b)
			case errors.Is(err, fs.ErrPermission):
				unread = append(unread, p+" (permission denied)")
			}
		}
	}
	return files, unread
}

// phpStatusExposed finds a pool's status page (pm.status_path) reachable from
// outside: its socket (pm.status_listen, else the pool's listen) on an
// address other than the host's own, or a web server passing the path on to
// FPM without keeping it to the host. path is the page; unread the files
// that decide and could not be read.
func phpStatusExposed() (path string, exposed bool, unread []string) {
	pools, unread := phpReadGlobs(phpPoolGlobs)
	type pool struct{ listen, status, statusListen string }
	by := map[string]*pool{}
	for _, text := range pools {
		var cur *pool
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == ';' || line[0] == '#' {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				name := line[1 : len(line)-1]
				if by[name] == nil {
					by[name] = &pool{}
				}
				cur = by[name]
				if name == "global" {
					cur = nil
				}
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || cur == nil {
				continue
			}
			v = strings.TrimSpace(v)
			if i := strings.Index(v, " ;"); i >= 0 && !strings.HasPrefix(v, `"`) {
				v = strings.TrimSpace(v[:i]) // an inline comment
			}
			v = strings.Trim(v, `"'`)
			switch strings.TrimSpace(k) {
			case "listen":
				cur.listen = v
			case "pm.status_path":
				cur.status = v
			case "pm.status_listen":
				cur.statusListen = v
			}
		}
	}
	var paths []string
	for _, p := range by {
		if p.status == "" {
			continue
		}
		paths = append(paths, p.status)
		l := p.statusListen
		if l == "" {
			l = p.listen
		}
		if phpNetAddr(l) {
			return p.status, true, nil
		}
	}
	if len(paths) == 0 {
		return "", false, unread
	}
	slices.Sort(paths)
	web, wunread := phpReadGlobs(phpWebGlobs)
	unread = append(unread, wunread...)
	for _, sp := range paths {
		for _, text := range web {
			if ngxPassesTo(text, sp) || apachePassesTo(text, sp) {
				return sp, true, nil
			}
		}
	}
	return paths[0], false, unread
}

// phpNetAddr reports whether an FPM listen address takes connections from
// other hosts: a port alone (every address) or an address not the host's own.
func phpNetAddr(a string) bool {
	a = strings.TrimSpace(a)
	if a == "" || strings.Contains(a, "/") {
		return false // none, or a Unix socket
	}
	if _, err := strconv.Atoi(a); err == nil {
		return true
	}
	host := a
	if i := strings.LastIndex(a, ":"); i >= 0 {
		host = a[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

var (
	ngxLocation   = regexp.MustCompile(`(?m)^\s*location\s+(=|~\*|~|\^~)?\s*("[^"]*"|\S+)\s*\{`)
	ngxKeptLocal  = regexp.MustCompile(`\bdeny\s+all\s*;|\binternal\s*;`)
	apacheBlock   = regexp.MustCompile(`(?is)<(Location|LocationMatch)\s+("[^"]*"|\S+?)\s*>(.*?)</(?:Location|LocationMatch)>`)
	apacheLocal   = regexp.MustCompile(`(?i)\bRequire\s+(local|ip|host|all\s+denied)\b|\bDeny\s+from\s+all\b`)
	apacheFCGI    = regexp.MustCompile(`(?i)proxy:.*fcgi:|\bProxyPass(Match)?\s+fcgi://`)
	apacheProxyRe = regexp.MustCompile(`(?im)^\s*ProxyPass(Match)?\s+("[^"]*"|\S+)\s+"?fcgi://`)
)

// ngxPassesTo reports whether an nginx file has a location that matches path
// and passes it on to FastCGI, not kept to some addresses (deny all) or to
// nginx itself (internal).
func ngxPassesTo(text, path string) bool {
	for _, m := range ngxLocation.FindAllStringSubmatchIndex(text, -1) {
		mod, pat := "", strings.Trim(text[m[4]:m[5]], `"`)
		if m[2] >= 0 {
			mod = text[m[2]:m[3]]
		}
		depth, end := 0, len(text)
		for i := m[1] - 1; i < len(text); i++ {
			if text[i] == '{' {
				depth++
			} else if text[i] == '}' {
				if depth--; depth == 0 {
					end = i
					break
				}
			}
		}
		body := text[m[1]:end]
		if !strings.Contains(body, "fastcgi_pass") || ngxKeptLocal.MatchString(body) {
			continue
		}
		if pathMatches(mod, pat, path) {
			return true
		}
	}
	return false
}

// apachePassesTo is ngxPassesTo for Apache: a Location or LocationMatch that
// hands path to FastCGI without Require local, ip or host, or a ProxyPass
// (Match) of it to fcgi://.
func apachePassesTo(text, path string) bool {
	for _, m := range apacheBlock.FindAllStringSubmatch(text, -1) {
		mod := "^~" // a Location is a prefix
		if strings.EqualFold(m[1], "LocationMatch") {
			mod = "~"
		}
		if apacheFCGI.MatchString(m[3]) && !apacheLocal.MatchString(m[3]) && pathMatches(mod, strings.Trim(m[2], `"`), path) {
			return true
		}
	}
	for _, m := range apacheProxyRe.FindAllStringSubmatch(text, -1) {
		mod := "^~"
		if m[1] != "" {
			mod = "~"
		}
		if pathMatches(mod, strings.Trim(m[2], `"`), path) {
			return true
		}
	}
	return false
}

// pathMatches reports whether a location of modifier mod (=, ~, ~*, ^~ or
// none) and pattern pat matches path.
func pathMatches(mod, pat, path string) bool {
	switch mod {
	case "=":
		return pat == path
	case "~", "~*":
		if mod == "~*" {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
		return err == nil && re.MatchString(path)
	}
	return strings.HasPrefix(path, pat)
}

// phpList is "X" or "X and Y" or "X, Y and Z".
func phpList(ids []string) string {
	if len(ids) < 2 {
		return strings.Join(ids, "")
	}
	return strings.Join(ids[:len(ids)-1], ", ") + " and " + ids[len(ids)-1]
}

// phpRisks is the risk of PHP's 2026-11-19 advisories on this server, if any.
func phpRisks(ctx context.Context) []Risk {
	ins, unread := phpInstalls(ctx)
	var out []Risk
	if len(unread) > 0 {
		out = append(out, Risk{uncheckedPrefix + "php:version", "info", "the PHP IIS runs could not be checked (" + strings.Join(unread, ", ") +
			"), so whether CVE-2026-129538 (php-cgi) and the other PHP advisories of 2026-11-19 affect it is unknown"})
	}
	if len(ins) == 0 {
		return out
	}
	var procs []hostenv.Process
	known := true
	if !phpWindows {
		procs, known = phpProcs()
	}
	statusRead := false
	var statusPath string
	var statusOut bool
	var statusUnread []string
	for _, g := range phpGroups(ins) {
		rel, ok := phpRelease(g.version)
		if !ok {
			continue
		}
		branch := fmt.Sprintf("%d.%d", rel[0], rel[1])
		key, name := "php"+branch+":", "PHP "+g.version+" ("+g.where()+")"
		if phpEOL(rel) {
			if g.thirdParty() {
				out = append(out, Risk{key + "eol", "info", name + " is a branch php.net no longer fixes; its fixes of 2026-11-19 " +
					"(18 CVEs) went into 8.2.36, 8.3.37, 8.4.28, 8.5.13 and 8.6.0. Move to a branch that is still fixed, " +
					"or ask whoever builds this one whether it carries the fixes"})
			}
			continue
		}
		log := ""
		if len(phpAffected(rel, slices.Concat(phpFPMCVEs, phpStatusCVE, phpCGICVE, phpOtherCVEs))) == 0 {
			continue
		}
		seenPkg := map[string]bool{}
		for _, in := range g.ins {
			if in.pkg != "" && !seenPkg[in.pkg] {
				seenPkg[in.pkg] = true
				log += phpChangelog(ctx, in, branch) + "\n"
			}
		}
		open := func(list []phpCVE) []string {
			var out []string
			for _, c := range phpAffected(rel, list) {
				if !mentionsCVE(log, c) {
					out = append(out, c) // not backported by the package
				}
			}
			return out
		}
		upgrade := fmt.Sprintf("Upgrade to PHP %s.%d (or 8.6), or to your package source's fixed build", branch, phpFixed[rel[1]])
		note := ". If your distribution has published a fixed package, its advisory is what counts " +
			"(an image without package changelogs keeps this warning after the fix)"
		fpmOn := g.has("fpm") && g.runs("fpm", procs)
		fpmUnknown := g.has("fpm") && !known && !fpmOn
		cgiOn := g.has("cgi") && g.runs("cgi", procs)
		cgiUnknown := g.has("cgi") && !known && !cgiOn
		var unknown []string
		why := "the process list could not be read"
		if c := open(phpFPMCVEs); len(c) > 0 {
			switch {
			case fpmOn:
				verb := " affect it "
				if len(c) == 1 {
					verb = " affects it "
				}
				out = append(out, Risk{key + c[0], "warning", name + ": php-fpm runs, and " + phpList(c) + verb +
					"(PHP-FPM: an epoll use-after-free that lets a local user gain the pool's or the master's privileges, " +
					"and request smuggling through a request body the script does not read). " + upgrade + note})
			case fpmUnknown:
				unknown = append(unknown, c...)
			}
		}
		if c := open(phpStatusCVE); len(c) > 0 && (fpmOn || fpmUnknown) {
			if !statusRead {
				statusPath, statusOut, statusUnread = phpStatusExposed()
				statusRead = true
			}
			switch {
			case statusOut && fpmOn:
				out = append(out, Risk{key + c[0], "warning", name + ": php-fpm's status page (pm.status_path " + statusPath +
					") can be reached from outside, and " + c[0] + " affects it (XSS: the page does not escape the user " +
					"and script it lists). " + upgrade + "; until then, keep the page to the host (allow 127.0.0.1; deny all; " +
					"or Require local) or remove pm.status_path" + note})
			case statusOut || len(statusUnread) > 0:
				unknown = append(unknown, c...)
				if !fpmUnknown {
					why = strings.Join(statusUnread, ", ") + " could not be read"
				}
			}
		}
		if c := open(phpCGICVE); len(c) > 0 {
			switch {
			case cgiOn:
				runs := "php-cgi runs"
				if g.ins[0].iis {
					runs = "IIS runs it through FastCGI"
				}
				out = append(out, Risk{key + c[0], "warning", name + ": " + runs + ", and " + c[0] + " affects it " +
					"(out-of-bounds read and write while php-cgi corrects PATH_INFO). " + upgrade + note})
			case cgiUnknown:
				unknown = append(unknown, c...)
			}
		}
		if len(unknown) > 0 {
			out = append(out, Risk{uncheckedPrefix + key + unknown[0], "info", name + " is in the range of " + phpList(unknown) +
				", but whether php-fpm or php-cgi runs (or php-fpm's status page can be reached), which they need, is unknown: " + why})
		}
		if c := open(phpOtherCVEs); len(c) > 0 {
			out = append(out, Risk{key + c[0], "warning", name + " is in the range of " + phpList(c) + " (the engine and the " +
				"extensions every PHP has: use-after-frees in Date, Session and SOAP that can lead to remote code execution, " +
				"a Phar signature downgrade, mixed-case HTTPS and FTPS URLs sent in plaintext, and more). " + upgrade + note})
		}
	}
	return out
}
