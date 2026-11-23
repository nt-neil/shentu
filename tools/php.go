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
	"path"
	"regexp"
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
	vendor                string // an rpm's %{VENDOR}
	iis                   bool
	apache                bool   // Apache runs it as CGI (Windows)
	conf                  string // the httpd.conf files that do, ", " between
	cgiOff                bool   // none of them loads cgi_module or cgid_module, all of them read
	cgiUnread             bool   // none seen loading cgi_module, but some of the configuration was not read
}

// phpBinGlobs are where PHP binaries are: the distributions' (Debian's
// php8.3, php-fpm8.3, php-cgi8.3 and /usr/lib/cgi-bin), the official Docker
// images' and a build from source's (/usr/local), Remi's collections,
// cPanel's EasyApache (ea-php) and CloudLinux's alt-php.
var phpBinGlobs = []string{"/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/lib/cgi-bin/php*", "/usr/local/bin/php*",
	"/usr/local/sbin/php-fpm*", "/opt/remi/php*/root/usr/bin/php*", "/opt/remi/php*/root/usr/sbin/php-fpm*",
	"/opt/cpanel/ea-php*/root/usr/bin/php*", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm*",
	"/opt/alt/php*/usr/bin/php*", "/opt/alt/php*/usr/sbin/php-fpm*"}

// phpBinName is a PHP binary's name, not php-config's, phpize's or phpdbg's.
var phpBinName = regexp.MustCompile(`^php(-cgi|-fpm)?(\d+(\.\d+)?)?$`)

// phpVersionString is the X-Powered-By header PHP's core keeps as one string.
var phpVersionString = regexp.MustCompile(`X-Powered-By: PHP/(\d+\.\d+\.\d+[0-9A-Za-z.+~-]*)\x00`)

// phpBinMax and phpConfMax cap what is read of a binary and of a
// configuration file or changelog.
var phpBinMax, phpConfMax = int64(64 << 20), int64(8 << 20)

// phpBinVersion is the version a binary names itself with. why says why
// there is none: several different ones, or a program (ELF, PE) or a
// read cut at phpBinMax without one; "" for a file that is no PHP (a script).
func phpBinVersion(data []byte) (v, why string) {
	var vs []string
	for _, m := range phpVersionString.FindAllSubmatch(data, -1) {
		if s := string(m[1]); !slices.Contains(vs, s) {
			vs = append(vs, s)
		}
	}
	switch {
	case len(vs) == 1:
		return vs[0], ""
	case len(vs) > 1:
		return "", "several versions: " + strings.Join(vs, ", ")
	case bytes.HasPrefix(data, []byte("\x7fELF")) || bytes.HasPrefix(data, []byte("MZ")) || int64(len(data)) >= phpBinMax:
		return "", "no version found"
	}
	return "", ""
}

// phpSource is the host the PHP check reads: hostSource, or on Windows
// winSource (as IIS's checks). Never the machine running the check when it
// reads a replay or another host's survey.
func phpSource() hostenv.Source {
	if phpOnWindows() {
		return winSource()
	}
	return hostSource()
}

// phpOnWindows: the host read is Windows (phpWindows: the tests' say).
func phpOnWindows() bool { return phpWindows || hostSource().Info().GOOS == "windows" }

// phpReadLimited reads a regular file of the host, at most max bytes;
// errTooLarge when there is more. Every read of a binary, a configuration
// file or a changelog goes through it: the host source opens without
// blocking and checks the open file itself, so a FIFO or a device is not
// waited on, and nothing can be swapped in between a check and the open.
func phpReadLimited(p string, max int64) ([]byte, error) {
	b, err := hostenv.ReadFileMax(phpSource(), p, max)
	switch {
	case errors.Is(err, hostenv.ErrTruncated):
		return b, errTooLarge
	case errors.Is(err, hostenv.ErrNotRegular):
		return nil, errNotRegular
	case err == nil && int64(len(b)) > max: // a source that does not cap
		return b[:max], errTooLarge
	}
	return b, err
}

var (
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("too large")
)

// The host for the tests: Windows or not, the package manager's queries,
// the process list, IIS's FastCGI applications and reading a binary. phpRun
// runs a query (hostenv's argv, allowlisted) on the host source; one that
// exits non-zero is an error.
var (
	phpWindows = false
	phpRun     = func(ctx context.Context, argv []string) ([]byte, error) {
		res, err := hostSource().Run(ctx, argv)
		if err == nil && res.ExitCode != 0 {
			err = fmt.Errorf("%s exited %d", argv[0], res.ExitCode)
		}
		return res.Stdout, err
	}
	phpProcs = func() ([]hostenv.Process, bool) {
		o, _ := linux.Processes(hostSource(), nil)
		return o.Value, o.Known()
	}
	phpWinFastCGI = func() ([]string, error) { return hostenv.IISFastCGI(winSource()) }
	phpReadBin    = func(p string) ([]byte, error) {
		full := p
		if phpOnWindows() {
			r, err := phpWinLocal(p)
			if err != nil {
				return nil, err
			}
			full = r
		}
		b, err := phpReadLimited(full, phpBinMax)
		if errors.Is(err, errTooLarge) {
			err = nil // what was read is searched; phpBinVersion knows it was cut
		}
		return b, err
	}
)

// phpInstalls finds the PHP binaries; unread are the ones that could not be
// checked (IIS's configuration, a php-cgi.exe without a version).
func phpInstalls(ctx context.Context) (ins []phpInstall, unread []string) {
	if phpOnWindows() {
		apps, err := phpWinFastCGI()
		if err != nil {
			return nil, []string{"applicationHost.config could not be read (" + err.Error() + ")"}
		}
		for _, a := range apps {
			a = strings.ReplaceAll(a, "/", `\`) // C:/PHP/php-cgi.exe
			if !strings.EqualFold(winBase(a), "php-cgi.exe") {
				continue
			}
			v, why := phpWinVersion(a)
			if v == "" {
				if why == "" {
					why = "no version found"
				}
				unread = append(unread, a+" ("+why+")")
				continue
			}
			ins = append(ins, phpInstall{bin: a, version: v, sapi: "cgi", iis: true})
		}
		confs, cunread := phpWinApacheConfs()
		unread = append(unread, cunread...)
		at := map[string]int{} // php-cgi.exe (lower case) -> index in ins: one entry, every conf named
		for _, conf := range confs {
			exes, un, cgiMod := phpApacheCGI(conf)
			unread = append(unread, un...)
			for _, a := range exes {
				if i, ok := at[strings.ToLower(a)]; ok {
					ins[i].conf += ", " + conf
					loaded := cgiMod || !ins[i].cgiOff && !ins[i].cgiUnread
					partial := ins[i].cgiUnread || len(un) > 0
					ins[i].cgiOff, ins[i].cgiUnread = !loaded && !partial, !loaded && partial
					continue
				}
				v, why := phpWinVersion(a)
				if v == "" {
					unread = append(unread, a+" ("+why+")")
					continue
				}
				at[strings.ToLower(a)] = len(ins)
				ins = append(ins, phpInstall{bin: a, version: v, sapi: "cgi", apache: true, conf: conf,
					cgiOff: !cgiMod && len(un) == 0, cgiUnread: !cgiMod && len(un) > 0})
			}
		}
		return ins, unread
	}
	src := hostSource()
	seen := map[string]bool{}
	var ids []string // of ins, to know a hard link of one ("" when the host cannot tell)
	for _, g := range phpBinGlobs {
		for _, m := range hostenv.Glob(src, g) {
			if !phpBinName.MatchString(path.Base(m)) {
				continue
			}
			p, err := hostenv.EvalSymlinks(src, m) // /usr/bin/php → /etc/alternatives/php → /usr/bin/php8.3
			if err != nil {
				continue
			}
			if seen[p] {
				continue
			}
			seen[p] = true
			st, err := hostenv.Stat(src, p)
			switch {
			case errors.Is(err, hostenv.ErrNoStat): // a replay: the read says whether it is a file
			case err != nil || !st.Mode.IsRegular():
				continue
			}
			data, err := phpReadBin(p)
			if err != nil {
				continue
			}
			v, why := phpBinVersion(data)
			if v == "" {
				if why != "" {
					unread = append(unread, p+" ("+why+")")
				}
				continue // a script, or not PHP
			}
			in := phpInstall{bin: p, version: v, sapi: "cli"}
			switch base := path.Base(p); {
			case strings.Contains(base, "fpm"):
				in.sapi = "fpm"
			case strings.Contains(base, "cgi") || strings.Contains(p, "/cgi-bin/"):
				in.sapi = "cgi"
			}
			in.pkg, in.pkgVersion, in.dist, in.vendor = phpPackage(ctx, p)
			if i := slices.Index(ids, st.ID); st.ID != "" && i >= 0 {
				// a hard link of a binary already found: one binary, the package's
				if ins[i].pkg == "" && in.pkg != "" {
					ins[i] = in
				}
				continue
			}
			ids = append(ids, st.ID)
			ins = append(ins, in)
		}
	}
	return ins, unread
}

// phpWinVersion is the version of the PHP whose php-cgi.exe is at exe: in
// PHP's core next to it (php8ts.dll, php8.dll, php7ts.dll, php7.dll), else
// in the program. why says why there is none: a path that is not a local
// absolute one (a network or device path is not read, so that reading it
// cannot make the host authenticate to another machine), several versions,
// or none found.
func phpWinVersion(exe string) (v, why string) {
	if !phpLocalWinPath(exe) {
		return "", "not a local absolute path"
	}
	d := winDir(exe) + `\`
	why = "no version found"
	for _, p := range []string{d + "php8ts.dll", d + "php8.dll", d + "php7ts.dll", d + "php7.dll", exe} {
		if data, err := phpReadBin(p); err == nil {
			if v, w := phpBinVersion(data); v != "" || strings.HasPrefix(w, "several") {
				return v, w
			}
		}
	}
	return "", why
}

// phpWinLocal is p with its links resolved, refused unless every step is
// a local absolute path: a symbolic link (or junction) in the path whose
// target is \\host\share or a device path would make the open connect to
// another machine (and hand it the host's credentials). Each component is
// looked at with Lstat before anything below it, and a target is checked
// before it is looked at, so nothing remote is ever touched. A link whose
// target cannot be read is not followed. Paths are cleaned first (slashes
// turned, "." and ".." resolved as Windows does), so the components looked
// at are the ones the open walks.
func phpWinLocal(p string) (string, error) {
	for hops := 0; ; hops++ {
		p = strings.ReplaceAll(p, "/", `\`)
		if !phpLocalWinPath(p) {
			return "", errNotLocal
		}
		p = winClean(p)
		if strings.ContainsAny(p[2:], ":?") { // an alternate data stream, or a device or wildcard spelling
			return "", errNotLocal
		}
		if hops > 16 {
			return "", errors.New("too many links, not read")
		}
		parts := strings.Split(strings.TrimRight(p[3:], `\`), `\`)
		cur, next := p[:2], ""
		for i, part := range parts {
			cur += `\` + part
			st, err := phpLstat(cur)
			if errors.Is(err, fs.ErrNotExist) {
				return p, nil // not there: the open says so
			}
			if err != nil {
				return "", fmt.Errorf("its links could not be checked (%w), not read", err)
			}
			if st&(fs.ModeSymlink|fs.ModeIrregular) == 0 {
				continue
			}
			t, err := phpReadlink(cur)
			if err != nil {
				return "", errors.New("a reparse point that is not a link, not followed")
			}
			t = strings.ReplaceAll(t, "/", `\`)
			switch {
			case phpLocalWinPath(t):
			case strings.HasPrefix(t, `\`) && !strings.HasPrefix(t, `\\`): // the root of the same drive
				t = cur[:2] + t
			case !strings.HasPrefix(t, `\`) && !strings.Contains(t, ":"): // relative to the link's folder
				t = winDir(cur) + `\` + t
			default:
				return "", errNotLocal
			}
			next = strings.Join(append([]string{strings.TrimRight(t, `\`)}, parts[i+1:]...), `\`)
			break
		}
		if next == "" {
			return p, nil
		}
		p = next
	}
}

// winClean is the local absolute path p (backslashes only) with empty,
// "." and ".." components resolved lexically, as Windows does before an
// open; ".." stops at the drive's root.
func winClean(p string) string {
	var out []string
	for _, c := range strings.Split(p[3:], `\`) {
		switch c {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, c)
		}
	}
	return p[:2] + `\` + strings.Join(out, `\`)
}

// phpLstat and phpReadlink look at one path component (tests replace them).
var (
	phpLstat = func(p string) (fs.FileMode, error) {
		st, err := hostenv.Lstat(winSource(), p)
		return st.Mode, err
	}
	phpReadlink = func(p string) (string, error) { return winSource().Readlink(p) }
)

// phpLocalWinPath reports whether p is a local absolute Windows path (C:\...):
// not relative, not \\host\share, not a device path (\\?\, \\.\).
func phpLocalWinPath(p string) bool {
	return len(p) >= 3 && (p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z') && p[1] == ':' && p[2] == '\\'
}

// phpPackage is the package holding the binary at p, its version, the
// package manager and (rpm) the vendor; "" when none does.
func phpPackage(ctx context.Context, p string) (pkg, version, dist, vendor string) {
	if out, err := phpRun(ctx, hostenv.DpkgSearchArgv(p)); err == nil {
		line, _, _ := strings.Cut(string(out), "\n")
		if name, _, ok := strings.Cut(line, ": "); ok {
			name, _, _ = strings.Cut(name, ", ")
			if o, err := phpRun(ctx, hostenv.DpkgStatusArgv(name)); err == nil {
				if f := strings.Fields(string(o)); len(f) == 2 && f[0] == "installed" {
					return name, f[1], "dpkg", ""
				}
			}
		}
	}
	if out, err := phpRun(ctx, hostenv.RPMOwnerArgv(p)); err == nil {
		line, _, _ := strings.Cut(string(out), "\n")
		if f := strings.Fields(line); len(f) >= 2 && !strings.Contains(line, "not owned") {
			return f[0], f[1], "rpm", strings.Join(f[2:], " ")
		}
	}
	return "", "", "", ""
}

// phpDistroVendors are the rpm vendors of distributions whose advisories
// reach the package scan; any other vendor (Remi, IUS, cPanel, CloudLinux's
// alt-php, none) is a third party.
var phpDistroVendors = []string{"red hat", "rocky", "almalinux", "fedora", "amazon", "centos", "oracle", "suse",
	"openanolis", "openeuler", "eurolinux", "cybertrust"}

func phpDistroVendor(v string) bool {
	v = strings.ToLower(v)
	return slices.ContainsFunc(phpDistroVendors, func(d string) bool { return strings.Contains(v, d) })
}

// phpChangelog is a package's changelog, where its packager names the CVEs
// it backported a fix of without changing the version.
func phpChangelog(ctx context.Context, in phpInstall, branch string) string {
	switch in.dist {
	case "dpkg":
		name, _, _ := strings.Cut(in.pkg, ":") // php8.3-cli:amd64
		for _, n := range []string{name, "php" + branch + "-common"} {
			if b, err := phpReadLimited("/usr/share/doc/"+n+"/changelog.Debian.gz", phpConfMax); err == nil {
				if z, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
					text, _ := io.ReadAll(io.LimitReader(z, 16<<20))
					return string(text)
				}
			}
		}
	case "rpm":
		if out, err := phpRun(ctx, hostenv.RPMChangelogArgv(in.pkg)); err == nil {
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
		k := fmt.Sprintf("%s|%s|%t|%t", in.version, in.pkgVersion, in.iis, in.apache) // IIS, Apache and the rest apart: where() and the notes speak for one
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
	case in.apache:
		var confs []string
		for _, a := range g.ins {
			for _, c := range strings.Split(a.conf, ", ") {
				if !slices.Contains(confs, c) {
					confs = append(confs, c)
				}
			}
		}
		from = "run by Apache as CGI from " + strings.Join(confs, ", ") + ", which the package scan does not cover"
	case strings.Contains(in.pkgVersion, "deb.sury.org"):
		from = "package " + in.pkg + " " + in.pkgVersion + " from deb.sury.org or the ondrej PPA, which the package scan does not cover"
	case strings.Contains(in.pkgVersion, "remi") || strings.HasPrefix(in.bin, "/opt/remi/"):
		from = "package " + in.pkg + " " + in.pkgVersion + " from Remi's repository, which the package scan does not cover"
	case in.dist == "rpm" && !phpDistroVendor(in.vendor):
		vendor := in.vendor
		if vendor == "" || vendor == "(none)" {
			vendor = "no vendor"
		}
		from = "package " + in.pkg + " " + in.pkgVersion + " from " + vendor + ", which the package scan does not cover"
	case in.pkg != "":
		from = "package " + in.pkg + " " + in.pkgVersion
	}
	return strings.Join(bins, ", ") + ": " + from
}

// thirdParty reports whether no distribution's advisories speak for the
// group: not from a package, or from deb.sury.org, the PPA, Remi, IIS.
func (g phpGroup) thirdParty() bool {
	in := g.ins[0]
	return in.pkg == "" || in.iis || in.apache || strings.Contains(in.pkgVersion, "deb.sury.org") || strings.Contains(in.pkgVersion, "remi") ||
		strings.HasPrefix(in.bin, "/opt/remi/") || in.dist == "rpm" && !phpDistroVendor(in.vendor)
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
		if in.iis || in.apache {
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

// phpConfFile is one configuration file read: its path and text.
type phpConfFile struct{ path, text string }

// phpReadGlobs reads the host's files of globs, in path order;
// unread are those that are there but could not be read (not a regular
// file, too large, permission).
func phpReadGlobs(globs []string) (files []phpConfFile, unread []string) {
	seen := map[string]bool{}
	for _, g := range globs {
		for _, p := range hostenv.Glob(hostSource(), g) {
			if seen[p] {
				continue
			}
			seen[p] = true
			if text, why := phpReadConf(p); why == "" {
				files = append(files, phpConfFile{p, text})
			} else if why != "missing" {
				unread = append(unread, p+" ("+why+")")
			}
		}
	}
	slices.SortFunc(files, func(a, b phpConfFile) int { return strings.Compare(a.path, b.path) })
	return files, unread
}

// phpResolve is where a host path leads, links followed; false when it
// leads nowhere (it is then not read anyway).
func phpResolve(p string) (string, bool) {
	real, err := hostenv.EvalSymlinks(hostSource(), p)
	return real, err == nil
}

// phpReadConf reads a configuration file; why is "" when read, "missing"
// when not there, else why it could not be.
func phpReadConf(full string) (text, why string) {
	b, err := phpReadLimited(full, phpConfMax)
	switch {
	case err == nil:
		return string(b), ""
	case errors.Is(err, fs.ErrNotExist):
		return "", "missing"
	case errors.Is(err, fs.ErrPermission):
		return "", "permission denied"
	}
	return "", err.Error()
}

// phpPoolBranch is the PHP branch a pool file belongs to (Debian's
// /etc/php/8.3/fpm/, Remi's /etc/opt/remi/php83/), "" for one shared.
func phpPoolBranch(p string) string {
	if rest, ok := strings.CutPrefix(p, "/etc/php/"); ok {
		if b, _, ok := strings.Cut(rest, "/"); ok {
			return b
		}
	}
	if rest, ok := strings.CutPrefix(p, "/etc/opt/remi/php"); ok {
		if b, _, ok := strings.Cut(rest, "/"); ok && len(b) == 2 {
			return b[:1] + "." + b[1:]
		}
	}
	return ""
}

// phpStatusExposed finds a status page (pm.status_path) of a pool of the
// branch (or one shared by all) reachable from outside: its socket
// (pm.status_listen, else the pool's listen) on an address other than the
// host's own, or a web server passing the path on to FPM without keeping it
// to the host. path is the page; unread what decides and could not be read.
// A pool is its file and its name: [www] of 8.2 is not [www] of 8.3.
func phpStatusExposed(branch string) (path string, exposed bool, unread []string) {
	files, unread := phpReadGlobs(phpPoolGlobs)
	type pool struct{ listen, status, statusListen string }
	var pools []*pool
	for _, f := range files {
		if b := phpPoolBranch(f.path); b != "" && b != branch {
			continue
		}
		by := map[string]*pool{}
		var cur *pool
		for _, line := range strings.Split(f.text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == ';' || line[0] == '#' {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				name := line[1 : len(line)-1]
				if cur = nil; name != "global" {
					if by[name] == nil {
						by[name] = &pool{}
						pools = append(pools, by[name])
					}
					cur = by[name]
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
	for _, p := range pools {
		if p.status == "" {
			continue
		}
		l := p.statusListen
		if l == "" {
			l = p.listen
		}
		if phpNetAddr(l) {
			return p.status, true, nil
		}
		if !slices.Contains(paths, p.status) {
			paths = append(paths, p.status)
		}
	}
	if len(paths) == 0 {
		return "", false, unread
	}
	web, wunread := phpWebConf()
	unread = append(unread, wunread...)
	for _, sp := range paths {
		for _, f := range web {
			hit, unsure := false, ""
			if f.nginx {
				hit, unsure = ngxPassesTo(f.text, sp)
			} else {
				hit, unsure = apachePassesTo(f.text, sp)
			}
			if hit {
				return sp, true, nil
			}
			if unsure != "" {
				unread = append(unread, f.path+" ("+unsure+")")
			}
		}
	}
	return paths[0], false, unread
}

// phpWebFile is a web server's file with what it includes put in place
// and its comments taken out.
type phpWebFile struct {
	path, text string
	nginx      bool
}

// phpIncludeRoots are where a web server's include is followed: under its
// own configuration (and nginx's modules folder on RHEL).
var phpIncludeRoots = map[bool][]string{
	true:  {"/etc/nginx/", "/usr/share/nginx/", "/usr/local/openresty/", "/usr/local/nginx/"},
	false: {"/etc/apache2/", "/etc/httpd/"},
}

var (
	ngxInclude    = regexp.MustCompile(`(?m)^[ \t]*include[ \t]+("[^"]*"|'[^']*'|[^;\s]+)[ \t]*;`)
	apacheInclude = regexp.MustCompile(`(?im)^[ \t]*Include(?:Optional)?[ \t]+("[^"]*"|\S+)[ \t]*$`)
)

// phpWebConf reads the web servers' files of phpWebGlobs, includes followed
// (8 deep, 256 files at most, under phpIncludeRoots); unread are the files
// that could not be read, or were not.
func phpWebConf() ([]phpWebFile, []string) {
	files, unread := phpReadGlobs(phpWebGlobs)
	count := len(files)
	var expand func(p, text string, nginx bool, depth int) string
	expand = func(p, text string, nginx bool, depth int) string {
		re, root := apacheInclude, "/etc/apache2"
		if nginx {
			re, root = ngxInclude, "/etc/nginx"
		} else if strings.HasPrefix(p, "/etc/httpd/") {
			root = "/etc/httpd"
		}
		return re.ReplaceAllStringFunc(text, func(m string) string {
			arg := strings.Trim(re.FindStringSubmatch(m)[1], `"'`)
			if !strings.HasPrefix(arg, "/") {
				arg = root + "/" + arg
			}
			if !slices.ContainsFunc(phpIncludeRoots[nginx], func(r string) bool { return strings.HasPrefix(path.Clean(arg), r) }) {
				unread = append(unread, arg+" (included by "+p+", not read: outside "+strings.Join(phpIncludeRoots[nginx], ", ")+")")
				return ""
			}
			var b strings.Builder
			for _, ip := range hostenv.Glob(hostSource(), arg) {
				if real, ok := phpResolve(ip); ok && !slices.ContainsFunc(phpIncludeRoots[nginx], func(r string) bool { return strings.HasPrefix(real, r) }) {
					// a link out of the server's folders
					unread = append(unread, ip+" (included by "+p+", not read: it links to "+real+", outside "+strings.Join(phpIncludeRoots[nginx], ", ")+")")
					continue
				}
				if depth >= 8 || count >= 256 {
					unread = append(unread, ip+" (included by "+p+", not read: past the include limit)")
					continue
				}
				count++
				text, why := phpReadConf(ip)
				if why != "" {
					unread = append(unread, ip+" (included by "+p+": "+why+")")
					continue
				}
				b.WriteString("\n" + expand(ip, phpStripComments(text, nginx), nginx, depth+1) + "\n")
			}
			return b.String()
		})
	}
	var out []phpWebFile
	for _, f := range files {
		nginx := strings.Contains(f.path, "nginx")
		out = append(out, phpWebFile{f.path, expand(f.path, phpStripComments(f.text, nginx), nginx, 0), nginx})
	}
	return out, unread
}

// phpStripComments takes the comments out of a web server's file: nginx's
// from a # outside quotes to the end of the line, Apache's lines that start
// with # (Apache has no comment after a directive).
func phpStripComments(text string, nginx bool) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if !nginx {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				lines[i] = ""
			}
			continue
		}
		var quote byte
		for j := 0; j < len(line); j++ {
			switch c := line[j]; {
			case quote != 0:
				if c == '\\' {
					j++
				} else if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '#':
				lines[i] = line[:j]
				j = len(line)
			}
		}
	}
	return strings.Join(lines, "\n")
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
	ngxServer     = regexp.MustCompile(`(?m)^\s*server\s*\{`)
	ngxListen     = regexp.MustCompile(`(?m)^\s*listen\s+([^;\s]+)`)
	ngxKeptLocal  = regexp.MustCompile(`\bdeny\s+all\s*;|\binternal\s*;`)
	apacheBlock   = regexp.MustCompile(`(?is)<(Location|LocationMatch)\s+("[^"]*"|\S+?)\s*>(.*?)</(?:Location|LocationMatch)>`)
	apacheLocal   = regexp.MustCompile(`(?i)\bRequire\s+(local|ip|host|all\s+denied)\b|\bDeny\s+from\s+all\b`)
	apacheFCGI    = regexp.MustCompile(`(?i)proxy:.*fcgi:|\bProxyPass(Match)?\s+fcgi://`)
	apacheProxyRe = regexp.MustCompile(`(?im)^\s*ProxyPass(Match)?\s+("[^"]*"|\S+)\s+"?fcgi://`)
)

// ngxBlockEnd is the index of the } closing the block whose { is at open.
func ngxBlockEnd(text string, open int) int {
	depth := 0
	for i := open; i < len(text); i++ {
		if text[i] == '{' {
			depth++
		} else if text[i] == '}' {
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return len(text)
}

// ngxLocalServer reports whether the server block holding the offset at
// listens on the host's own addresses only (127.0.0.1, [::1], localhost, a
// Unix socket). A location in no server block, or a server with no listen
// (port 80 on every address), is not.
func ngxLocalServer(text string, at int) bool {
	for _, m := range ngxServer.FindAllStringIndex(text, -1) {
		end := ngxBlockEnd(text, m[1]-1)
		if at < m[0] || at > end {
			continue
		}
		ls := ngxListen.FindAllStringSubmatch(text[m[1]:end], -1)
		if len(ls) == 0 {
			return false
		}
		for _, l := range ls {
			a := l[1]
			if strings.HasPrefix(a, "unix:") {
				continue
			}
			if !strings.Contains(a, ":") && !strings.Contains(a, ".") {
				return false // a port alone: every address
			}
			if phpNetAddr(a) {
				return false
			}
		}
		return true
	}
	return false
}

// ngxPassesTo reports whether nginx's text (comments taken out) has a
// location that matches path and passes it on to FastCGI, in a server not
// listening on the host's own addresses only, and not kept to some
// addresses (deny all) or to nginx itself (internal). unsure says why that
// cannot be told (a regular expression Go cannot read).
func ngxPassesTo(text, path string) (bool, string) {
	unsure := ""
	for _, m := range ngxLocation.FindAllStringSubmatchIndex(text, -1) {
		mod, pat := "", strings.Trim(text[m[4]:m[5]], `"`)
		if m[2] >= 0 {
			mod = text[m[2]:m[3]]
		}
		body := text[m[1]:ngxBlockEnd(text, m[1]-1)]
		if !strings.Contains(body, "fastcgi_pass") || ngxKeptLocal.MatchString(body) || ngxLocalServer(text, m[0]) {
			continue
		}
		switch ok, err := pathMatches(mod, pat, path); {
		case ok:
			return true, ""
		case err != nil:
			unsure = "location " + pat + " is a regular expression that could not be read"
		}
	}
	return false, unsure
}

// apachePassesTo is ngxPassesTo for Apache: a Location or LocationMatch that
// hands path to FastCGI without Require local, ip or host, or a ProxyPass
// (Match) of it to fcgi:// that no such Location of it keeps to the host.
func apachePassesTo(text, path string) (bool, string) {
	unsure := ""
	kept := false // a Location matching path keeps it to the host
	for _, m := range apacheBlock.FindAllStringSubmatch(text, -1) {
		mod := "^~" // a Location is a prefix
		if strings.EqualFold(m[1], "LocationMatch") {
			mod = "~"
		}
		ok, err := pathMatches(mod, strings.Trim(m[2], `"`), path)
		if err != nil {
			unsure = "LocationMatch " + m[2] + " is a regular expression that could not be read"
		}
		if !ok {
			continue
		}
		if apacheLocal.MatchString(m[3]) {
			kept = true
			continue
		}
		if apacheFCGI.MatchString(m[3]) {
			return true, ""
		}
	}
	for _, m := range apacheProxyRe.FindAllStringSubmatch(text, -1) {
		mod := "^~"
		if m[1] != "" {
			mod = "~"
		}
		ok, err := pathMatches(mod, strings.Trim(m[2], `"`), path)
		if err != nil {
			unsure = "ProxyPassMatch " + m[2] + " is a regular expression that could not be read"
		}
		if ok && !kept {
			return true, ""
		}
	}
	return false, unsure
}

// pathMatches reports whether a location of modifier mod (=, ~, ~*, ^~ or
// none) and pattern pat matches path; err when the regular expression is
// one Go's RE2 cannot read (PCRE's lookarounds, backreferences).
func pathMatches(mod, pat, path string) (bool, error) {
	switch mod {
	case "=":
		return pat == path, nil
	case "~", "~*":
		if mod == "~*" {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return false, err
		}
		return re.MatchString(path), nil
	}
	return strings.HasPrefix(path, pat), nil
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
		out = append(out, Risk{uncheckedPrefix + "php:version", "info", "PHP could not be checked (" + strings.Join(unread, ", ") +
			"), so whether CVE-2026-129538 (php-cgi) and the other PHP advisories of 2026-11-19 affect it is unknown"})
	}
	if len(ins) == 0 {
		return out
	}
	var procs []hostenv.Process
	known := true
	if !phpOnWindows() {
		procs, known = phpProcs()
	}
	type status struct {
		path   string
		out    bool
		unread []string
	}
	statuses := map[string]*status{} // by branch: each reads its own pools
	groups := phpGroups(ins)
	branches := map[string]int{}
	for _, g := range groups {
		if rel, ok := phpRelease(g.version); ok {
			branches[fmt.Sprintf("%d.%d", rel[0], rel[1])]++
		}
	}
	for _, g := range groups {
		rel, ok := phpRelease(g.version)
		if !ok {
			continue
		}
		branch := fmt.Sprintf("%d.%d", rel[0], rel[1])
		iisNote := phpIISArgInjNote(g, rel)
		key, name := "php"+branch+":", "PHP "+g.version+" ("+g.where()+")"
		if branches[branch] > 1 {
			key = "php" + branch + "@" + g.ins[0].bin + ":" // two builds of one branch: a risk each
		}
		if phpEOL(rel) {
			if g.thirdParty() {
				out = append(out, Risk{key + "eol", "info", name + " is a branch php.net no longer fixes; its fixes of 2026-11-19 " +
					"(18 CVEs) went into 8.2.36, 8.3.37, 8.4.28, 8.5.13 and 8.6.0. Move to a branch that is still fixed, " +
					"or ask whoever builds this one whether it carries the fixes" + iisNote})
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
			st := statuses[branch]
			if st == nil {
				st = &status{}
				st.path, st.out, st.unread = phpStatusExposed(branch)
				statuses[branch] = st
			}
			statusPath, statusOut, statusUnread := st.path, st.out, st.unread
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
				switch {
				case g.ins[0].iis:
					runs = "IIS runs it through FastCGI"
				case g.ins[0].apache:
					runs = "Apache runs it as CGI"
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
				"a Phar signature downgrade, mixed-case HTTPS and FTPS URLs sent in plaintext, and more). " + upgrade + note + iisNote})
		}
	}
	if phpOnWindows() {
		for _, k := range phpArgInjChecks(ins) {
			out = append(out, phpArgInjRisk(k))
		}
	}
	return out
}

// phpIISArgInjNote says, for php-cgi IIS runs whose version is in the range
// of CVE-2024-4577 or CVE-2024-8926, why they are not reported.
func phpIISArgInjNote(g phpGroup, rel [3]int) string {
	if !slices.ContainsFunc(g.ins, func(in phpInstall) bool { return in.iis }) {
		return ""
	}
	for _, c := range phpArgInjCVEs {
		if aff, _ := phpArgInjAffected(rel, c); aff {
			return ". CVE-2024-4577 and CVE-2024-8926 (argument injection in PHP-CGI) are not reported for it: their advisories cover " +
				"PHP-CGI under Apache only, and IIS's FastCGI does not pass the query string as arguments"
		}
	}
	return ""
}
