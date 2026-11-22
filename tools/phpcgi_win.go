package tools

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/hostenv"
)

// CVE-2024-4577 (argument injection in PHP-CGI on Windows: under a code page
// with "Best-Fit", 932, 936 or 950, a soft hyphen in the query string
// becomes "-", and PHP-CGI takes it as an option) and CVE-2024-8926 (its
// bypass, under an ANSI code page pointed at an OEM one such as 437). NVD,
// GHSA-3qgc-jrrr-25jv and GHSA-p99j-rfp4-xqvq give PHP-CGI under Apache on
// Windows only, where Apache passes a query string without "=" to the
// program as its arguments; IIS's FastCGI does not, and no advisory names
// it. Fixed in 8.1.29, 8.2.20, 8.3.8 and in 8.1.30, 8.2.24, 8.3.12. The
// branches before 8.1 are not listed and get no fix; 8.4 came out fixed.

// phpArgInj is one of them: the fixed release of each 8.x branch, and
// whether a system code page (the ANSI one, ACP) lets it through.
type phpArgInj struct {
	id       string
	fixed    map[int]int
	severity string // the Risk's when confirmed; the surface's is the advisory's
	advisory string
	codePage func(acp string) bool
	cpWhy    string
}

// phpANSICodePages are Windows's standard ANSI code pages (and UTF-8).
var phpANSICodePages = map[string]bool{"874": true, "932": true, "936": true, "949": true, "950": true, "1250": true, "1251": true,
	"1252": true, "1253": true, "1254": true, "1255": true, "1256": true, "1257": true, "1258": true, "65001": true}

var phpArgInjCVEs = []phpArgInj{
	{"CVE-2024-4577", map[int]int{1: 29, 2: 20, 3: 8}, "critical", "critical",
		func(acp string) bool { a := strings.TrimSpace(acp); return a == "932" || a == "936" || a == "950" },
		"the system code page has Best-Fit (932, 936 or 950)"},
	{"CVE-2024-8926", map[int]int{1: 30, 2: 24, 3: 12}, "warning", "high",
		func(acp string) bool { return !phpANSICodePages[strings.TrimSpace(acp)] },
		"the system's ANSI code page is not a standard ANSI one (an OEM code page such as 437)"},
}

// phpArgInjAffected reports whether a PHP version is in c's range, or in a
// branch before 8.1 (eol: not listed, never fixed).
func phpArgInjAffected(v [3]int, c phpArgInj) (affected, eol bool) {
	switch {
	case v == [3]int{}:
		return false, false // not read
	case v[0] < 8 || v[0] == 8 && v[1] == 0:
		return true, true
	case v[0] == 8 && v[1] >= 1 && v[1] <= 3:
		return v[2] < c.fixed[v[1]], false
	}
	return false, false
}

// The Windows host for the tests: listing a folder, the Apache
// configurations to read, the system code page, the KEV catalog.
var (
	phpReadDir = func(d string) ([]string, error) { return winSource().ReadDir(d) }
	phpWinACP  = func() (string, error) {
		ws, ok := winSource().(hostenv.WinSource)
		if !ok {
			return "", fmt.Errorf("not a Windows source")
		}
		v, err := ws.RegValues(hostenv.KeyCodePage)
		if err != nil {
			return "", err
		}
		if s := strings.TrimSpace(v["ACP"].String); s != "" {
			return s, nil
		}
		return "", fmt.Errorf("no ACP value")
	}
	phpWinApacheConfs = winApacheConfs
	phpLoadKEV        = loadKEV
)

// winApacheConfs are the httpd.conf files of Apache on this host: next to an
// httpd.exe a service or a process runs, and XAMPP's and Apache Lounge's
// places.
func winApacheConfs() []string {
	var bins []string
	if ws, ok := winSource().(hostenv.WinSource); ok {
		if svcs, err := ws.Services(); err == nil {
			for _, s := range svcs {
				bins = append(bins, s.BinaryPath)
			}
		}
		if procs, err := ws.Processes(); err == nil {
			for _, p := range procs {
				bins = append(bins, p.Exe)
			}
		}
	}
	confs := []string{`C:\xampp\apache\conf\httpd.conf`, `C:\Apache24\conf\httpd.conf`}
	for _, b := range bins {
		b = strings.TrimSpace(b)
		if strings.HasPrefix(b, `"`) {
			b, _, _ = strings.Cut(b[1:], `"`)
		} else if i := strings.Index(strings.ToLower(b), ".exe"); i >= 0 {
			b = b[:i+4]
		}
		if strings.EqualFold(winBase(b), "httpd.exe") {
			confs = append(confs, winDir(winDir(b))+`\conf\httpd.conf`)
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range confs {
		if k := strings.ToLower(c); !seen[k] {
			seen[k] = true
			if _, err := phpReadBin(c); err == nil {
				out = append(out, c)
			}
		}
	}
	return out
}

func winBase(p string) string { return p[strings.LastIndexAny(p, `\/`)+1:] }

func winDir(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return ""
}

// winPath is an Apache path in Windows spelling: slashes turned, relative
// ones under root.
func winPath(p, root string) string {
	p = strings.ReplaceAll(strings.Trim(strings.TrimSpace(p), `"`), "/", `\`)
	if len(p) >= 2 && p[1] == ':' || strings.HasPrefix(p, `\\`) {
		return strings.TrimRight(p, `\`)
	}
	return strings.TrimRight(root+`\`+strings.TrimLeft(p, `\`), `\`)
}

var apacheDefine = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)

// phpApacheCGI reads Apache's configuration from conf, following Include and
// IncludeOptional (globs too), and returns the php-cgi.exe programs Apache
// runs as CGI: a ScriptAlias (or ScriptAliasMatch) onto php-cgi.exe or the
// folder holding it, an Action whose target is php-cgi.exe under such an
// alias, or AddHandler cgi-script .exe in the Directory of that folder.
// unread are the files that are there and could not be read.
func phpApacheCGI(conf string, read func(string) ([]byte, error), list func(string) ([]string, error)) (exes, unread []string) {
	root := winDir(winDir(conf))
	defines := map[string]string{}
	aliases := map[string]string{} // URL prefix (lower case) -> folder
	var actions []string
	seenFile, seenExe := map[string]bool{}, map[string]bool{}
	exists := func(p string) bool { _, err := read(p); return err == nil }
	addExe := func(p string) {
		if k := strings.ToLower(p); !seenExe[k] && exists(p) {
			seenExe[k] = true
			exes = append(exes, p)
		}
	}
	folderExe := func(target string) {
		if strings.EqualFold(winBase(target), "php-cgi.exe") {
			addExe(target)
		} else {
			addExe(target + `\php-cgi.exe`)
		}
	}
	var walk func(file string, depth int)
	walk = func(file string, depth int) {
		if depth > 8 || len(seenFile) >= 256 || seenFile[strings.ToLower(file)] {
			return
		}
		seenFile[strings.ToLower(file)] = true
		b, err := read(file)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				unread = append(unread, file+" ("+err.Error()+")")
			}
			return
		}
		dir := "" // the Directory block the line is in
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(apacheDefine.ReplaceAllStringFunc(line, func(m string) string {
				if v, ok := defines[m[2:len(m)-1]]; ok {
					return v
				}
				return m
			}))
			if line == "" || line[0] == '#' {
				continue
			}
			f := apacheFields(line)
			switch name := strings.ToLower(f[0]); {
			case name == "define" && len(f) >= 3:
				defines[f[1]] = f[2]
			case name == "serverroot" && len(f) >= 2:
				root = winPath(f[1], root)
			case (name == "include" || name == "includeoptional") && len(f) >= 2:
				p := winPath(f[1], root)
				if strings.ContainsAny(winBase(p), "*?[") {
					names, _ := list(winDir(p))
					for _, n := range names {
						if ok, _ := path.Match(strings.ToLower(winBase(p)), strings.ToLower(n)); ok {
							walk(winDir(p)+`\`+n, depth+1)
						}
					}
				} else {
					walk(p, depth+1)
				}
			case (name == "scriptalias" || name == "scriptaliasmatch") && len(f) >= 3:
				target := winPath(f[2], root)
				if i := strings.Index(target, "$"); i >= 0 {
					target = strings.TrimRight(target[:i], `\`) // a ScriptAliasMatch's $1
				}
				folderExe(target)
				if name == "scriptalias" {
					aliases[strings.ToLower(f[1])] = target
				}
			case name == "action" && len(f) >= 3 && strings.Contains(strings.ToLower(f[2]), "php-cgi"):
				actions = append(actions, f[2])
			case name == "<directory" && len(f) >= 2:
				dir = winPath(strings.TrimSuffix(f[1], ">"), root)
			case name == "</directory>":
				dir = ""
			case name == "addhandler" && dir != "" && len(f) >= 3 && strings.EqualFold(f[1], "cgi-script"):
				for _, ext := range f[2:] {
					if strings.EqualFold(ext, ".exe") || strings.EqualFold(ext, "exe") {
						addExe(dir + `\php-cgi.exe`)
					}
				}
			}
		}
	}
	walk(conf, 0)
	// An Action names a URL: the alias it is under gives the folder.
	for _, a := range actions {
		u := strings.ToLower(strings.Trim(a, `"`))
		for prefix, folder := range aliases {
			if rest, ok := strings.CutPrefix(u, prefix); ok {
				addExe(winPath(rest, folder))
			}
		}
	}
	return exes, unread
}

// apacheFields splits an Apache directive into its words, quotes kept
// together and taken off.
func apacheFields(line string) []string {
	var out []string
	for line = strings.TrimSpace(line); line != ""; line = strings.TrimSpace(line) {
		if line[0] == '"' {
			end := strings.IndexByte(line[1:], '"')
			if end < 0 {
				out = append(out, line[1:])
				break
			}
			out = append(out, line[1:end+1])
			line = line[end+2:]
			continue
		}
		i := strings.IndexAny(line, " \t")
		if i < 0 {
			out = append(out, line)
			break
		}
		out = append(out, line[:i])
		line = line[i:]
	}
	return out
}

// phpArgInjCheck is one CVE for one Apache-run php-cgi: whether it is in the
// range (eol: a branch before 8.1), and whether the code page lets it
// through (cpKnown false: the code page could not be read).
type phpArgInjCheck struct {
	in           phpInstall
	c            phpArgInj
	eol, cpKnown bool
	acp          string
	release      [3]int
}

// phpArgInjChecks are the CVEs that may reach the Apache-run php-cgi
// programs of ins: in range, and the code page letting them through or not
// known.
func phpArgInjChecks(ins []phpInstall) []phpArgInjCheck {
	var out []phpArgInjCheck
	acp, acpRead, cpKnown := "", false, false
	for _, in := range ins {
		if !in.apache {
			continue
		}
		rel, _ := phpRelease(in.version)
		for _, c := range phpArgInjCVEs {
			aff, eol := phpArgInjAffected(rel, c)
			if !aff {
				continue
			}
			if !acpRead {
				a, err := phpWinACP()
				acp, cpKnown, acpRead = a, err == nil, true
			}
			if cpKnown && !c.codePage(acp) {
				continue
			}
			out = append(out, phpArgInjCheck{in: in, c: c, eol: eol, cpKnown: cpKnown, acp: acp, release: rel})
		}
	}
	return out
}

// phpArgInjRisk is the survey's line for one check.
func phpArgInjRisk(k phpArgInjCheck) Risk {
	key := fmt.Sprintf("php%d.%d:%s", k.release[0], k.release[1], k.c.id)
	what := "PHP " + k.in.version + " (" + k.in.bin + ", run by Apache as CGI from " + k.in.conf + "): " + k.c.id +
		" (argument injection in PHP-CGI on Windows: a request's query string becomes PHP's command-line options, " +
		"which can run code)"
	sev := k.c.severity
	cp := ", and " + k.c.cpWhy + " (ACP " + k.acp + ")"
	if !k.cpKnown {
		sev, cp = "warning", "; the system code page could not be read (code page unconfirmed: it applies only if "+k.c.cpWhy+")"
	}
	fix := fmt.Sprintf(". Upgrade to PHP %d.%d.%d or later", k.release[0], k.release[1], k.c.fixed[k.release[1]])
	if k.eol {
		sev = "warning"
		fix = ". This branch is not listed in the advisory and gets no fix (php.net no longer fixes it): move to a branch " +
			"that is fixed, or stop running php-cgi.exe as CGI (use mod_php or PHP-FPM-style FastCGI)"
	}
	return Risk{key, sev, what + cp + fix + "; until then, remove the ScriptAlias or Action that hands requests to php-cgi.exe"}
}

// phpWinSurface is the vulnerability surface's entries for php-cgi under
// Apache on Windows: one per CVE in check, marked KEV as the catalog says.
// note says what could not be told (the catalog unavailable).
func phpWinSurface(ctx context.Context, hc *http.Client) ([]detect.PackageVuln, string) {
	ins, _ := phpInstalls(ctx)
	checks := phpArgInjChecks(ins)
	if len(checks) == 0 {
		return nil, ""
	}
	note := ""
	kev, err := phpLoadKEV(ctx, hc)
	if err != nil {
		note = "CISA KEV list unavailable: php-cgi's CVE-2024-4577 and CVE-2024-8926 entries are not marked as exploited (" + err.Error() + ")"
	}
	var out []detect.PackageVuln
	for _, k := range checks {
		v := detect.PackageVuln{Source: "os", Ecosystem: "PHP", Package: "php-cgi", Version: k.in.version, ID: k.c.id, CVE: k.c.id,
			Severity: k.c.advisory}
		if !k.eol {
			v.Fixed = fmt.Sprintf("%d.%d.%d", k.release[0], k.release[1], k.c.fixed[k.release[1]])
		}
		if k.eol || !k.cpKnown {
			v.Severity = "medium" // not confirmed: not listed, or the code page not read
		}
		if e, ok := kev[k.c.id]; ok {
			v.KEV, v.KEVSince, v.KEVCVE = true, e.Added, k.c.id
		}
		out = append(out, v)
	}
	return out, note
}
