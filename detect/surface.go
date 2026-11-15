// Package detect finds attempts to exploit the vulnerabilities this host
// actually has, by matching its web server and application logs against
// them. This file builds that list (the vulnerability surface) from the code
// audit's injection findings and the installed packages' known
// vulnerabilities; the log readers and the matching come later.
//
// detect does not import tools: tools converts its own results into the
// inputs here, so that tools can offer detect as a tool without a cycle.
package detect

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/rules/engine"
)

// CodeSink is one injection finding of the code audit.
type CodeSink struct {
	Rule     string            // the rule id
	CWE      string            // CWE-89
	Severity string            // as the code audit gives it: critical, warning
	Path     string            // the file holding the sink
	Line     int               // the sink's line
	Routes   []engine.RouteRef // the routes registering the handler the sink is in; often none
}

// PackageVuln is one known vulnerability of an installed package or a
// dependency in a lock file.
type PackageVuln struct {
	Source    string // "os", or the lock file's path
	Ecosystem string // Debian, npm, Packagist, PyPI...
	Package   string
	Version   string // installed
	ID        string // the advisory id: CVE-2024-1234, GHSA-..., USN-...
	CVE       string // the CVE id when known (from the KEV match or the id itself)
	Severity  string // as the advisory gives it; may be empty
	Fixed     string // the first fixed version; may be empty
	KEV       bool   // CISA lists it as exploited in the wild
	KEVSince  string // the date CISA added it
}

// Coverage says what detect can match for an entry.
const (
	CoverRoutes    = "routes"          // a code sink whose URLs are known: requests to them are matched
	CoverNoRoute   = "no_route"        // a code sink whose URLs are not known; see NoRoutesMeaning
	CoverSignature = "needs_signature" // a package vulnerability: matched only once a signature for it exists
)

// The two caveats every report and alert built on the surface must carry,
// in English and in Chinese.
const (
	RoutesMeaning     = "routes only say that the sink sits in this handler, not that request data was traced to it along this route"
	RoutesMeaningZh   = "routes 只代表 sink 位在這個 handler 裡，不代表請求資料一定是從這條路由流進來的"
	NoRoutesMeaning   = "no routes does not mean no attack surface: the handler may be registered in another file (Django urls.py, Laravel routes) or be an entry point without a route model yet (WordPress admin-ajax)"
	NoRoutesMeaningZh = "沒有 routes 不代表沒有攻擊面：handler 可能註冊在別的檔案（Django urls.py、Laravel routes），或是還沒有路由模型的入口（WordPress admin-ajax）"
)

// Entry is one vulnerability of this host that an attacker could try.
type Entry struct {
	ID       string            `json:"id"`   // code:<rule>:<path>:<line> or pkg:<advisory>:<package>
	Kind     string            `json:"kind"` // code or package
	Severity string            `json:"severity,omitempty"`
	CWE      string            `json:"cwe,omitempty"`
	Payload  string            `json:"payload,omitempty"` // the payload class an attempt carries (sqli, cmdi, path...), from the CWE
	Path     string            `json:"path,omitempty"`
	Line     int               `json:"line,omitempty"`
	Routes   []engine.RouteRef `json:"routes,omitempty"`
	Rule     string            `json:"rule,omitempty"`

	Source    string `json:"source,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	Advisory  string `json:"advisory,omitempty"`
	CVE       string `json:"cve,omitempty"`
	Fixed     string `json:"fixed_version,omitempty"`
	KEV       bool   `json:"kev,omitempty"`
	KEVSince  string `json:"kev_since,omitempty"`

	Coverage string `json:"coverage"`
}

// Surface is the host's vulnerability surface.
type Surface struct {
	Entries   []Entry `json:"entries"`
	Truncated int     `json:"truncated,omitempty"` // entries left out past MaxEntries
	// Caveats: RoutesMeaning and NoRoutesMeaning, for whoever reads the JSON.
	Caveats []string `json:"caveats"`
}

// MaxEntries bounds the surface: the matcher keeps it in memory for a whole
// log pass on a 512MB host.
const MaxEntries = 5000

// payloadByCWE is the payload class an attempt on a weakness carries.
var payloadByCWE = map[string]string{
	"CWE-89": "sqli", "CWE-564": "sqli",
	"CWE-943": "nosqli",
	"CWE-77":  "cmdi", "CWE-78": "cmdi", "CWE-88": "cmdi",
	"CWE-22": "path", "CWE-23": "path", "CWE-36": "path", "CWE-73": "path", "CWE-98": "path",
	"CWE-918": "ssrf",
	"CWE-79":  "xss",
	"CWE-502": "deser",
	"CWE-611": "xxe",
	"CWE-94":  "code", "CWE-95": "code", "CWE-1336": "code",
	"CWE-434": "upload",
	"CWE-601": "redirect",
	"CWE-90":  "ldapi",
	"CWE-643": "xpathi",
}

// PayloadClass is the payload class for a CWE, or "other".
func PayloadClass(cwe string) string {
	if p, ok := payloadByCWE[strings.ToUpper(strings.TrimSpace(cwe))]; ok {
		return p
	}
	return "other"
}

// Build puts the code sinks and package vulnerabilities into one surface:
// one entry per sink (rule, file, line) and per advisory of a package
// version, the routes of a sink merged, sorted so that the same host gives
// the same surface. KEV entries come first, so a cut keeps them.
func Build(code []CodeSink, pkgs []PackageVuln) Surface {
	byID := map[string]int{}
	var out []Entry
	for _, c := range code {
		if c.Rule == "" || c.Path == "" {
			continue
		}
		id := "code:" + c.Rule + ":" + c.Path + ":" + strconv.Itoa(c.Line)
		if i, ok := byID[id]; ok {
			out[i].Routes = mergeRoutes(out[i].Routes, c.Routes)
			continue
		}
		byID[id] = len(out)
		out = append(out, Entry{ID: id, Kind: "code", Severity: c.Severity, CWE: c.CWE, Payload: PayloadClass(c.CWE),
			Path: c.Path, Line: c.Line, Routes: mergeRoutes(nil, c.Routes), Rule: c.Rule})
	}
	for _, p := range pkgs {
		adv := p.ID
		if adv == "" {
			adv = p.CVE
		}
		if adv == "" || p.Package == "" {
			continue
		}
		id := "pkg:" + adv + ":" + p.Package
		if p.Source != "" && p.Source != "os" {
			id += "@" + p.Source // the same dependency in two lock files is two places to fix
		}
		if i, ok := byID[id]; ok {
			e := &out[i]
			e.KEV = e.KEV || p.KEV
			if e.KEVSince == "" {
				e.KEVSince = p.KEVSince
			}
			if e.CVE == "" {
				e.CVE = p.CVE
			}
			continue
		}
		cve := p.CVE
		if cve == "" && strings.HasPrefix(strings.ToUpper(adv), "CVE-") {
			cve = adv
		}
		byID[id] = len(out)
		out = append(out, Entry{ID: id, Kind: "package", Severity: p.Severity, Source: p.Source, Ecosystem: p.Ecosystem,
			Package: p.Package, Version: p.Version, Advisory: adv, CVE: cve, Fixed: p.Fixed, KEV: p.KEV, KEVSince: p.KEVSince})
	}
	for i := range out {
		switch {
		case out[i].Kind == "package":
			out[i].Coverage = CoverSignature
		case len(out[i].Routes) > 0:
			out[i].Coverage = CoverRoutes
		default:
			out[i].Coverage = CoverNoRoute
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].KEV != out[j].KEV {
			return out[i].KEV
		}
		return out[i].ID < out[j].ID
	})
	s := Surface{Caveats: []string{RoutesMeaning, NoRoutesMeaning}}
	if len(out) > MaxEntries {
		s.Truncated = len(out) - MaxEntries
		out = out[:MaxEntries]
	}
	s.Entries = out
	if s.Entries == nil {
		s.Entries = []Entry{}
	}
	return s
}

// mergeRoutes adds the routes of b not in a, in order.
func mergeRoutes(a, b []engine.RouteRef) []engine.RouteRef {
	for _, r := range b {
		dup := false
		for _, x := range a {
			if x == r {
				dup = true
				break
			}
		}
		if !dup {
			a = append(a, r)
		}
	}
	return a
}
