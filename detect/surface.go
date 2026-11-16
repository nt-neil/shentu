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
	"slices"
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
	// RoutesTruncated: the engine kept only some of the file's registrations:
	// Routes may lack some, or be empty though one reaches the sink.
	RoutesTruncated bool
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
	KEVCVE    string // the CVE CISA lists, which CVE (keyed on another of the advisory's) may not be
}

// Coverage says what detect can match for an entry.
const (
	CoverRoutes    = "routes"          // a code sink with at least one route whose path is known: requests to it are matched
	CoverNoRoute   = "no_route"        // a code sink with no known path (none, or only hooks such as a WordPress shortcode); see NoRoutesMeaning
	CoverSignature = "needs_signature" // a package vulnerability: matched only once a signature for it exists
)

// The caveats every report and alert built on the surface must carry, in
// English and in Chinese.
const (
	RoutesMeaning     = "routes only say that the sink sits in this handler, not that request data was traced to it along this route; a sink written on the same line as a one-line handler but outside it is given that handler's routes too"
	RoutesMeaningZh   = "routes 只代表 sink 位在這個 handler 裡，不代表請求資料一定是從這條路由流進來的；sink 若和單行 handler 寫在同一行但在它外面，也會被掛上這個 handler 的 routes"
	NoRoutesMeaning   = "no routes does not mean no attack surface: the handler may be registered in another file (Django urls.py, Laravel routes) or be an entry point without a route model yet (WordPress admin-ajax)"
	NoRoutesMeaningZh = "沒有 routes 不代表沒有攻擊面：handler 可能註冊在別的檔案（Django urls.py、Laravel routes），或是還沒有路由模型的入口（WordPress admin-ajax）"
	// PatternMeaning: how the matcher compares a route's path with a URL.
	PatternMeaning   = "a route's pattern is the path as written, without the prefix its router may be mounted under (app.use('/api', router), a blueprint's url_prefix, APIRouter(prefix=), Route::prefix): a request matches when its path ends with the pattern"
	PatternMeaningZh = "route 的 pattern 是原始碼裡的寫法，不含 router 掛載時的前綴（app.use('/api', router)、blueprint 的 url_prefix、APIRouter 的 prefix、Route::prefix）：請求路徑以 pattern 結尾就算比對到"
)

// Entry is one vulnerability of this host that an attacker could try.
type Entry struct {
	ID       string            `json:"id"`   // code:<rule>:<path>:<line> or pkg:<advisory>:<package>@<version>[#<lock file>], the advisory being the CVE when known
	Kind     string            `json:"kind"` // code or package
	Severity string            `json:"severity,omitempty"`
	CWE      string            `json:"cwe,omitempty"`
	Payload  string            `json:"payload,omitempty"` // the payload class an attempt carries (sqli, cmdi, path...), from the CWE
	Path     string            `json:"path,omitempty"`
	Line     int               `json:"line,omitempty"`
	Routes   []engine.RouteRef `json:"routes,omitempty"`
	// RoutesTruncated: Routes may lack some (CodeSink.RoutesTruncated).
	RoutesTruncated bool   `json:"routes_truncated,omitempty"`
	Rule            string `json:"rule,omitempty"`

	Source    string   `json:"source,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Package   string   `json:"package,omitempty"`
	Version   string   `json:"version,omitempty"`
	Advisory  string   `json:"advisory,omitempty"`
	Aliases   []string `json:"aliases,omitempty"` // the other advisory ids found for it (a GHSA id and its CVE)
	CVE       string   `json:"cve,omitempty"`
	Fixed     string   `json:"fixed_version,omitempty"`
	KEV       bool     `json:"kev,omitempty"`
	KEVSince  string   `json:"kev_since,omitempty"`
	KEVCVE    string   `json:"kev_cve,omitempty"` // the CVE on CISA's list, when KEV

	Coverage string `json:"coverage"`
}

// Surface is the host's vulnerability surface.
type Surface struct {
	Entries []Entry `json:"entries"`
	// Entries left out past MaxEntries, code sinks and package ones apart.
	TruncatedCode     int `json:"truncated_code,omitempty"`
	TruncatedPackages int `json:"truncated_packages,omitempty"`
	// Caveats: RoutesMeaning, NoRoutesMeaning and PatternMeaning, for whoever
	// reads the JSON.
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
// version (an advisory and the CVE it is known as being one), the routes of a
// sink merged, sorted so that the same host gives the same surface. KEV
// entries come first, then the more severe, so a cut keeps them. Entries
// without a severity go last: lock files' dependencies have none
// (tools.SurfaceApps), so past MaxEntries the non-KEV ones are cut before
// any rated code sink.
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
			out[i].RoutesTruncated = out[i].RoutesTruncated || c.RoutesTruncated
			continue
		}
		byID[id] = len(out)
		out = append(out, Entry{ID: id, Kind: "code", Severity: c.Severity, CWE: c.CWE, Payload: PayloadClass(c.CWE),
			Path: c.Path, Line: c.Line, Routes: mergeRoutes(nil, c.Routes), RoutesTruncated: c.RoutesTruncated, Rule: c.Rule})
	}
	for _, p := range pkgs {
		adv := p.ID
		if adv == "" {
			adv = p.CVE
		}
		if adv == "" || p.Package == "" {
			continue
		}
		cve := p.CVE
		if cve == "" && strings.HasPrefix(strings.ToUpper(adv), "CVE-") {
			cve = adv
		}
		key := adv
		if cve != "" {
			key = cve // a GHSA id and the CVE id of one vulnerability are one entry
		}
		id := "pkg:" + key + ":" + p.Package + "@" + p.Version // two versions in one lock file are two
		if p.Source != "" && p.Source != "os" {
			id += "#" + p.Source // the same dependency in two lock files is two places to fix
		}
		if i, ok := byID[id]; ok {
			e := &out[i]
			if adv != e.Advisory && !slices.Contains(e.Aliases, adv) {
				e.Aliases = append(e.Aliases, adv)
			}
			if e.Severity == "" {
				e.Severity = p.Severity
			}
			if e.Fixed == "" {
				e.Fixed = p.Fixed
			}
			e.KEV = e.KEV || p.KEV
			if e.KEVCVE == "" {
				e.KEVCVE = p.KEVCVE
			}
			if e.KEVSince == "" {
				e.KEVSince = p.KEVSince
			}
			if e.CVE == "" {
				e.CVE = cve
			}
			continue
		}
		byID[id] = len(out)
		out = append(out, Entry{ID: id, Kind: "package", Severity: p.Severity, Source: p.Source, Ecosystem: p.Ecosystem,
			Package: p.Package, Version: p.Version, Advisory: adv, CVE: cve, Fixed: p.Fixed, KEV: p.KEV, KEVSince: p.KEVSince, KEVCVE: p.KEVCVE})
	}
	for i := range out {
		switch {
		case out[i].Kind == "package":
			out[i].Coverage = CoverSignature
		case slices.ContainsFunc(out[i].Routes, func(r engine.RouteRef) bool { return r.Pattern != "" }):
			out[i].Coverage = CoverRoutes
		default:
			out[i].Coverage = CoverNoRoute
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].KEV != out[j].KEV {
			return out[i].KEV
		}
		if a, b := severityRank(out[i].Severity), severityRank(out[j].Severity); a != b {
			return a > b
		}
		return out[i].ID < out[j].ID
	})
	s := Surface{Caveats: []string{RoutesMeaning, NoRoutesMeaning, PatternMeaning}}
	if len(out) > MaxEntries {
		for _, e := range out[MaxEntries:] {
			if e.Kind == "code" {
				s.TruncatedCode++
			} else {
				s.TruncatedPackages++
			}
		}
		out = out[:MaxEntries]
	}
	s.Entries = out
	if s.Entries == nil {
		s.Entries = []Entry{}
	}
	return s
}

// severityRank orders the code audit's severities and the advisories' (CVSS
// words, GitHub's moderate) together; unknown is last.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "warning", "medium", "moderate":
		return 2
	case "low":
		return 1
	}
	return 0
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
