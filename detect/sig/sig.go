// Package sig holds shentu detect's attack signatures: what a request
// trying one of this host's vulnerabilities carries. They ship inside the
// binary (signatures/*.toml, embedded) and are never fetched at run time.
//
// Sources (plan 0743f0, decision 2): signatures written for shentu
// (Apache-2.0), and Nuclei templates (MIT) extracted offline and reviewed
// by a person, each naming its template id and version. No other source.
package sig

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed signatures/*.toml
var embedded embed.FS

// Signature is one attack signature.
type Signature struct {
	ID    string   `toml:"id"` // kebab-case, unique
	Title string   `toml:"title"`
	Class string   `toml:"class"` // the payload class (sqli, path, cmdi...): detect.PayloadClass's names
	CWE   []string `toml:"cwe"`
	// CVEs and Advisories: the vulnerabilities it is written for; none for
	// a signature of a whole class (any SQL injection), which applies to the
	// code sinks of that class.
	CVEs       []string `toml:"cves"`
	Advisories []string `toml:"advisories"`
	AppliesTo  []Range  `toml:"applies_to"` // the package versions it is for; none: any
	Routes     []Route  `toml:"route"`      // where it is sent; none: anywhere the class's sinks are
	Matches    []Match  `toml:"match"`      // what it carries: every one must hold
	// Source: "shentu" or "nuclei". License follows it (Apache-2.0, MIT);
	// a Nuclei one names its template and the templates' release.
	Source         string `toml:"source"`
	License        string `toml:"license"`
	Author         string `toml:"author"`
	NucleiTemplate string `toml:"nuclei_template"`
	NucleiVersion  string `toml:"nuclei_version"`
	Note           string `toml:"note"`
	File           string `toml:"-"` // where it was read from
}

// Range is a package and the versions of it a signature is for.
type Range struct {
	Ecosystem string `toml:"ecosystem"` // npm, Packagist, PyPI, Debian, WordPress (plugins)...
	Package   string `toml:"package"`
	// Versions: comparisons joined by commas, all to hold (">=1.2, <1.4.3");
	// empty: every version.
	Versions string `toml:"versions"`
}

// Route is where a signature's request goes.
type Route struct {
	Methods []string `toml:"methods"` // GET, POST...; none: any
	// Path is matched as a suffix of the request's normalized path (a
	// router may be mounted under a prefix); PathRegex, RE2, anywhere in it.
	Path      string `toml:"path"`
	PathRegex string `toml:"path_regex"`
}

// Match is one thing the request must carry.
type Match struct {
	// Part: "path", "query" (the whole query), "param" (the parameter Param,
	// every value it has), "any_param" (any parameter's value), "user_agent",
	// "referer".
	Part  string `toml:"part"`
	Param string `toml:"param"`
	// Contains: literals, any of which matches, compared with the
	// normalized text (decoded, lower case); Regex: RE2 on the same. At
	// least one of the two.
	Contains []string `toml:"contains"`
	Regex    string   `toml:"regex"`

	re *regexp.Regexp
}

// Re is the compiled Regex (nil when none).
func (m Match) Re() *regexp.Regexp { return m.re }

// Classes are the payload classes a signature may be of: the ones
// detect.PayloadClass gives a CWE, and scanner, for a tool's own marks
// (a scanner's user agent, an out-of-band callback host).
var Classes = map[string]bool{"sqli": true, "nosqli": true, "cmdi": true, "path": true, "ssrf": true, "xss": true,
	"deser": true, "xxe": true, "code": true, "upload": true, "redirect": true, "ldapi": true, "xpathi": true, "scanner": true}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	cveRe     = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cweRe     = regexp.MustCompile(`^CWE-\d+$`)
	compareRe = regexp.MustCompile(`^(>=|<=|>|<|=)\s*([0-9A-Za-z.+~:_-]+)$`)
	parts     = map[string]bool{"path": true, "query": true, "param": true, "any_param": true, "user_agent": true, "referer": true}
)

// Limits on what a signature may hold, so the matcher's cost per request is
// bounded however many there are.
const (
	MaxLiteral  = 256
	MaxLiterals = 64
	MaxRegex    = 1024
	MaxMatches  = 8
	MaxRoutes   = 16
)

// Load reads the embedded signatures. Any that is not valid fails the
// whole load: a signature set is checked whole, not taken in part.
func Load() ([]Signature, error) { return LoadFS(embedded, "signatures") }

// LoadFS reads every .toml under dir of fsys.
func LoadFS(fsys fs.FS, dir string) ([]Signature, error) {
	names, err := fs.Glob(fsys, path.Join(dir, "*.toml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	seen := map[string]string{}
	var out []Signature
	var errs []string
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		var f struct {
			Signature []Signature `toml:"signature"`
		}
		md, err := toml.Decode(string(b), &f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		if extra := md.Undecoded(); len(extra) > 0 {
			return nil, fmt.Errorf("%s: unknown keys %v", n, extra)
		}
		for i := range f.Signature {
			s := &f.Signature[i]
			s.File = n
			if prev, ok := seen[s.ID]; ok {
				errs = append(errs, fmt.Sprintf("%s: %s already in %s", n, s.ID, prev))
				continue
			}
			seen[s.ID] = n
			if err := s.check(); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %s: %v", n, s.ID, err))
				continue
			}
			out = append(out, *s)
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid signatures:\n%s", strings.Join(errs, "\n"))
	}
	return out, nil
}

// check validates a signature and compiles its expressions.
func (s *Signature) check() error {
	switch {
	case !idRe.MatchString(s.ID):
		return fmt.Errorf("id %q: kebab-case, letters and digits", s.ID)
	case s.Title == "":
		return fmt.Errorf("no title")
	case !Classes[s.Class]:
		return fmt.Errorf("class %q unknown", s.Class)
	case len(s.Matches) == 0 && len(s.Routes) == 0:
		return fmt.Errorf("neither a route nor a match: it would match every request")
	case len(s.Matches) > MaxMatches || len(s.Routes) > MaxRoutes:
		return fmt.Errorf("more than %d matches or %d routes", MaxMatches, MaxRoutes)
	}
	switch s.Source {
	case "shentu":
		if s.License != "Apache-2.0" {
			return fmt.Errorf("source shentu: license must be Apache-2.0, not %q", s.License)
		}
		if s.NucleiTemplate != "" || s.NucleiVersion != "" {
			return fmt.Errorf("source shentu names a Nuclei template")
		}
	case "nuclei":
		if s.License != "MIT" {
			return fmt.Errorf("source nuclei: license must be MIT, not %q", s.License)
		}
		if s.NucleiTemplate == "" || s.NucleiVersion == "" {
			return fmt.Errorf("source nuclei: nuclei_template and nuclei_version are required")
		}
	default:
		return fmt.Errorf("source %q: only shentu or nuclei (plan decision 2)", s.Source)
	}
	for _, c := range s.CVEs {
		if !cveRe.MatchString(c) {
			return fmt.Errorf("cve %q", c)
		}
	}
	for _, c := range s.CWE {
		if !cweRe.MatchString(c) {
			return fmt.Errorf("cwe %q", c)
		}
	}
	for _, r := range s.AppliesTo {
		if r.Ecosystem == "" || r.Package == "" {
			return fmt.Errorf("applies_to: ecosystem and package are required")
		}
		if _, err := ParseVersions(r.Versions); err != nil {
			return fmt.Errorf("applies_to %s: %w", r.Package, err)
		}
	}
	for i := range s.Routes {
		r := &s.Routes[i]
		if r.Path == "" && r.PathRegex == "" {
			return fmt.Errorf("route %d: path or path_regex", i)
		}
		if r.Path != "" && !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("route %d: path %q must start with /", i, r.Path)
		}
		if r.PathRegex != "" {
			if len(r.PathRegex) > MaxRegex {
				return fmt.Errorf("route %d: path_regex longer than %d", i, MaxRegex)
			}
			if _, err := regexp.Compile(r.PathRegex); err != nil {
				return fmt.Errorf("route %d: %w", i, err)
			}
		}
		for j, m := range r.Methods {
			r.Methods[j] = strings.ToUpper(m)
		}
	}
	for i := range s.Matches {
		m := &s.Matches[i]
		switch {
		case !parts[m.Part]:
			return fmt.Errorf("match %d: part %q unknown", i, m.Part)
		case (m.Part == "param") != (m.Param != ""):
			return fmt.Errorf("match %d: param is for part param, and part param needs it", i)
		case len(m.Contains) == 0 && m.Regex == "":
			return fmt.Errorf("match %d: contains or regex", i)
		case len(m.Contains) > MaxLiterals:
			return fmt.Errorf("match %d: more than %d literals", i, MaxLiterals)
		case len(m.Regex) > MaxRegex:
			return fmt.Errorf("match %d: regex longer than %d", i, MaxRegex)
		}
		for j, c := range m.Contains {
			if c == "" || len(c) > MaxLiteral {
				return fmt.Errorf("match %d: literal empty or longer than %d", i, MaxLiteral)
			}
			m.Contains[j] = strings.ToLower(c) // compared with the normalized, lower-cased text
		}
		if m.Regex != "" {
			re, err := regexp.Compile(m.Regex)
			if err != nil {
				return fmt.Errorf("match %d: %w", i, err)
			}
			m.re = re
		}
	}
	return nil
}

// Comparison is one of a Range's comparisons.
type Comparison struct {
	Op, Version string
}

// ParseVersions reads ">=1.2, <1.4.3" (empty: no comparison, every version).
func ParseVersions(s string) ([]Comparison, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []Comparison
	for _, p := range strings.Split(s, ",") {
		m := compareRe.FindStringSubmatch(strings.TrimSpace(p))
		if m == nil {
			return nil, fmt.Errorf("version comparison %q: >=, <=, >, < or = and a version", strings.TrimSpace(p))
		}
		out = append(out, Comparison{m[1], m[2]})
	}
	return out, nil
}

// InRange says whether version is in every comparison of r. It compares the
// dotted numeric parts, then the rest as text; ok is false when version or
// a bound is not of a shape it can compare (a Debian epoch, a git hash):
// not known, never taken as "in".
func InRange(r Range, version string) (in, ok bool) {
	cs, err := ParseVersions(r.Versions)
	if err != nil {
		return false, false
	}
	for _, c := range cs {
		d, ok := compareVersions(version, c.Version)
		if !ok {
			return false, false
		}
		hold := map[string]bool{">=": d >= 0, "<=": d <= 0, ">": d > 0, "<": d < 0, "=": d == 0}[c.Op]
		if !hold {
			return false, true
		}
	}
	return true, true
}

var versionRe = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)([-.+~]?[0-9A-Za-z.+~-]*)$`)

// compareVersions compares a and b: numeric parts as numbers, then a
// pre-release suffix (1.2.0-beta) before none.
func compareVersions(a, b string) (int, bool) {
	ma, mb := versionRe.FindStringSubmatch(a), versionRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	na, nb := strings.Split(ma[1], "."), strings.Split(mb[1], ".")
	for i := 0; i < len(na) || i < len(nb); i++ {
		var x, y int
		if i < len(na) {
			x, _ = strconv.Atoi(na[i])
		}
		if i < len(nb) {
			y, _ = strconv.Atoi(nb[i])
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	sa, sb := ma[2], mb[2]
	switch {
	case sa == sb:
		return 0, true
	case sa == "":
		return 1, true // 1.2.0 after 1.2.0-beta
	case sb == "":
		return -1, true
	}
	return strings.Compare(sa, sb), true
}
