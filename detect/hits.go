package detect

import (
	"maps"
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"strings"

	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/rules/engine"
)

// Levels of a candidate (plan 0743f0, detection 3). L3, success likely,
// takes the response and error logs: P4.
const (
	LevelRoute   = "L1" // the request reached the vulnerable code's route, carrying nothing known
	LevelPayload = "L2" // it reached it carrying a payload of the vulnerability's class, or a signature written for it
)

// Candidate is one vulnerability of this host a request may be trying.
type Candidate struct {
	Entry string `json:"entry"` // the surface entry's ID
	Level string `json:"level"`
	Hits  []Hit  `json:"hits,omitempty"` // the signatures that make it L2
	// Route is the route of a code sink the request reached; empty for a
	// package's vulnerability (its signatures carry the route).
	Route *engine.RouteRef `json:"route,omitempty"`
	// VersionUnknown: a package signature's version range could not be
	// compared with the installed version (an epoch, a hash): taken, said.
	VersionUnknown bool `json:"version_unknown,omitempty"`
}

// Judgment is what one request is to this host.
type Judgment struct {
	Candidates []Candidate `json:"candidates,omitempty"`
	// Noise: signatures that hit for a vulnerability this host does not
	// have (a CVE not installed, a class no sink on the route has): counted,
	// never alerted (plan: "對不存在的洞").
	Noise []Hit `json:"noise,omitempty"`
	// Unanchored: class hits that a sink of that class may take, though no
	// route of it is known (coverage no_route): kept for P4, not candidates.
	Unanchored []Hit `json:"unanchored,omitempty"`
	// Cut: some of the request was not matched (Request.Cut): no hit is
	// not "nothing there". TimedOut: matching took longer than
	// MaxMatchTime (MatchResult.TimedOut). Both said with the judgment.
	Cut      bool      `json:"cut,omitempty"`
	CutParts []CutPart `json:"cut_parts,omitempty"` // what was cut, and how much (Request.CutParts)
	TimedOut bool      `json:"timed_out,omitempty"`
	// Unknown: the request was cut and no candidate reached L2 in what was
	// matched: not known to be harmless (padding may hide a payload in
	// what was cut), a result of its own, never an empty judgment. Then
	// HiddenSinks are the sinks it reached (L1), then those reached some
	// way not matched (no route known, cut routes, loose ones), at most
	// MaxHidden; HiddenClasses the payload classes the cut part may hold
	// for this host: all those sinks'. P4 shows it as "the request was cut
	// and may hide <classes>; sinks: <sinks> (and N more)".
	Unknown     bool     `json:"unknown,omitempty"`
	HiddenSinks []string `json:"hidden_sinks,omitempty"`
	// HiddenSinksMore: how many more there are than HiddenSinks lists.
	HiddenSinksMore int      `json:"hidden_sinks_more,omitempty"`
	HiddenClasses   []string `json:"hidden_classes,omitempty"`
}

// MaxHidden bounds Judgment.HiddenSinks.
const MaxHidden = 16

// Judge says which of the surface's vulnerabilities a matched request may
// be trying.
type Judge struct {
	surface Surface
	sigs    map[string]sig.Signature
	routes  []routeEntry
	// classes: payload classes of sinks reachable by a route not known: no
	// route, a route list the engine cut (RoutesTruncated), or a route whose
	// pattern makes no expression (a hook, a pattern that does not compile).
	classes map[string]bool
	loose   []string // the IDs of those sinks, in the surface's order
}

type routeEntry struct {
	entry int
	ref   engine.RouteRef
	re    *regexp.Regexp // matches the request's routed path, by suffix
}

// NewJudge indexes the surface's routes and the signatures by id.
func NewJudge(s Surface, ss []sig.Signature) *Judge {
	j := &Judge{surface: s, sigs: map[string]sig.Signature{}, classes: map[string]bool{}}
	seen := map[int]bool{}
	loose := func(i int) { // its class's hits elsewhere are unanchored; a cut may hide one for it
		j.classes[s.Entries[i].Payload] = true
		if !seen[i] {
			seen[i] = true
			j.loose = append(j.loose, s.Entries[i].ID)
		}
	}
	for _, x := range ss {
		j.sigs[x.ID] = x
	}
	for i, e := range s.Entries {
		if e.Kind != "code" {
			continue
		}
		if e.Coverage != CoverRoutes || e.RoutesTruncated {
			loose(i)
		}
		if e.Coverage != CoverRoutes {
			continue
		}
		for _, r := range e.Routes {
			re, lax := routeRegexp(r.Pattern)
			if re != nil {
				j.routes = append(j.routes, routeEntry{i, r, re})
			}
			// Reached some way not matched (no expression), an expression
			// not checked, or a route whose mount prefix matters (the root,
			// /:id): the class's hits elsewhere are unanchored, never noise.
			if re == nil || lax {
				loose(i)
			}
		}
	}
	return j
}

var placeholder = regexp.MustCompile(`\{[^/{}]+\}|<[^/<>]+>|:[A-Za-z_][A-Za-z0-9_]*(?:\((?:[^()]|\([^()]*\))*\))?[*+?]?|\*[A-Za-z0-9_]*`)

// manySegments: a placeholder that takes a path of several segments:
// Flask's and Django's <path:f>, FastAPI's {p:path}, Express's * and :p*.
func manySegments(ph string) bool {
	return strings.HasPrefix(ph, "<path:") || strings.HasSuffix(ph, ":path}") || strings.HasPrefix(ph, "*") ||
		strings.HasSuffix(ph, "*") || strings.HasSuffix(ph, "+")
}

// routeRegexp makes a route pattern (as written: /users/{id}, /run/<cmd>,
// /api/:id, Express's /users/:id? and /user/:id(\d+), Django's
// report/<str:name>/ and re_path's ^article/\d+/$, WordPress's
// /wp-json/ns/(?P<id>\d+)) an expression the routed path must end with,
// from a segment's start (PatternMeaning: no mount prefix is known). A
// pattern without a leading / gets one (Django, Laravel write none). nil
// for none: a hook's empty pattern, an expression that does not compile.
//
// loose: the expression may miss requests the route takes, so its sink's
// class hits elsewhere must stay unanchored, not noise: a pattern taken
// as a regular expression (what it matches is not checked), the root, or
// one starting with a placeholder. The last two are anchored at the
// path's start (L1 only without a mount prefix): as suffixes they would
// match nearly every request.
func routeRegexp(pattern string) (re *regexp.Regexp, loose bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, true
	}
	if !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "^") {
		pattern = "/" + pattern
	}
	bare := placeholder.ReplaceAllString(pattern, "")
	if strings.ContainsAny(bare, `\[|+?()^$`) || strings.Contains(bare, ".*") { // re_path, WordPress, Express's /ab?c: an expression
		// The leading / goes before parsing: the syntax tree may print
		// flags first ((?-s:/files/...)), and the / is put back below.
		expr, err := stripAnchors(strings.TrimPrefix(strings.TrimPrefix(pattern, "^"), "/"))
		if err != nil {
			return nil, true
		}
		expr = strings.TrimSuffix(expr, "/") // the trailing / is optional below
		re, err = regexp.Compile(`(?i)/(?:` + expr + `)/?$`)
		if err != nil {
			return nil, true
		}
		return re, true
	}
	if strings.Trim(pattern, "/") == "" {
		return regexp.MustCompile(`^/?$`), true
	}
	var b strings.Builder
	idx := placeholder.FindAllStringIndex(pattern, -1)
	last := 0
	for _, m := range idx {
		lit, ph := pattern[last:m[0]], pattern[m[0]:m[1]]
		switch {
		case strings.HasSuffix(ph, "?") && strings.HasSuffix(lit, "/"): // Express's optional /:id?
			b.WriteString(regexp.QuoteMeta(lit[:len(lit)-1]) + `(?:/([^/]+))?`)
		case manySegments(ph):
			b.WriteString(regexp.QuoteMeta(lit) + `(.+)`)
		default:
			b.WriteString(regexp.QuoteMeta(lit) + `([^/]+)`)
		}
		last = m[1]
	}
	b.WriteString(regexp.QuoteMeta(pattern[last:]))
	expr := strings.TrimSuffix(b.String(), "/")
	anchor := ""
	if len(idx) > 0 && idx[0][0] == 1 { // /:id, /{slug}, /:id?: anchored, as the root is
		anchor, loose = "^", true
	}
	re, err := regexp.Compile(`(?i)` + anchor + expr + `/?$`)
	if err != nil {
		return nil, true
	}
	return re, loose
}

// stripAnchors is expr without the ^ and $ that start and end its
// branches (re_path's ^foo/$|^bar/$ is anchored at the mount point, which
// is not known).
func stripAnchors(expr string) (string, error) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return "", err
	}
	anchor := func(r *syntax.Regexp) bool {
		switch r.Op {
		case syntax.OpBeginText, syntax.OpBeginLine, syntax.OpEndText, syntax.OpEndLine:
			return true
		}
		return false
	}
	var strip func(*syntax.Regexp) *syntax.Regexp
	strip = func(r *syntax.Regexp) *syntax.Regexp {
		switch {
		case anchor(r):
			return &syntax.Regexp{Op: syntax.OpEmptyMatch}
		case r.Op == syntax.OpAlternate || r.Op == syntax.OpCapture:
			for i, s := range r.Sub {
				r.Sub[i] = strip(s)
			}
		case r.Op == syntax.OpConcat:
			for len(r.Sub) > 0 && anchor(r.Sub[0]) {
				r.Sub = r.Sub[1:]
			}
			for len(r.Sub) > 0 && anchor(r.Sub[len(r.Sub)-1]) {
				r.Sub = r.Sub[:len(r.Sub)-1]
			}
			if len(r.Sub) > 0 {
				r.Sub[0] = strip(r.Sub[0])
				r.Sub[len(r.Sub)-1] = strip(r.Sub[len(r.Sub)-1])
			}
		}
		return r
	}
	return strip(re).String(), nil
}

// placeholderTook says whether one of a route's placeholder values holds
// one of the path segments whole, as sent or as cleanPath reads it (the
// route is matched on the cleaned path).
func placeholderTook(vals, segs []string) bool {
	for _, v := range vals {
		v = "/" + strings.ToLower(v) + "/"
		for _, sg := range segs {
			if v != "//" && (strings.Contains(v, "/"+sg+"/") || strings.Contains(v, "/"+cleanSegment(sg)+"/")) {
				return true
			}
		}
	}
	return false
}

// Judge judges one matched request (MatchResult of the record or of one
// of its other splits).
func (j *Judge) Judge(m MatchResult) Judgment {
	out := Judgment{Cut: m.Request.Cut, CutParts: m.Request.CutParts, TimedOut: m.TimedOut}
	byEntry := map[int]int{} // entry -> index in out.Candidates
	// add gives the candidate for entry i, made at level if new, raised to
	// level if it was lower.
	add := func(i int, level string, h *Hit) {
		k, ok := byEntry[i]
		if !ok {
			out.Candidates = append(out.Candidates, Candidate{Entry: j.surface.Entries[i].ID, Level: level})
			k = len(out.Candidates) - 1
			byEntry[i] = k
		}
		c := &out.Candidates[k]
		if level > c.Level {
			c.Level = level
		}
		if h != nil {
			c.Hits = append(c.Hits, *h)
		}
	}
	// Code sinks whose route the request reached: L1, and L2 with a hit of
	// the sink's payload class.
	// reached: the entry, and the values its routes' placeholders took.
	reached := map[int][]string{}
	for _, r := range j.routes {
		// The routed path, and the path with its dot segments as sent: a
		// router that does not resolve them (or a traversal it lets
		// through) routes that one.
		q := m.Request
		if !methodOK(r.ref.Method, q.Method) {
			continue
		}
		sm := r.re.FindStringSubmatch(q.Path)
		if sm == nil && q.RawPath != "" {
			sm = r.re.FindStringSubmatch(q.RawPath)
		}
		if sm == nil {
			continue
		}
		ref := r.ref
		add(r.entry, LevelRoute, nil)
		if c := &out.Candidates[byEntry[r.entry]]; c.Route == nil {
			c.Route = &ref
		}
		reached[r.entry] = append(reached[r.entry], sm[1:]...)
	}
	// A path cut may join two far parts into a route (the cut is between
	// them): a route reached then is L1 at most, its hits unanchored.
	pathCut := slices.ContainsFunc(m.Request.CutParts, func(c CutPart) bool { return c.Part == "path" })
	used := map[int]bool{} // hits that found a vulnerability of this host
	for hi, h := range m.Hits {
		s, ok := j.sigs[h.Signature]
		if !ok {
			continue
		}
		if len(s.CVEs) == 0 && len(s.Advisories) == 0 && len(s.AppliesTo) == 0 { // a class signature
			for i, vals := range reached {
				// A hit in a path segment counts only when the route's
				// placeholder took that segment: a mount prefix or the
				// route's own words reach no handler (review 2 of #87, N-1).
				taken := len(h.Segments) == 0 || placeholderTook(vals, h.Segments)
				if j.surface.Entries[i].Payload == h.Class && !pathCut && taken {
					add(i, LevelPayload, &h)
					used[hi] = true
				}
				if j.surface.Entries[i].Payload == h.Class && (pathCut || !taken) && !used[hi] {
					out.Unanchored, used[hi] = append(out.Unanchored, h), true
				}
			}
			if !used[hi] && j.classes[h.Class] {
				out.Unanchored, used[hi] = append(out.Unanchored, h), true
			}
			continue
		}
		for i, e := range j.surface.Entries { // a signature for a vulnerability: does this host have it?
			if e.Kind != "package" || !forEntry(s, e) {
				continue
			}
			in, known := true, true
			if len(s.AppliesTo) > 0 {
				in, known = appliesTo(s, e)
			}
			if !in && known {
				continue
			}
			level := LevelPayload
			if h.RouteOnly || pathCut && len(s.Routes) > 0 {
				level = LevelRoute
			}
			add(i, level, &h)
			if !known {
				out.Candidates[byEntry[i]].VersionUnknown = true
			}
			used[hi] = true
		}
	}
	for hi, h := range m.Hits {
		if !used[hi] {
			out.Noise = append(out.Noise, h)
		}
	}
	out.Unknown = out.Cut && !slices.ContainsFunc(out.Candidates, func(c Candidate) bool { return c.Level == LevelPayload })
	sort.SliceStable(out.Candidates, func(a, b int) bool {
		if out.Candidates[a].Level != out.Candidates[b].Level {
			return out.Candidates[a].Level > out.Candidates[b].Level
		}
		return out.Candidates[a].Entry < out.Candidates[b].Entry
	})
	if out.Unknown {
		classes := maps.Clone(j.classes)
		var ids []string
		for i := range byEntry { // the candidates, all L1
			e := j.surface.Entries[i]
			if e.Payload != "" {
				classes[e.Payload] = true
			}
			ids = append(ids, e.ID)
		}
		slices.Sort(ids)
		for _, id := range j.loose { // and the sinks reached some way not matched
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		out.HiddenSinks = ids[:min(len(ids), MaxHidden)]
		out.HiddenSinksMore = len(ids) - len(out.HiddenSinks)
		out.HiddenClasses = slices.Sorted(maps.Keys(classes))
	}
	return out
}

// forEntry: s is written for e's vulnerability: a CVE or an advisory id in
// common, or (with no ids) its package.
func forEntry(s sig.Signature, e Entry) bool {
	ids := map[string]bool{strings.ToUpper(e.Advisory): true, strings.ToUpper(e.CVE): true, strings.ToUpper(e.KEVCVE): true}
	for _, a := range e.Aliases {
		ids[strings.ToUpper(a)] = true
	}
	delete(ids, "")
	for _, c := range append(append([]string{}, s.CVEs...), s.Advisories...) {
		if ids[strings.ToUpper(c)] {
			return true
		}
	}
	if len(s.CVEs) == 0 && len(s.Advisories) == 0 {
		for _, r := range s.AppliesTo {
			if strings.EqualFold(r.Ecosystem, e.Ecosystem) && samePackage(e.Ecosystem, r.Package, e.Package) {
				return true
			}
		}
	}
	return false
}

// appliesTo: e's installed version is in one of s's ranges for its package;
// known is false when a range could not be compared, or when s lists no
// range for e's package (written for e's CVE, it names other packages: a
// fork, a renamed one): a candidate, its version not known.
func appliesTo(s sig.Signature, e Entry) (in, known bool) {
	known = true
	listed := false
	for _, r := range s.AppliesTo {
		if !strings.EqualFold(r.Ecosystem, e.Ecosystem) || !samePackage(e.Ecosystem, r.Package, e.Package) {
			continue
		}
		listed = true
		i, ok := sig.InRange(r, e.Version)
		if !ok {
			known = false
			continue
		}
		if i {
			return true, true
		}
	}
	return false, known && listed
}

var pep503 = regexp.MustCompile(`[-_.]+`)

// samePackage: a and b name one package of ecosystem: PyPI's names
// normalized as PEP 503 says, Packagist's case-insensitive (Composer
// lower-cases them), the others as written.
func samePackage(ecosystem, a, b string) bool {
	switch strings.ToLower(ecosystem) {
	case "pypi":
		return pep503.ReplaceAllString(strings.ToLower(a), "-") == pep503.ReplaceAllString(strings.ToLower(b), "-")
	case "packagist":
		return strings.EqualFold(a, b)
	}
	return a == b
}

// methodOK: a route registered for method (any, all, match or none: every
// method) takes the request's. A GET route takes HEAD too: frameworks
// answer it with the GET handler.
func methodOK(route, req string) bool {
	switch strings.ToLower(route) {
	case "", "any", "all", "match", "route", "use", "api_route", "add_url_rule":
		return true
	}
	if strings.EqualFold(req, "HEAD") && strings.EqualFold(route, "get") {
		return true
	}
	return strings.EqualFold(route, req)
}
