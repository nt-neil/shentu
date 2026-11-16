package detect

import (
	"regexp"
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
}

// Judge says which of the surface's vulnerabilities a matched request may
// be trying.
type Judge struct {
	surface Surface
	sigs    map[string]sig.Signature
	routes  []routeEntry
	classes map[string]bool // payload classes of sinks with no known route
}

type routeEntry struct {
	entry int
	ref   engine.RouteRef
	re    *regexp.Regexp // matches the request's routed path, by suffix
}

// NewJudge indexes the surface's routes and the signatures by id.
func NewJudge(s Surface, ss []sig.Signature) *Judge {
	j := &Judge{surface: s, sigs: map[string]sig.Signature{}, classes: map[string]bool{}}
	for _, x := range ss {
		j.sigs[x.ID] = x
	}
	for i, e := range s.Entries {
		if e.Kind != "code" {
			continue
		}
		if e.Coverage != CoverRoutes {
			j.classes[e.Payload] = true
			continue
		}
		for _, r := range e.Routes {
			if re := routeRegexp(r.Pattern); re != nil {
				j.routes = append(j.routes, routeEntry{i, r, re})
			}
		}
	}
	return j
}

var placeholder = regexp.MustCompile(`\{[^/{}]+\}|<[^/<>]+>|:[A-Za-z_][A-Za-z0-9_]*`)

// routeRegexp makes a route pattern (as written: /users/{id}, /run/<cmd>,
// /api/:id, WordPress's /wp-json/ns/(?P<id>\d+)) an expression the routed
// path must end with (PatternMeaning: no mount prefix is known). nil for
// none (a hook, an empty pattern, an expression that does not compile).
func routeRegexp(pattern string) *regexp.Regexp {
	if pattern == "" || !strings.HasPrefix(pattern, "/") {
		return nil
	}
	var expr string
	if strings.Contains(pattern, "(") { // WordPress's route is an expression already
		expr = pattern
	} else {
		idx := placeholder.FindAllStringIndex(pattern, -1)
		var b strings.Builder
		last := 0
		for _, m := range idx {
			b.WriteString(regexp.QuoteMeta(pattern[last:m[0]]))
			b.WriteString(`[^/]+`)
			last = m[1]
		}
		b.WriteString(regexp.QuoteMeta(pattern[last:]))
		expr = b.String()
	}
	re, err := regexp.Compile(`(?i)` + strings.TrimSuffix(expr, "/") + `/?$`)
	if err != nil {
		return nil
	}
	return re
}

// Judge judges one matched request (MatchResult of the record or of one
// of its other splits).
func (j *Judge) Judge(m MatchResult) Judgment {
	var out Judgment
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
	reached := map[int]bool{}
	for _, r := range j.routes {
		if !methodOK(r.ref.Method, m.Request.Method) || !r.re.MatchString(m.Request.Path) {
			continue
		}
		ref := r.ref
		add(r.entry, LevelRoute, nil)
		if c := &out.Candidates[byEntry[r.entry]]; c.Route == nil {
			c.Route = &ref
		}
		reached[r.entry] = true
	}
	used := map[int]bool{} // hits that found a vulnerability of this host
	for hi, h := range m.Hits {
		s, ok := j.sigs[h.Signature]
		if !ok {
			continue
		}
		if len(s.CVEs) == 0 && len(s.Advisories) == 0 && len(s.AppliesTo) == 0 { // a class signature
			for i := range reached {
				if j.surface.Entries[i].Payload == h.Class {
					add(i, LevelPayload, &h)
					used[hi] = true
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
			if h.RouteOnly {
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
	sort.SliceStable(out.Candidates, func(a, b int) bool {
		if out.Candidates[a].Level != out.Candidates[b].Level {
			return out.Candidates[a].Level > out.Candidates[b].Level
		}
		return out.Candidates[a].Entry < out.Candidates[b].Entry
	})
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
			if strings.EqualFold(r.Ecosystem, e.Ecosystem) && r.Package == e.Package {
				return true
			}
		}
	}
	return false
}

// appliesTo: e's installed version is in one of s's ranges for its package;
// known is false when a range could not be compared.
func appliesTo(s sig.Signature, e Entry) (in, known bool) {
	known = true
	for _, r := range s.AppliesTo {
		if !strings.EqualFold(r.Ecosystem, e.Ecosystem) || r.Package != e.Package {
			continue
		}
		i, ok := sig.InRange(r, e.Version)
		if !ok {
			known = false
			continue
		}
		if i {
			return true, true
		}
	}
	return false, known
}

// methodOK: a route registered for method (any, all, match or none: every
// method) takes the request's.
func methodOK(route, req string) bool {
	switch strings.ToLower(route) {
	case "", "any", "all", "match", "route", "use", "api_route", "add_url_rule":
		return true
	}
	return strings.EqualFold(route, req)
}
