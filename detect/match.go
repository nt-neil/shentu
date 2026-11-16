package detect

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nt-neil/shentu/detect/sig"
)

// Bounds on matching one request: decoding stops after MaxDecodeRounds,
// a normalized value is cut at MaxNormalized, and matching one request
// stops at MaxMatchTime (said, never taken as no hit). Matching runs inside
// the read's LineFunc, so its time counts against the run's budget too.
const (
	MaxDecodeRounds = 2
	MaxNormalized   = 16 << 10
	MaxParams       = 256
	MaxMatchTime    = 10 * time.Millisecond
)

// Request is a request as signatures see it: every text decoded at most
// MaxDecodeRounds times (%XX, IIS's %uXXXX, + as a space in the query),
// overlong UTF-8 folded to what it stands for, NUL kept as \x00, lower
// case.
type Request struct {
	Method string
	// RawPath is the path decoded, its dot segments kept (a ../ is
	// evidence); Path the same with them resolved and // collapsed, for
	// routes.
	RawPath, Path string
	Query         string              // the whole query, decoded
	Params        map[string][]string // every value of every parameter, in order (a repeated one keeps all)
	UserAgent     string
	Referer       string
	// Encoded: decoding changed something past the first round (a double
	// encoding), or a %u or overlong form was used: evasion, a signal.
	Encoded bool
	Cut     bool // some text was cut at MaxNormalized or the parameters at MaxParams
}

// Normalize makes a Request of a record. Parameters are split here, not
// with url.ParseQuery, which refuses a malformed escape an attacker would
// send on purpose.
func Normalize(r AccessRecord) Request {
	q := Request{Method: strings.ToUpper(r.Method), Params: map[string][]string{}}
	var enc bool
	q.RawPath, enc = normalizeText(r.Path, false)
	q.Encoded = q.Encoded || enc
	q.Path = cleanPath(q.RawPath)
	q.Query, enc = normalizeText(r.Query, true)
	q.Encoded = q.Encoded || enc
	n := 0
	for _, kv := range strings.Split(r.Query, "&") {
		if kv == "" {
			continue
		}
		if n >= MaxParams {
			q.Cut = true
			break
		}
		n++
		k, v, _ := strings.Cut(kv, "=")
		nk, e1 := normalizeText(k, true)
		nv, e2 := normalizeText(v, true)
		q.Encoded = q.Encoded || e1 || e2
		q.Params[nk] = append(q.Params[nk], nv)
	}
	q.UserAgent, _ = normalizeText(r.UserAgent, false)
	q.Referer, _ = normalizeText(r.Referer, false)
	for _, s := range []string{q.RawPath, q.Query, q.UserAgent, q.Referer} {
		if len(s) >= MaxNormalized {
			q.Cut = true
		}
	}
	return q
}

// normalizeText decodes s at most MaxDecodeRounds times, folds overlong
// UTF-8, and lower-cases it; enc says an evasive encoding was seen.
func normalizeText(s string, query bool) (string, bool) {
	if len(s) > MaxNormalized {
		s = s[:MaxNormalized]
	}
	enc := false
	for round := 0; round < MaxDecodeRounds; round++ {
		d, u := percentDecode(s, query && round == 0)
		if u {
			enc = true
		}
		if d == s {
			break
		}
		if round > 0 {
			enc = true // still encoded after one decoding
		}
		s = d
	}
	f, over := foldOverlong(s)
	if over {
		enc = true
	}
	return strings.ToLower(f), enc
}

// percentDecode decodes %XX and %uXXXX (u: one was), and + as a space when
// plus. A malformed escape is left as it is.
func percentDecode(s string, plus bool) (string, bool) {
	if !strings.ContainsAny(s, "%+") {
		return s, false
	}
	var b strings.Builder
	u := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+' && plus:
			b.WriteByte(' ')
		case c == '%' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U'):
			if n, err := strconv.ParseUint(s[i+2:i+6], 16, 16); err == nil {
				b.WriteRune(rune(n))
				i += 5
				u = true
				continue
			}
			b.WriteByte(c)
		case c == '%' && i+2 < len(s):
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), u
}

// foldOverlong replaces overlong UTF-8 forms (C0 AE for '.', E0 80 AF for
// '/') with the character they encode, as a lenient decoder would read
// them: the evasion they are for.
func foldOverlong(s string) (string, bool) {
	if utf8.ValidString(s) {
		return s, false
	}
	var b strings.Builder
	over := false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case (c == 0xC0 || c == 0xC1) && i+1 < len(s) && s[i+1]&0xC0 == 0x80:
			b.WriteByte((c&0x1F)<<6 | s[i+1]&0x3F)
			i += 2
			over = true
		case c == 0xE0 && i+2 < len(s) && s[i+1]&0xE0 == 0x80 && s[i+2]&0xC0 == 0x80:
			r := rune(c&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F)
			b.WriteRune(r)
			i += 3
			over = true
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), over
}

// cleanPath resolves dot segments and collapses slashes.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	return c
}

// Hit is one signature a request carried.
type Hit struct {
	Signature string `json:"signature"`
	Class     string `json:"class"`
	Part      string `json:"part,omitempty"`  // where the payload was (the first match's): path, query, param, user_agent, referer
	Param     string `json:"param,omitempty"` // the parameter, for param and any_param
	Excerpt   string `json:"excerpt,omitempty"`
	RouteOnly bool   `json:"route_only,omitempty"` // a signature with routes and no match: the route alone
}

// MatchResult is what a request matched.
type MatchResult struct {
	Request  Request
	Hits     []Hit
	TimedOut bool // stopped at MaxMatchTime: other signatures were not tried
}

// Matcher matches requests against signatures.
type Matcher struct {
	sigs   []sig.Signature
	routes [][]*regexp.Regexp
	now    func() time.Time
}

// NewMatcher compiles the routes of ss.
func NewMatcher(ss []sig.Signature) *Matcher {
	m := &Matcher{sigs: ss, now: time.Now}
	for _, s := range ss {
		var res []*regexp.Regexp
		for _, r := range s.Routes {
			if r.PathRegex != "" {
				res = append(res, regexp.MustCompile(r.PathRegex)) // checked by sig.Load
			} else {
				res = append(res, nil)
			}
		}
		m.routes = append(m.routes, res)
	}
	return m
}

// MatchRecord matches a record and its other splits (AccessRecord.Alts):
// a hit in any counts.
func (m *Matcher) MatchRecord(r AccessRecord) []MatchResult {
	out := []MatchResult{m.Match(Normalize(r))}
	for _, a := range r.Alts {
		out = append(out, m.Match(Normalize(a)))
	}
	return out
}

// Match tries every signature on q, at most MaxMatchTime.
func (m *Matcher) Match(q Request) MatchResult {
	res := MatchResult{Request: q}
	start := m.now()
	for i, s := range m.sigs {
		if m.now().Sub(start) > MaxMatchTime {
			res.TimedOut = true
			break
		}
		if len(s.Routes) > 0 && !m.routeHolds(i, q) {
			continue
		}
		if len(s.Matches) == 0 {
			res.Hits = append(res.Hits, Hit{Signature: s.ID, Class: s.Class, RouteOnly: true})
			continue
		}
		hit := Hit{Signature: s.ID, Class: s.Class}
		all := true
		for j, mt := range s.Matches {
			part, param, ex, ok := matchOne(mt, q)
			if !ok {
				all = false
				break
			}
			if j == 0 {
				hit.Part, hit.Param, hit.Excerpt = part, param, ex
			}
		}
		if all {
			res.Hits = append(res.Hits, hit)
		}
	}
	return res
}

func (m *Matcher) routeHolds(i int, q Request) bool {
	for j, r := range m.sigs[i].Routes {
		if len(r.Methods) > 0 && !containsStr(r.Methods, q.Method) {
			continue
		}
		if r.Path != "" && !strings.HasSuffix(q.Path, strings.ToLower(r.Path)) {
			continue
		}
		if re := m.routes[i][j]; re != nil && !re.MatchString(q.Path) {
			continue
		}
		return true
	}
	return false
}

// matchOne tries one match: where it held, and an excerpt of what held.
func matchOne(mt sig.Match, q Request) (part, param, excerpt string, ok bool) {
	try := func(text string) (string, bool) {
		for _, c := range mt.Contains {
			if i := strings.Index(text, c); i >= 0 {
				return excerptAt(text, i, len(c)), true
			}
		}
		if re := mt.Re(); re != nil {
			if loc := re.FindStringIndex(text); loc != nil {
				return excerptAt(text, loc[0], loc[1]-loc[0]), true
			}
		}
		return "", false
	}
	switch mt.Part {
	case "path":
		ex, ok := try(q.RawPath)
		return "path", "", ex, ok
	case "query":
		ex, ok := try(q.Query)
		return "query", "", ex, ok
	case "user_agent":
		ex, ok := try(q.UserAgent)
		return "user_agent", "", ex, ok
	case "referer":
		ex, ok := try(q.Referer)
		return "referer", "", ex, ok
	case "param":
		for _, v := range q.Params[strings.ToLower(mt.Param)] {
			if ex, ok := try(v); ok {
				return "param", mt.Param, ex, true
			}
		}
	case "any_param":
		keys := make([]string, 0, len(q.Params))
		for k := range q.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys) // the same request names the same parameter every time
		for _, k := range keys {
			for _, v := range q.Params[k] {
				if ex, ok := try(v); ok {
					return "any_param", k, ex, true
				}
			}
		}
	}
	return "", "", "", false
}

// excerptAt is up to 64 bytes around the match, for a person to read.
func excerptAt(s string, i, n int) string {
	from, to := max(0, i-16), min(len(s), i+n+16)
	if to-from > 64 {
		to = from + 64
	}
	return s[from:to]
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
