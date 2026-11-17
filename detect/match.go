package detect

import (
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nt-neil/shentu/detect/sig"
)

// Bounds on matching one request. Its cost is bounded by the length of
// what is matched, not by a clock: decoding stops after MaxDecodeRounds,
// each text (the path, a user agent, a referer, one parameter's name or
// value) is cut at MaxNormalized, the whole query and all the parameters'
// values together at MaxParamsText, their number at MaxParams; a cut keeps
// the text's start and end (headTail) and is said (Request.Cut), never
// taken as no hit. Every signature is tried on what
// is left. MaxMatchTime is only watched: a request that took longer is
// said (MatchResult.TimedOut), its signatures all tried all the same.
const (
	MaxDecodeRounds = 2
	MaxNormalized   = 8 << 10
	MaxParamsText   = 16 << 10
	MaxParams       = 256
	MaxParamsLast   = 32 // of MaxParams, the last ones of a request that has more
	// MinValueKept: a value past MaxParamsText keeps this much of its start
	// and end all the same, so a long value first cannot hide the next.
	MinValueKept = 64
	MaxMatchTime = 10 * time.Millisecond
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
	// Segments: the path as sent split at /, each segment then decoded
	// and lower-cased, as a router hands a parameter its value (nil when
	// the path was longer than MaxNormalized).
	Segments []string
	// PlainPath: those segments decoded in their case, an / one held
	// kept as %2F, dot segments resolved, nothing else cleaned: an
	// anchored route's path ("" when longer than MaxNormalized).
	PlainPath string
	// CasePath is Path in the case it was sent ("" when the path was
	// longer than MaxNormalized: Path is used then), for a
	// case-sensitive route.
	CasePath string
	Query    string              // the whole query, decoded
	Params   map[string][]string // every value of every parameter, in order (a repeated one keeps all)
	// Sent: the names in Params as the request sent them; the others are
	// how a framework reads one (PHP's id for id[]) and hold its values
	// again: any_param tries only these, so a value is not matched twice.
	Sent      map[string]bool
	UserAgent string
	Referer   string
	// Raw holds what the request sent, as logged (not decoded, its case),
	// for the evidence an alert shows: the record's path, query, user
	// agent and referer, and each parameter's values under its key.
	Raw       AccessRecord
	RawParams map[string][]string
	// Encoded: decoding changed something past the first round (a double
	// encoding), or a %u or overlong form was used: evasion, a signal.
	Encoded bool
	Cut     bool // some text was cut at MaxNormalized, the parameters' values at MaxParamsText or their number at MaxParams
	// CutParts says what was cut, at most MaxCutParts of them.
	CutParts []CutPart
}

// CutPart is one text Normalize cut: its part (path, query, param,
// user_agent, referer; params for their number), the parameter, and how
// much was sent and kept (bytes; parameters for params).
type CutPart struct {
	Part  string `json:"part"`
	Param string `json:"param,omitempty"`
	Sent  int    `json:"sent"`
	Kept  int    `json:"kept"`
}

// MaxCutParts bounds Request.CutParts.
const MaxCutParts = 16

// Normalize makes a Request of a record. Parameters are split here, not
// with url.ParseQuery, which refuses a malformed escape an attacker would
// send on purpose.
func Normalize(r AccessRecord) Request {
	q := Request{Method: strings.ToUpper(r.Method), Params: map[string][]string{}, Sent: map[string]bool{}, RawParams: map[string][]string{}, Raw: r}
	q.Raw.Alts = nil
	var enc, cut bool
	said := func(cut bool, part, param string, sent, kept int) {
		if cut {
			q.Cut = true
			if len(q.CutParts) < MaxCutParts {
				q.CutParts = append(q.CutParts, CutPart{part, param[:min(len(param), 64)], sent, kept})
			}
		}
	}
	q.RawPath, enc, cut = normalizeText(r.Path, false)
	q.Encoded = q.Encoded || enc
	said(cut, "path", "", len(r.Path), len(q.RawPath))
	q.Path = cleanPath(q.RawPath)
	if len(r.Path) <= MaxNormalized {
		cp, _ := decodePiece(r.Path, false)
		q.CasePath = cleanPath(cp)
		var plain []string
		for _, sg := range strings.Split(r.Path, "/") {
			d, _ := decodePiece(sg, false)
			n, _ := normalizePiece(sg, false)
			q.Segments = append(q.Segments, n)
			plain = append(plain, strings.ReplaceAll(d, "/", "%2F"))
		}
		q.PlainPath = path.Clean("/" + strings.Join(plain, "/"))
	}
	q.Query, enc, cut = normalizeTextN(r.Query, true, MaxParamsText) // the whole query: the parameters' bound
	q.Encoded = q.Encoded || enc
	said(cut, "query", "", len(r.Query), len(q.Query))
	var kvs []string
	for _, kv := range strings.Split(r.Query, "&") {
		if kv != "" {
			kvs = append(kvs, kv)
		}
	}
	if len(kvs) > MaxParams { // the first ones and the last: many before a parameter do not push it out
		said(true, "params", "", len(kvs), MaxParams)
		kvs = append(kvs[:MaxParams-MaxParamsLast:MaxParams-MaxParamsLast], kvs[len(kvs)-MaxParamsLast:]...)
	}
	left := MaxParamsText
	for _, kv := range kvs {
		k, v, _ := strings.Cut(kv, "=")
		nk, e1, c1 := normalizeText(k, true)
		nv, e2, c2 := normalizeText(v, true)
		q.Encoded = q.Encoded || e1 || e2
		if len(nv) > left { // every value together: the request's cost is bounded, not each value's
			nv, c2 = headTail(nv, max(left, MinValueKept)), true // a value past the bound keeps its end too
		}
		said(c1 || c2, "param", nk, len(kv), len(nk)+len(nv))
		left = max(0, left-len(nv))
		q.Sent[nk] = true
		for _, key := range paramNames(nk) { // as sent, and as PHP and others read it
			q.Params[key] = append(q.Params[key], nv)
			q.RawParams[key] = append(q.RawParams[key], v)
		}
	}
	q.UserAgent, _, cut = normalizeText(r.UserAgent, false)
	said(cut, "user_agent", "", len(r.UserAgent), len(q.UserAgent))
	q.Referer, _, cut = normalizeText(r.Referer, false)
	said(cut, "referer", "", len(r.Referer), len(q.Referer))
	return q
}

// paramNames is a parameter's name as sent, and as a framework reads it
// when that differs: PHP turns ' ', '.' and '[' into '_' and takes
// a[b] or a[] for a: a signature for "id" must see i.d and id[].
func paramNames(k string) []string {
	c := k
	if i := strings.IndexByte(c, '['); i > 0 && strings.HasSuffix(c, "]") {
		c = c[:i]
	}
	c = strings.NewReplacer(" ", "_", ".", "_", "[", "_").Replace(c)
	if c == k {
		return []string{k}
	}
	return []string{k, c}
}

// normalizeText decodes s at most MaxDecodeRounds times, folds overlong
// UTF-8, and lower-cases it; enc says an evasive encoding was seen, cut
// that s was longer than MaxNormalized and only its start and its end were
// taken.
func normalizeText(s string, query bool) (string, bool, bool) {
	return normalizeTextN(s, query, MaxNormalized)
}

// headTail is s cut to n bytes, keeping its start and its end (a quarter
// of n) joined by cutMark: padding before a payload does not push it out.
// The two are matched apart (pieces), never as one text.
func headTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	tail := n / 4
	head := n - tail - len(cutMark)
	if head < 0 {
		return s[len(s)-n:]
	}
	return s[:head] + cutMark + s[len(s)-tail:]
}

// cutMark is where headTail joined what it kept. Normalized text holds no
// other (normalizePiece turns a sent one into U+FFFD), so pieces splits
// on it: a match never spans it.
const cutMark = "\x1f"

// pieces is a normalized text's parts, matched one by one.
func pieces(s string) []string {
	if !strings.Contains(s, cutMark) {
		return []string{s}
	}
	return strings.Split(s, cutMark)
}

// normalizeTextN is normalizeText cutting at limit: past it, the start and
// the end (headTail's shares) are normalized apart and joined by cutMark.
func normalizeTextN(s string, query bool, limit int) (string, bool, bool) {
	if len(s) <= limit {
		t, enc := normalizePiece(s, query)
		if len(t) > limit { // lower-casing can lengthen some characters
			return headTail(t, limit), enc, true
		}
		return t, enc, false
	}
	tail := limit / 4
	head := limit - tail - len(cutMark)
	h, e1 := normalizePiece(s[:head], query)
	t, e2 := normalizePiece(s[len(s)-tail:], query)
	if len(h) > head {
		h = h[:head]
	}
	if len(t) > tail {
		t = t[len(t)-tail:]
	}
	return h + cutMark + t, e1 || e2, true
}

// normalizePiece decodes, folds and lower-cases s; enc says an evasive
// encoding was seen. A cutMark it holds becomes U+FFFD (visible, and
// neither \s nor a word character, so it joins nothing) and is said as
// an evasive encoding.
func normalizePiece(s string, query bool) (string, bool) {
	f, enc := decodePiece(s, query)
	l := strings.ToLower(f)
	if strings.Contains(l, cutMark) { // sent to split a payload as a cut would: evasion, said
		l, enc = strings.ReplaceAll(l, cutMark, "\uFFFD"), true
	}
	return l, enc
}

// decodePiece is s decoded and its overlong UTF-8 folded, in its case.
func decodePiece(s string, query bool) (string, bool) {
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
	return f, enc || over
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

// cleanPath is the path as a server routes it: dot segments resolved,
// slashes collapsed, backslashes as slashes, each segment's ;parameters
// dropped (Tomcat, Spring: /admin;x=1 is /admin), and the trailing dots,
// spaces and ::$DATA Windows drops from a name.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(strings.ReplaceAll(p, "\\", "/"), "/")
	for i, sg := range segs {
		segs[i] = cleanSegment(sg)
	}
	return path.Clean("/" + strings.Join(segs, "/"))
}

// cleanSegment is one segment as cleanPath reads it.
func cleanSegment(sg string) string {
	if j := strings.IndexByte(sg, ';'); j >= 0 {
		sg = sg[:j]
	}
	sg = strings.TrimSuffix(sg, "::$data")
	if sg == "." || sg == ".." { // dot segments are resolved, not trimmed
		return sg
	}
	return strings.TrimRight(sg, ". ")
}

// Hit is one signature a request carried.
type Hit struct {
	Signature string `json:"signature"`
	Class     string `json:"class"`
	Part      string `json:"part,omitempty"`    // where the payload was (the first match's): path, query, param, user_agent, referer
	Param     string `json:"param,omitempty"`   // the parameter, for param and any_param
	Excerpt   string `json:"excerpt,omitempty"` // the normalized text around the match
	// Raw is what the request sent in that part, as logged (its case, not
	// decoded), at most 256 bytes: the evidence an alert shows.
	Raw       string `json:"raw,omitempty"`
	RouteOnly bool   `json:"route_only,omitempty"` // a signature with routes and no match: the route alone
	// Segments: the path segments a class signature held in (part path,
	// any_param), decoded, every one of them: L2 only where a route's
	// placeholder took one.
	Segments []string `json:"segments,omitempty"`
}

// MatchResult is what a request matched.
type MatchResult struct {
	Request Request
	Hits    []Hit
	// TimedOut: matching took longer than MaxMatchTime. Every signature was
	// tried all the same; it says the host was slow or the request costly.
	TimedOut bool
}

// Matcher matches requests against signatures.
type Matcher struct {
	sigs   []sig.Signature
	routes [][]*regexp.Regexp
	now    func() time.Time
}

// pathHolds says whether a route's Path is in the request's path: at the
// end, or followed by PATH_INFO (/x.php/anything). An anchored route is
// taken from PlainPath, at its end only.
func pathHolds(r sig.Route, q Request) bool {
	p, rp := q.Path, strings.ToLower(r.Path)
	if r.CaseSensitive && q.CasePath != "" { // a path too long for it: compared without case, not skipped
		p, rp = q.CasePath, r.Path
	}
	if r.Anchored && q.PlainPath != "" {
		// Not cleanPath's: ; parameters and trailing dots are not how a
		// PHP router reads a path, an encoded / stays in its segment
		// (review 2 of #87, S-4).
		p = q.PlainPath
		if !r.CaseSensitive {
			p = strings.ToLower(p)
		}
		return strings.HasSuffix(p, rp) && anchorOK(p[:len(p)-len(rp)])
	}
	var prefix string
	if strings.HasSuffix(p, rp) {
		prefix = p[:len(p)-len(rp)]
	} else if i := strings.Index(p+"/", rp+"/"); i >= 0 {
		prefix = p[:i]
	} else {
		return false
	}
	return !r.Anchored || anchorOK(prefix)
}

// anchorOK says whether what comes before an anchored route is only
// directories (no segment with a dot), the last of them possibly the
// front controller index.php, as without URL rewriting (review 2 of #87,
// N-3: index.php right before the route only).
func anchorOK(prefix string) bool {
	k := strings.LastIndexByte(prefix, '/')
	if k >= 0 && strings.EqualFold(prefix[k+1:], "index.php") {
		prefix = prefix[:k]
	}
	return !strings.Contains(prefix, ".")
}

// NewMatcher compiles the routes of ss. Signatures with a route or written
// for a vulnerability are tried first, then the classes', each group in
// the order given: the hits that name a vulnerability lead.
func NewMatcher(ss []sig.Signature) *Matcher {
	ss = slices.Clone(ss)
	sort.SliceStable(ss, func(a, b int) bool { return specific(ss[a]) && !specific(ss[b]) })
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

// specific: s has a route or is written for a vulnerability.
func specific(s sig.Signature) bool {
	return len(s.Routes) > 0 || len(s.CVEs) > 0 || len(s.Advisories) > 0 || len(s.AppliesTo) > 0
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

// Match tries every signature on q; Normalize's bounds bound its cost.
func (m *Matcher) Match(q Request) (res MatchResult) {
	res = MatchResult{Request: q}
	start := m.now()
	defer func() { res.TimedOut = m.now().Sub(start) > MaxMatchTime }()
	for i, s := range m.sigs {
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
			part, param, ex, segs, ok := matchOne(mt, q)
			if !ok {
				all = false
				break
			}
			if j == 0 {
				hit.Part, hit.Param, hit.Excerpt, hit.Segments = part, param, ex, segs
				hit.Raw = rawOf(q, part, param)
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
		if len(r.Methods) > 0 && !containsStr(r.Methods, q.Method) && !(q.Method == "HEAD" && containsStr(r.Methods, "GET")) {
			continue // a GET route takes HEAD too, as methodOK says
		}
		if r.Path != "" && !pathHolds(r, q) {
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
func matchOne(mt sig.Match, q Request) (part, param, excerpt string, segments []string, ok bool) {
	try := func(whole string) (string, bool) {
		for _, text := range pieces(whole) { // a cut text's start and end apart
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
		}
		return "", false
	}
	switch mt.Part {
	case "path":
		ex, ok := try(q.RawPath)
		return "path", "", ex, nil, ok
	case "query":
		ex, ok := try(q.Query)
		return "query", "", ex, nil, ok
	case "user_agent":
		ex, ok := try(q.UserAgent)
		return "user_agent", "", ex, nil, ok
	case "referer":
		ex, ok := try(q.Referer)
		return "referer", "", ex, nil, ok
	case "param":
		for _, v := range q.Params[strings.ToLower(mt.Param)] {
			if ex, ok := try(v); ok {
				return "param", mt.Param, ex, nil, true
			}
		}
	case "any_param":
		keys := make([]string, 0, len(q.Params))
		for k := range q.Params {
			if q.Sent[k] || q.Sent == nil { // a Request not made by Normalize: every name
				keys = append(keys, k)
			}
		}
		sort.Strings(keys) // the same request names the same parameter every time
		for _, k := range keys {
			for _, v := range q.Params[k] {
				if ex, ok := try(v); ok {
					return "any_param", k, ex, nil, true
				}
			}
		}
		// A name holds what an application may read too: one sent without
		// =, or the whole query string PHP reads (review 1 of #87, N-4).
		for _, k := range keys {
			if ex, ok := try(k); ok {
				return "query", k, ex, nil, true
			}
		}
		// A path segment is a route parameter's value ({id}, :id, <id>)
		// (review 1 of #87, N-5): each segment as sent, decoded apart (a
		// router splits before it decodes: %2F stays in its value; review
		// 2, N-2), and the decoded path's segments.
		// Every segment that holds it, not the first: one the route's
		// words take must not hide one its placeholder takes.
		var first string
		var held []string
		for _, segs := range [][]string{q.Segments, strings.Split(q.RawPath, "/")} {
			for _, sg := range segs {
				if sg == "" || sg == "." || sg == ".." || slices.Contains(held, sg) {
					continue
				}
				if ex, ok := try(sg); ok {
					if held == nil {
						first = ex
					}
					held = append(held, sg)
				}
			}
		}
		if held != nil {
			return "path", "", first, held, true
		}
	}
	return "", "", "", nil, false
}

// rawOf is what the request sent in part, as logged.
func rawOf(q Request, part, param string) string {
	var s string
	switch part {
	case "path":
		s = q.Raw.Path
	case "query":
		s = q.Raw.Query
	case "user_agent":
		s = q.Raw.UserAgent
	case "referer":
		s = q.Raw.Referer
	case "param", "any_param":
		s = strings.Join(q.RawParams[strings.ToLower(param)], "&")
	}
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// excerptAt is up to 64 bytes around the match, for a person to read.
func excerptAt(s string, i, n int) string {
	from, to := max(0, i-16), min(len(s), i+n+16)
	if to-from > 64 {
		to = from + 64
	}
	return strings.ReplaceAll(s[from:to], cutMark, "…") // a person reads where a text was cut
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
