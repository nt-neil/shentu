package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// ReasonFormatUnrecognized: the log's format is not one detect can split
// into fields without guessing. Its lines are not matched; the log counts
// as not covering what it would have shown.
const ReasonFormatUnrecognized hostenv.Reason = "format_unrecognized"

// ErrFormatUnrecognized is returned for such a format, with why.
var ErrFormatUnrecognized = errors.New(string(ReasonFormatUnrecognized))

// AccessRecord is one request of an access log.
type AccessRecord struct {
	Client  string    // the address that connected (behind a proxy, the proxy)
	Time    time.Time // zero when the format has no time detect reads
	Request string    // the request line as logged, unescaped
	Method  string
	Path    string // the target before '?', as sent (not decoded)
	Query   string // after '?'
	Proto   string
	Status  int
	Bytes   int64
	// ReqLength: the request's length as the server logged it (nginx's
	// $request_length, Apache's %I: line, headers and body); 0 when the
	// format does not log it.
	ReqLength int64
	Referer   string
	UserAgent string
	Host      string
	XFF       string // X-Forwarded-For, believed only from trusted proxies (P4)
	User      string
	Vhost     string // the server's own name for itself (Apache %v, nginx $server_name), not the Host header
	Cut       bool   // parsed from a line cut at MaxLine (ParseCut): fields after the cut are missing
	// Suspicious: the line splits only from its end (an unquoted field
	// held so many of the next literal that the split from the start gave
	// up): taken, matched, and to be flagged.
	Suspicious bool
	// Ambiguous: the line splits more than one way into different requests
	// (a field the client writes before the request held a forged line
	// end). Alts are every other distinct split; all are to be matched.
	Ambiguous bool
	Alts      []AccessRecord
}

// Parser splits the lines of one access log format.
type Parser struct {
	segs    []seg
	escape  string // nginx: "default", "json"; apache: "apache"
	hasTime bool
	// Parsed, Unparsed, Suspicious and Ambiguous count the lines given (not
	// safe for concurrent use: one parser per log read). Unparsed,
	// Suspicious and Ambiguous lines are signals of their own.
	Parsed, Unparsed, Suspicious, Ambiguous int
}

type seg struct {
	lit    string // literal text, or
	field  string // the field it fills (client, time_local, request...); "" for one detect does not use
	var_   bool
	quoted bool // between two quotes: the server escapes a quote inside it
}

// ParserFor is the parser of a log source's format.
func ParserFor(s hostenv.LogSource) (*Parser, error) {
	if s.Kind != "access" {
		return nil, fmt.Errorf("%w: a %s log, not an access log", ErrFormatUnrecognized, s.Kind)
	}
	if s.Spec == "" {
		return nil, fmt.Errorf("%w: format %q is defined nowhere read", ErrFormatUnrecognized, s.Format)
	}
	switch s.Server {
	case "nginx":
		return NginxParser(s.Spec, s.Escape)
	case "apache":
		return apacheParser(s.Spec, s.HostnameLookups, s.IdentityCheck)
	}
	return nil, fmt.Errorf("%w: %s access logs are not read yet", ErrFormatUnrecognized, s.Server)
}

var ngxVar = regexp.MustCompile(`\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))`)

// nginx variables detect reads, by what they fill.
var ngxFields = map[string]string{
	"remote_addr": "client", "remote_user": "user",
	"time_local": "time_local", "time_iso8601": "time_iso", "msec": "msec",
	"request": "request", "request_method": "method", "request_uri": "uri", "uri": "path", "args": "query", "query_string": "query",
	"server_protocol": "proto", "status": "status", "body_bytes_sent": "bytes", "bytes_sent": "bytes", "request_length": "reqlen",
	"http_referer": "referer", "http_user_agent": "ua", "http_x_forwarded_for": "xff", "host": "host", "http_host": "host",
	"server_name": "vhost", "server_port": "port",
}

// NginxParser compiles a log_format's strings (as hostenv gives them,
// joined) with its escape= (empty is nginx's default).
func NginxParser(spec, escape string) (*Parser, error) {
	if escape == "" {
		escape = "default"
	}
	switch escape {
	case "default", "json":
	case "none": // a request or a User-Agent may hold the delimiters, and write fields of its own
		return nil, fmt.Errorf("%w: escape=none, the fields can be forged from the request", ErrFormatUnrecognized)
	default:
		return nil, fmt.Errorf("%w: escape=%s", ErrFormatUnrecognized, escape)
	}
	p := &Parser{escape: escape}
	last := 0
	for _, m := range ngxVar.FindAllStringSubmatchIndex(spec, -1) {
		if m[0] > last {
			p.segs = append(p.segs, seg{lit: spec[last:m[0]]})
		}
		var name string
		if m[2] >= 0 { // ${name}
			name = spec[m[2]:m[3]]
		} else {
			name = spec[m[4]:m[5]]
		}
		p.segs = append(p.segs, seg{field: ngxFields[name], var_: true})
		last = m[1]
	}
	if last < len(spec) {
		p.segs = append(p.segs, seg{lit: spec[last:]})
	}
	return p, p.check()
}

var apacheDirective = regexp.MustCompile(`%(?:!?[0-9]{3}(?:,[0-9]{3})*)?[<>]?(?:\{([^}]*)\})?([a-zA-Z%])`)

// ApacheParser compiles a LogFormat string, HostnameLookups off (Apache's
// default).
func ApacheParser(spec string) (*Parser, error) { return apacheParser(spec, false, false) }

// apacheParser: with HostnameLookups On or Double, %h is the client's PTR
// name, which whoever controls the address's reverse zone writes (even as
// "203.0.113.5"): it is not the client, only %a is.
//
// With IdentityCheck On, %l is what the client's identd answers: a field the
// client writes, like %u.
func apacheParser(spec string, lookups, identity bool) (*Parser, error) {
	p := &Parser{escape: "apache"}
	last := 0
	lit := func(s string) {
		if s == "" {
			return
		}
		if n := len(p.segs); n > 0 && !p.segs[n-1].var_ {
			p.segs[n-1].lit += s
			return
		}
		p.segs = append(p.segs, seg{lit: s})
	}
	for _, m := range apacheDirective.FindAllStringSubmatchIndex(spec, -1) {
		lit(spec[last:m[0]])
		last = m[1]
		arg := ""
		if m[2] >= 0 {
			arg = strings.ToLower(spec[m[2]:m[3]])
		}
		var f string
		switch d := spec[m[4]:m[5]]; d {
		case "%":
			lit("%")
			continue
		case "a":
			if arg == "" || arg == "c" {
				f = "client"
			}
		case "h":
			if !lookups {
				f = "client"
			}
		case "p":
			f = "port"
		case "l": // identd's answer: "-" unless IdentityCheck is On (then the client's identd writes it)
			if !identity {
				f = "ident"
			}
		case "u":
			f = "user"
		case "t":
			if arg != "" {
				return nil, fmt.Errorf("%w: %%{%s}t, a time format detect does not read", ErrFormatUnrecognized, arg)
			}
			f = "time_apache"
		case "r":
			f = "request"
		case "s":
			f = "status"
		case "b", "B", "O":
			f = "bytes"
		case "I": // mod_logio: bytes received, the request's line and headers included
			f = "reqlen"
		case "m":
			f = "method"
		case "U":
			f = "path"
		case "q":
			f = "query_apache" // "?a=b", or empty
		case "H":
			f = "proto"
		case "v":
			f = "vhost" // the configured ServerName
		case "V":
			f = "host" // UseCanonicalName Off: the Host header
		case "i":
			switch arg {
			case "referer":
				f = "referer"
			case "user-agent":
				f = "ua"
			case "x-forwarded-for":
				f = "xff"
			case "host":
				f = "host"
			}
		}
		if n := len(p.segs); f == "query_apache" && n > 0 && p.segs[n-1].var_ && p.segs[n-1].field == "path" {
			p.segs[n-1].field = "uri" // %U%q: the path, then "?query" or nothing; split at '?'
			continue
		}
		p.segs = append(p.segs, seg{field: f, var_: true})
	}
	lit(spec[last:])
	return p, p.check()
}

// clientWritten are the fields whose text the request chooses; "" is one
// detect does not read (a header, an argument, a cookie), taken as such.
var clientWritten = map[string]bool{"": true, "user": true, "request": true, "uri": true, "path": true, "query": true,
	"query_apache": true, "referer": true, "ua": true, "xff": true, "host": true, "method": true, "proto": true}

// safeBeforeClient are the fields the client may follow: none of them is
// written by the request, so none can hold a forged address.
var safeBeforeClient = map[string]bool{"ident": true, "time_local": true, "time_iso": true, "time_apache": true, "msec": true, "status": true, "bytes": true, "reqlen": true, "vhost": true, "port": true}

// check: every field is delimited by literal text (two side by side cannot
// be split without guessing), nothing the request writes comes before the
// client address (a header holding "x 203.0.113.5 -" would make the
// address what it likes), and the fields matching needs are there.
func (p *Parser) check() error {
	have := map[string]bool{}
	client := -1
	for i, s := range p.segs {
		if !s.var_ {
			continue
		}
		if i > 0 && p.segs[i-1].var_ {
			return fmt.Errorf("%w: two fields with nothing between them", ErrFormatUnrecognized)
		}
		if s.field == "client" && client < 0 {
			client = i
			if n := i + 1; n < len(p.segs) && !p.segs[n].var_ && p.segs[n].lit != "" && strings.ContainsAny(p.segs[n].lit[:1], ":.%]0123456789abcdefABCDEF") {
				return fmt.Errorf("%w: the client address is followed by %q, which an IPv6 address may hold", ErrFormatUnrecognized, p.segs[i+1].lit[:1])
			}
		}
		if client < 0 && !safeBeforeClient[s.field] {
			name := s.field
			if name == "" {
				name = "a field detect does not read"
			}
			return fmt.Errorf("%w: %s comes before the client address and could forge it", ErrFormatUnrecognized, name)
		}
		p.segs[i].quoted = i > 0 && i+1 < len(p.segs) && strings.HasSuffix(p.segs[i-1].lit, `"`) && strings.HasPrefix(p.segs[i+1].lit, `"`)
		have[s.field] = true
	}
	// Two fields the client writes, neither between quotes, can trade text:
	// a forged line end in the first lands its own request (N-3).
	free := 0
	for _, sg := range p.segs {
		if sg.var_ && !sg.quoted && clientWritten[sg.field] {
			free++
		}
	}
	if free > 1 {
		return fmt.Errorf("%w: %d fields the client writes are not between quotes: a line could be split two ways", ErrFormatUnrecognized, free)
	}
	p.hasTime = have["time_local"] || have["time_iso"] || have["time_apache"] || have["msec"]
	switch {
	case !have["client"]:
		return fmt.Errorf("%w: no client address", ErrFormatUnrecognized)
	case !have["status"]:
		return fmt.Errorf("%w: no status", ErrFormatUnrecognized)
	case !have["request"] && !have["uri"] && !have["path"]:
		return fmt.Errorf("%w: no request", ErrFormatUnrecognized)
	}
	return nil
}

// maxSplits bounds the backtracking of one line: a field may end at any of
// the next literal's occurrences, tried leftmost first.
const maxSplits = 64

// Parse splits one line. false: the line is not in the format (another
// format, an injected line); counted in Unparsed, which the caller is to
// report: an attacker making his own lines unparseable is itself a sign.
func (p *Parser) Parse(line []byte) (AccessRecord, bool) { return p.parse(line, false) }

// ParseCut splits a line cut at MaxLine (its end lost): enough when the
// client, the request and the time (if the format has one) came before
// the cut. The record says Cut.
func (p *Parser) ParseCut(line []byte) (AccessRecord, bool) { return p.parse(line, true) }

func (p *Parser) parse(line []byte, cut bool) (AccessRecord, bool) {
	s := string(line)
	if !cut {
		s = strings.TrimRight(s, " \r")
	}
	var r AccessRecord
	steps := 0
	left := p.match(s, 0, 0, &r, cut, &steps)
	var alts []AccessRecord
	if !left && !cut { // the other splits, only when the split from the start failed; a cut line has no end
		alts = p.splits(s)
	}
	fix := func(x *AccessRecord) {
		if x.Request != "" && x.Method == "" {
			x.splitRequest()
		}
	}
	fix(&r)
	if !left {
		if len(alts) == 0 {
			p.Unparsed++
			return AccessRecord{}, false
		}
		r, r.Suspicious = alts[0], true
		p.Suspicious++
		alts = alts[1:]
	}
	for _, a := range alts {
		if !sameRequest(r, a) {
			r.Alts = append(r.Alts, a)
		}
	}
	if len(r.Alts) > 0 {
		r.Ambiguous = true
		p.Ambiguous++
	}
	p.Parsed++
	return r, true
}

// sameRequest: two splits of a line agree on who asked for what.
func sameRequest(a, b AccessRecord) bool {
	return a.Client == b.Client && a.Request == b.Request && a.Method == b.Method && a.Path == b.Path &&
		a.Query == b.Query && a.Status == b.Status && a.Time.Equal(b.Time)
}

// splits are the other ways s splits, one pass each, no backtracking: for
// each field m, the fields before it split from the start (each at the
// first occurrence of the literal after it), the fields after it from the
// end (each at the last occurrence of the literal before it), and m takes
// what lies between. Whatever a field the client writes holds, the split
// with it in the middle is the line as the server wrote it.
func (p *Parser) splits(s string) []AccessRecord {
	var out []AccessRecord
	for m, sg := range p.segs {
		if !sg.var_ {
			continue
		}
		var r AccessRecord
		i, ok := p.fromStart(s, m, &r)
		if !ok {
			continue
		}
		j, ok := p.fromEnd(s, m, &r)
		if !ok || i > j || !p.fill(&r, sg, s[i:j]) {
			continue
		}
		if r.Request != "" && r.Method == "" {
			r.splitRequest()
		}
		dup := false
		for _, o := range out {
			if sameRequest(o, r) {
				dup = true
			}
		}
		if !dup {
			out = append(out, r)
		}
	}
	return out
}

// fromStart fills segments 0..m-1 from the start of s; it returns where m begins.
func (p *Parser) fromStart(s string, m int, r *AccessRecord) (int, bool) {
	i := 0
	for k := 0; k < m; k++ {
		sg := p.segs[k]
		if !sg.var_ {
			if !strings.HasPrefix(s[i:], sg.lit) {
				return 0, false
			}
			i += len(sg.lit)
			continue
		}
		end := -1
		if e := strings.IndexByte(s[i:], ']'); sg.field == "time_apache" && strings.HasPrefix(s[i:], "[") && e > 0 {
			end = i + e + 1
		} else if j := p.index(s[i:], p.segs[k+1].lit); j >= 0 {
			end = i + j
		}
		if end < 0 || !p.fill(r, sg, s[i:end]) {
			return 0, false
		}
		i = end
	}
	return i, true
}

// fromEnd fills segments m+1.. from the end of s; it returns where m ends.
func (p *Parser) fromEnd(s string, m int, r *AccessRecord) (int, bool) {
	j := len(s)
	for k := len(p.segs) - 1; k > m; k-- {
		sg := p.segs[k]
		if !sg.var_ {
			if !strings.HasSuffix(s[:j], sg.lit) {
				return 0, false
			}
			j -= len(sg.lit)
			continue
		}
		var start int
		if sg.field == "time_apache" && strings.HasSuffix(s[:j], "]") {
			start = strings.LastIndexByte(s[:j], '[')
		} else if x := p.lastIndex(s[:j], p.segs[k-1].lit); x >= 0 {
			start = x + len(p.segs[k-1].lit)
		} else {
			return 0, false
		}
		if start < 0 || !p.fill(r, sg, s[start:j]) {
			return 0, false
		}
		j = start
	}
	return j, true
}

// lastIndex is the last place lit starts in s outside an escape.
func (p *Parser) lastIndex(s, lit string) int {
	if p.escape == "none" {
		return strings.LastIndex(s, lit)
	}
	for end := len(s); ; {
		i := strings.LastIndex(s[:end], lit)
		if i < 0 {
			return -1
		}
		if !escapedAt(s, i) {
			return i
		}
		end = i + len(lit) - 1
		if end < 0 {
			return -1
		}
	}
}

// escapedAt: s[i] follows an odd run of backslashes, so it is part of an
// escape. Only the escapes the servers write matter here: a quote after \
// (Apache, JSON); nginx's default escape has no backslash before a quote.
func escapedAt(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// trimEscape drops an escape the cut left unfinished at the end of v
// (\xF, \u00, a lone backslash), which would make the whole value fail.
func (p *Parser) trimEscape(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			continue
		}
		need := 2 // \" \\ \n
		if i+1 < len(v) {
			switch v[i+1] {
			case 'x':
				need = 4
			case 'u':
				if p.escape == "json" {
					need = 6
				}
			}
		}
		if i+need > len(v) {
			return v[:i]
		}
		i += need - 1
	}
	return v
}

// match matches segments k.. against s from i, filling r.
func (p *Parser) match(s string, i, k int, r *AccessRecord, cut bool, steps *int) bool {
	if k == len(p.segs) {
		return i == len(s)
	}
	sg := p.segs[k]
	if !sg.var_ {
		switch {
		case strings.HasPrefix(s[i:], sg.lit):
			return p.match(s, i+len(sg.lit), k+1, r, cut, steps)
		case cut && strings.HasPrefix(sg.lit, s[i:]): // the cut fell inside this literal
			return p.enough(r)
		}
		return false
	}
	try := func(v string, next int) bool {
		r2 := *r
		if next < 0 {
			v = p.trimEscape(v)
		}
		if !p.fill(&r2, sg, v) {
			if next < 0 && p.enough(&r2) { // a cut value (" 2 for a status) is no reason to lose the line
				r2.Cut = true
				*r = r2
				return true
			}
			return false
		}
		if next < 0 { // the cut: nothing after this value
			r2.Cut = true
			if !p.enough(&r2) {
				return false
			}
		} else if !p.match(s, next, k+1, &r2, cut, steps) {
			return false
		}
		*r = r2
		return true
	}
	if end := strings.IndexByte(s[i:], ']'); sg.field == "time_apache" && strings.HasPrefix(s[i:], "[") && end > 0 {
		return try(s[i:i+end+1], i+end+1) // %t is "[02/Jan/2006:15:04:05 -0700]": a space inside
	}
	if k+1 == len(p.segs) {
		if cut {
			return try(s[i:], -1)
		}
		return try(s[i:], len(s))
	}
	next := p.segs[k+1].lit
	for from := i; ; {
		if *steps++; *steps > maxSplits {
			return false
		}
		j := p.index(s[from:], next)
		if j < 0 {
			if cut {
				return try(s[i:], -1)
			}
			return false
		}
		if try(s[i:from+j], from+j) {
			return true
		}
		if sg.quoted { // a quoted value ends at the first unescaped quote: no other split
			return false
		}
		from += j + 1
	}
}

// fill unescapes v into sg's field of r.
func (p *Parser) fill(r *AccessRecord, sg seg, v string) bool {
	if sg.field == "" {
		return true
	}
	u, ok := p.unescape(v)
	return ok && r.set(sg.field, u)
}

// enough: a cut record still names who asked for what, and when.
func (p *Parser) enough(r *AccessRecord) bool {
	return r.Client != "" && (r.Request != "" || r.Path != "") && (!p.hasTime || !r.Time.IsZero())
}

// index is where lit next starts in s, outside an escape: Apache writes a
// quote inside a value as \", JSON as \", so the quote ending the value is
// the first one not escaped.
func (p *Parser) index(s, lit string) int {
	if p.escape == "none" {
		return strings.Index(s, lit)
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], lit) {
			return i
		}
	}
	return -1
}

// set fills one field; false: a value the field cannot have.
func (r *AccessRecord) set(f, v string) bool {
	dash := v == "-"
	switch f {
	case "client":
		if v == "unix:" { // nginx behind a unix socket: no address
			return true
		}
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" { // a zone is any text after %
			return false
		}
		r.Client = a.String()
	case "user":
		if !dash {
			r.User = v
		}
	case "time_local", "time_apache":
		t, err := time.Parse("02/Jan/2006:15:04:05 -0700", strings.Trim(v, "[]"))
		if err != nil {
			return false
		}
		r.Time = t.UTC()
	case "time_iso":
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return false
		}
		r.Time = t.UTC()
	case "msec":
		sec, frac, _ := strings.Cut(v, ".")
		s, err := strconv.ParseInt(sec, 10, 64)
		if err != nil {
			return false
		}
		ms, _ := strconv.Atoi((frac + "000")[:3])
		r.Time = time.Unix(s, int64(ms)*int64(time.Millisecond)).UTC()
	case "request":
		if !dash {
			r.Request = v
		}
	case "method":
		r.Method = v
	case "uri":
		r.Path, r.Query, _ = strings.Cut(v, "?")
	case "path":
		r.Path = v
	case "query":
		if !dash {
			r.Query = v
		}
	case "query_apache":
		r.Query = strings.TrimPrefix(v, "?")
	case "proto":
		r.Proto = v
	case "status":
		n, err := strconv.Atoi(v)
		if err != nil || n < 100 || n > 999 {
			return false
		}
		r.Status = n
	case "bytes":
		if !dash {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return false
			}
			r.Bytes = n
		}
	case "reqlen":
		if !dash {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return false
			}
			r.ReqLength = n
		}
	case "referer":
		if !dash {
			r.Referer = v
		}
	case "ua":
		if !dash {
			r.UserAgent = v
		}
	case "xff":
		if !dash && validXFF(v) { // addresses only: anything else is a client's text, not a proxy's
			r.XFF = v
		}
	case "host":
		r.Host = v
	case "vhost":
		r.Vhost = v
	}
	return true
}

// splitRequest reads "GET /a?b HTTP/1.1"; a line that is not one (junk a
// scanner sent) keeps only Request.
func (r *AccessRecord) splitRequest() {
	f := strings.Split(r.Request, " ")
	if len(f) < 2 || len(f) > 3 {
		return
	}
	r.Method = f[0]
	r.Path, r.Query, _ = strings.Cut(f[1], "?")
	if len(f) == 3 {
		r.Proto = f[2]
	}
}

// unescape undoes the server's escaping of a value: nginx's \xHH (default),
// JSON's (escape=json), Apache's \xhh, \" and \\. false: an escape the
// server does not write, so not a line it wrote.
func (p *Parser) unescape(v string) (string, bool) {
	if !strings.Contains(v, `\`) {
		return v, true
	}
	switch p.escape {
	case "none":
		return v, true
	case "json":
		var s string
		if err := json.Unmarshal([]byte(`"`+v+`"`), &s); err != nil {
			return "", false
		}
		return s, true
	}
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			sb.WriteByte(v[i])
			continue
		}
		if i+3 < len(v) && v[i+1] == 'x' {
			if b, err := strconv.ParseUint(v[i+2:i+4], 16, 8); err == nil {
				sb.WriteByte(byte(b))
				i += 3
				continue
			}
		}
		if p.escape == "apache" && i+1 < len(v) {
			switch v[i+1] {
			case '"', '\\':
				sb.WriteByte(v[i+1])
				i++
				continue
			case 'n':
				sb.WriteByte('\n')
				i++
				continue
			case 't':
				sb.WriteByte('\t')
				i++
				continue
			}
		}
		return "", false
	}
	return sb.String(), true
}
