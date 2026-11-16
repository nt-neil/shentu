package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	Client    string    // the address that connected (behind a proxy, the proxy)
	Time      time.Time // zero when the format has no time detect reads
	Request   string    // the request line as logged, unescaped
	Method    string
	Path      string // the target before '?', as sent (not decoded)
	Query     string // after '?'
	Proto     string
	Status    int
	Bytes     int64
	Referer   string
	UserAgent string
	Host      string
	XFF       string // X-Forwarded-For, believed only from trusted proxies (P4)
	User      string
}

// Parser splits the lines of one access log format.
type Parser struct {
	segs   []seg
	escape string // nginx: "default", "json", "none"; apache: "apache"
}

type seg struct {
	lit   string // literal text, or
	field string // the field it fills (client, time_local, request...); "" for one detect does not use
	var_  bool
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
		return ApacheParser(s.Spec)
	}
	return nil, fmt.Errorf("%w: %s access logs are not read yet", ErrFormatUnrecognized, s.Server)
}

var ngxVar = regexp.MustCompile(`\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))`)

// nginx variables detect reads, by what they fill.
var ngxFields = map[string]string{
	"remote_addr": "client", "remote_user": "user",
	"time_local": "time_local", "time_iso8601": "time_iso", "msec": "msec",
	"request": "request", "request_method": "method", "request_uri": "uri", "uri": "path", "args": "query", "query_string": "query",
	"server_protocol": "proto", "status": "status", "body_bytes_sent": "bytes", "bytes_sent": "bytes",
	"http_referer": "referer", "http_user_agent": "ua", "http_x_forwarded_for": "xff", "host": "host", "http_host": "host",
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

// ApacheParser compiles a LogFormat string.
func ApacheParser(spec string) (*Parser, error) {
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
		case "h", "a":
			if arg == "" || arg == "c" {
				f = "client"
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
		case "m":
			f = "method"
		case "U":
			f = "path"
		case "q":
			f = "query_apache" // "?a=b", or empty
		case "H":
			f = "proto"
		case "v", "V":
			f = "host"
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

// check: every field is delimited by literal text (two side by side cannot
// be split without guessing), and the fields matching needs are there.
func (p *Parser) check() error {
	have := map[string]bool{}
	for i, s := range p.segs {
		if s.var_ && i > 0 && p.segs[i-1].var_ {
			return fmt.Errorf("%w: two fields with nothing between them", ErrFormatUnrecognized)
		}
		if s.var_ {
			have[s.field] = true
		}
	}
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

// Parse splits one line. false: the line is not in the format (another
// format, a cut line, an injected one); the caller counts it.
func (p *Parser) Parse(line []byte) (AccessRecord, bool) {
	if !utf8.Valid(line) && p.escape == "json" {
		return AccessRecord{}, false
	}
	s := strings.TrimRight(string(line), " \r")
	var r AccessRecord
	i := 0
	for k, sg := range p.segs {
		if !sg.var_ {
			if !strings.HasPrefix(s[i:], sg.lit) {
				return r, false
			}
			i += len(sg.lit)
			continue
		}
		var v string
		if end := strings.IndexByte(s[i:], ']'); sg.field == "time_apache" && strings.HasPrefix(s[i:], "[") && end > 0 {
			v, i = s[i:i+end+1], i+end+1 // %t is "[02/Jan/2006:15:04:05 -0700]": a space inside
			if u, ok := p.unescape(v); !ok || !r.set(sg.field, u) {
				return r, false
			}
			continue
		}
		if k+1 == len(p.segs) {
			v, i = s[i:], len(s)
		} else {
			j := p.index(s[i:], p.segs[k+1].lit)
			if j < 0 {
				return r, false
			}
			v, i = s[i:i+j], i+j
		}
		if sg.field == "" {
			continue
		}
		u, ok := p.unescape(v)
		if !ok || !r.set(sg.field, u) {
			return r, false
		}
	}
	if i != len(s) {
		return r, false
	}
	if r.Request != "" && r.Method == "" {
		r.splitRequest()
	}
	return r, true
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
		r.Client = v
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
	case "referer":
		if !dash {
			r.Referer = v
		}
	case "ua":
		if !dash {
			r.UserAgent = v
		}
	case "xff":
		if !dash {
			r.XFF = v
		}
	case "host":
		r.Host = v
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
