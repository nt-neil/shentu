package detect

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/rules/engine"
)

// Levels past the judge's (plan 0743f0, detection 3): L3, success likely,
// is LevelPayload with a response or an error log that says so (l3.go);
// LevelUnknown is a cut request that may hide one (Judgment.Unknown).
const (
	LevelSuccess = "L3"
	LevelUnknown = "unknown"
)

// Severities of an attempt, lowest first.
var severities = []string{"info", "low", "medium", "high", "critical"}

// MaxSample bounds Attempt.Sample, in bytes.
const MaxSample = 256

// Origin is where a record came from, as the reader knows it.
type Origin struct {
	// Verified: the log is trusted (Line.Verified). Reason says why not,
	// in Chinese, for the alert.
	Verified bool
	Reason   string
	// Custom: the log's format is one written out in place (not a known
	// one such as combined): only then may its client address be X-
	// Forwarded-For, never believed.
	Custom bool
}

// Attempt is one request trying one of this host's vulnerabilities (or,
// LevelUnknown, cut where it may hide one).
type Attempt struct {
	Entry    string    `json:"entry"` // the surface entry's ID; for LevelUnknown a sink the cut may hide a payload for, "" when none is known
	Level    string    `json:"level"` // L1, L2, L3, unknown
	CVE      string    `json:"cve,omitempty"`
	KEV      bool      `json:"kev,omitempty"`
	Severity string    `json:"severity"` // without the campaign step (attacks.go adds it)
	IP       string    `json:"ip"`
	Time     time.Time `json:"time"`
	// Verified: the IP can be believed (a trusted log, remote_addr); Reason
	// says why not, in Chinese.
	Verified bool   `json:"verified"`
	Reason   string `json:"reason,omitempty"`
	// ForwardedFor: X-Forwarded-For as logged by a format written out in
	// place, a note only (NoteXFF), never the source.
	ForwardedFor string `json:"forwarded_for,omitempty"`
	// ReqLen: the request's length, what a response may echo back, taken
	// off its size for L3; ReqKnown: it is known: logged ($request_length,
	// %I), or a GET or HEAD (no body: its path and query). Otherwise the
	// size is no evidence.
	ReqLen   int  `json:"req_len,omitempty"`
	ReqKnown bool `json:"req_known,omitempty"`
	// LogVerified: the access log itself is trusted (Origin.Verified),
	// whatever the IP: its status and size may back L3.
	LogVerified bool `json:"log_verified,omitempty"`
	// Success: why the attempt is L3, in Chinese (l3.go's Upgrade);
	// SizeEvidence, ErrorEvidence: which kinds back it. The error log
	// counts half (a request can write a line of its own into it): L3 is
	// critical only with both and a KEV entry or a campaign (SeverityWith).
	Success       string `json:"success,omitempty"`
	SizeEvidence  bool   `json:"size_evidence,omitempty"`
	ErrorEvidence bool   `json:"error_evidence,omitempty"`
	// Severe: the entry is KEV or rated critical (CVSS 9 or more): one step
	// up, kept for the campaign step.
	Severe     bool     `json:"severe,omitempty"`
	Signatures []string `json:"signatures,omitempty"`
	Sample     string   `json:"sample"` // the request line, secrets masked, at most MaxSample bytes
	Status     int      `json:"status,omitempty"`
	Bytes      int64    `json:"bytes,omitempty"`
	// Route is the code sink's route the request reached; File and Line the
	// sink's (for L3's error log match).
	Route *engine.RouteRef `json:"route,omitempty"`
	File  string           `json:"file,omitempty"`
	Line  int              `json:"line,omitempty"`
	Path  string           `json:"path,omitempty"` // the routed path, for a package's baseline
	// What the record and its matching say.
	Cut, Suspicious, Ambiguous, Encoded, TimedOut, Unknown bool
	HiddenClasses                                          []string `json:"hidden_classes,omitempty"`
	HiddenSinks                                            []string `json:"hidden_sinks,omitempty"`
	HiddenSinksMore                                        int      `json:"hidden_sinks_more,omitempty"`
}

// NoteXFF is said with an X-Forwarded-For note.
const NoteXFF = "代理標頭 X-Forwarded-For（僅供參考，可以偽造，未用來判斷來源或封鎖）"

// Attempts are the attempts one matched and judged request makes: one per
// candidate, and, when the judgment is Unknown, one per sink the cut may
// hide a payload for (one with no entry when none is known).
func (j *Judge) Attempts(rec AccessRecord, o Origin, m MatchResult, g Judgment) []Attempt {
	base := Attempt{Time: rec.Time, Sample: Sample(rec), Status: rec.Status, Bytes: rec.Bytes, Path: m.Request.Path,
		Cut: g.Cut || rec.Cut, Suspicious: rec.Suspicious, Ambiguous: rec.Ambiguous, Encoded: m.Request.Encoded, TimedOut: g.TimedOut}
	base.IP, base.Verified, base.Reason = clientOf(rec, o)
	base.IP = cutUTF8(Printable(base.IP), 64)
	base.LogVerified = o.Verified
	base.ForwardedFor = forwardedFor(rec, o)
	switch m := strings.ToUpper(rec.Method); {
	case rec.ReqLength > 0:
		base.ReqLen, base.ReqKnown = int(rec.ReqLength), true
	case m == "GET" || m == "HEAD":
		base.ReqLen, base.ReqKnown = len(rec.Path)+len(rec.Query), true
	}
	var out []Attempt
	for _, c := range g.Candidates {
		a := base
		a.Entry, a.Level, a.Route = c.Entry, c.Level, c.Route
		for _, h := range c.Hits {
			a.Signatures = append(a.Signatures, h.Signature)
		}
		if i, ok := j.byID[c.Entry]; ok {
			e := j.surface.Entries[i]
			a.CVE, a.KEV, a.File, a.Line = e.CVE, e.KEV, e.Path, e.Line
			if e.KEVCVE != "" {
				a.CVE = e.KEVCVE
			}
			a.Severe = e.KEV || strings.EqualFold(e.Severity, "critical")
		}
		a.Severity = a.SeverityWith(false)
		out = append(out, a)
	}
	if g.Unknown {
		u := base
		u.Level, u.Unknown = LevelUnknown, true
		u.HiddenClasses, u.HiddenSinks, u.HiddenSinksMore = g.HiddenClasses, g.HiddenSinks, g.HiddenSinksMore
		u.Severity = SeverityOf(LevelUnknown, false, false, u.Verified)
		if len(g.HiddenSinks) == 0 {
			out = append(out, u)
		}
		for _, s := range g.HiddenSinks {
			x := u
			x.Entry = s
			out = append(out, x)
		}
	}
	return out
}

// clientOf is the request's client address: remote_addr (the record's
// Client), believed as its log is. X-Forwarded-For is never the source,
// only a note (forwardedFor).
func clientOf(rec AccessRecord, o Origin) (ip string, verified bool, reason string) {
	ip, verified, reason = rec.Client, o.Verified, o.Reason
	if !o.Verified && reason == "" {
		reason = "記錄檔未通過信任檢查（擁有者或權限不符），內容可能被竄改"
	}
	return ip, verified, reason
}

// forwardedFor is X-Forwarded-For as a note (a format written out in
// place logs it): never the source, at most MaxForwarded bytes; one not
// a list of addresses is said invalid, its text not shown.
func forwardedFor(rec AccessRecord, o Origin) string {
	x := strings.TrimSpace(rec.XFF)
	if !o.Custom || x == "" || x == "-" {
		return ""
	}
	if !validXFF(x) {
		return "（XFF 無效：不是 IP 位址清單，內容不顯示）"
	}
	return cutUTF8(x, MaxForwarded)
}

// validXFF: x is a comma-separated list of IP addresses, nothing else.
func validXFF(x string) bool {
	for _, p := range strings.Split(x, ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(p)); err != nil || a.Zone() != "" { // a zone is any text after %
			return false
		}
	}
	return true
}

// Printable is s with every character that could start a line or change
// how a line reads (C0 and C1 controls, DEL, U+2028/2029, format
// characters such as U+202E) written as \xHH or \u{HHHH}: what an alert
// shows is one line per field, as written by shentu.
func Printable(s string) string {
	if !strings.ContainsFunc(s, unprintable) && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == utf8.RuneError && !strings.HasPrefix(s[i:], "\uFFFD"):
			fmt.Fprintf(&b, `\x%02X`, s[i])
		case r < 0x80 && unprintable(r):
			fmt.Fprintf(&b, `\x%02X`, r)
		case unprintable(r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unprintable(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

// MaxForwarded bounds Attempt.ForwardedFor.
const MaxForwarded = 128

// cutUTF8 is s cut to n bytes on a character's boundary.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// SeverityWith is a's severity, a campaign or not: SeverityOf, and an L3
// at most high unless both kinds of evidence back it and its entry is KEV
// or it is a campaign (the error log counts half: a request can write a
// line of its own into it).
func (a Attempt) SeverityWith(campaign bool) string {
	s := SeverityOf(a.Level, a.Severe, campaign, a.Verified)
	full := a.SizeEvidence && a.ErrorEvidence && (a.KEV || campaign)
	if a.Level == LevelSuccess && !full && severityIndex(s) > severityIndex("high") {
		s = "high"
	}
	return s
}

// SeverityOf is an attempt's severity: L1 info, L2 high, L3 critical (at most
// high on one kind of evidence: SeverityWith), an unknown one low; a step up when the vulnerability is KEV or critical
// (severe), another for a campaign (one IP trying three or more in 24
// hours); at most medium when the IP cannot be believed.
func SeverityOf(level string, severe, campaign, verified bool) string {
	i := map[string]int{LevelRoute: 0, LevelPayload: 3, LevelSuccess: 4, LevelUnknown: 1}[level]
	if severe {
		i++
	}
	if campaign {
		i++
	}
	i = min(i, len(severities)-1)
	if !verified {
		i = min(i, 2)
	}
	return severities[i]
}

// sensitive are words that, inside a parameter's name, mark its value
// as one a sample never shows (access_token, user_email, PHPSESSID);
// sensitiveWords are short ones that do only as a whole word of the name,
// split at _ - [ ] . and spaces (pw, key, pin: not keyword, shipping).
var (
	sensitive = []string{"token", "password", "passwd", "passphrase", "secret", "email", "session", "sessid", "cookie",
		"authorization", "apikey", "api_key", "credential", "signature", "private_key"}
	sensitiveWords = []string{"pwd", "pass", "pw", "auth", "key", "sid", "code", "sig", "otp", "pin", "card", "cc", "cvv", "ssn", "jwt"}
)

// sensitiveName: a parameter name, decoded as a server reads it (%XX
// twice, + as a space, PHP's a[b] and a.b), holds a sensitive word; one
// still holding a % after decoding is taken as sensitive (fail closed).
func sensitiveName(k string) bool {
	n, _, _ := normalizeText(k, true)
	if strings.Contains(n, "%") {
		return true
	}
	for _, name := range paramNames(n) {
		for _, s := range sensitive {
			if strings.Contains(name, s) {
				return true
			}
		}
		for _, w := range strings.FieldsFunc(name, func(r rune) bool { return strings.ContainsRune("_-[]. ", r) }) {
			if slices.Contains(sensitiveWords, w) {
				return true
			}
		}
	}
	return false
}

// Sample is the record's request line for a person to read: parameters
// with a sensitive name masked (in the query, and a path segment's
// ;name=value), then hostenv.MaskSecrets, then made Printable, then cut
// to MaxSample bytes on a character's boundary.
func Sample(rec AccessRecord) string {
	p := rec.Path
	if strings.Contains(p, ";") {
		segs := strings.Split(p, "/")
		for i, sg := range segs {
			parts := strings.Split(sg, ";")
			for j := 1; j < len(parts); j++ {
				if k, _, ok := strings.Cut(parts[j], "="); ok && sensitiveName(k) {
					parts[j] = k + "=[REDACTED]"
				}
			}
			segs[i] = strings.Join(parts, ";")
		}
		p = strings.Join(segs, "/")
	}
	q := rec.Query
	if q != "" {
		kvs := strings.Split(q, "&")
		for i, kv := range kvs {
			// A server splitting on ; too reads more names in it; one
			// splitting on & alone reads the value to the next &. Any
			// sensitive name in the piece masks from its first = to its end.
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				continue
			}
			hide := sensitiveName(kv[:eq])
			for _, sub := range strings.Split(kv, ";") {
				if k, _, ok := strings.Cut(sub, "="); ok && sensitiveName(k) {
					hide = true
				}
			}
			if hide {
				kvs[i] = kv[:eq] + "=[REDACTED]"
			}
		}
		q = "?" + strings.Join(kvs, "&")
	}
	s := Printable(hostenv.MaskSecrets(strings.TrimSpace(rec.Method + " " + p + q)))
	if len(s) <= MaxSample {
		return s
	}
	// Cut, and not inside what may be an address: half of one would pass
	// the report's masking (maskIPs) unmasked.
	return strings.TrimRight(cutUTF8(s, MaxSample), "0123456789abcdefABCDEF:.")
}
