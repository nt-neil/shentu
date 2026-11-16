package detect

import (
	"strings"
	"time"
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

// ReasonXFF is said of an IP taken from X-Forwarded-For.
const ReasonXFF = "此 IP 來自代理標頭（X-Forwarded-For），可以偽造，無法確認真實來源"

// Attempts are the attempts one matched and judged request makes: one per
// candidate, and, when the judgment is Unknown, one per sink the cut may
// hide a payload for (one with no entry when none is known).
func (j *Judge) Attempts(rec AccessRecord, o Origin, m MatchResult, g Judgment) []Attempt {
	base := Attempt{Time: rec.Time, Sample: Sample(rec), Status: rec.Status, Bytes: rec.Bytes, Path: m.Request.Path,
		Cut: g.Cut || rec.Cut, Suspicious: rec.Suspicious, Ambiguous: rec.Ambiguous, Encoded: m.Request.Encoded, TimedOut: g.TimedOut}
	base.IP, base.Verified, base.Reason = clientOf(rec, o)
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
		a.Severity = SeverityOf(a.Level, a.Severe, false, a.Verified)
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

// clientOf is the request's client address: remote_addr for a known
// format; for one written out in place, X-Forwarded-For when it has one
// (its last address, the one the nearest proxy added), never verified.
func clientOf(rec AccessRecord, o Origin) (ip string, verified bool, reason string) {
	ip, verified, reason = rec.Client, o.Verified, o.Reason
	if !o.Verified && reason == "" {
		reason = "記錄檔未通過信任檢查（擁有者或權限不符），內容可能被竄改"
	}
	if o.Custom && strings.TrimSpace(rec.XFF) != "" {
		parts := strings.Split(rec.XFF, ",")
		ip, verified = strings.TrimSpace(parts[len(parts)-1]), false
		if reason != "" && reason != ReasonXFF {
			reason += "；" + ReasonXFF
		} else {
			reason = ReasonXFF
		}
	}
	return ip, verified, reason
}

// SeverityOf is an attempt's severity: L1 info, L2 high, L3 critical, an
// unknown one low; a step up when the vulnerability is KEV or critical
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

// sensitive are parameter names whose value a sample never shows.
var sensitive = []string{"token", "password", "passwd", "secret", "email", "session", "cookie", "authorization"}

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
	}
	return false
}

// Sample is the record's request line for a person to read: parameters
// with a sensitive name masked, then hostenv.MaskSecrets, then cut to
// MaxSample bytes on a character's boundary.
func Sample(rec AccessRecord) string {
	q := rec.Query
	if q != "" {
		var b strings.Builder
		start := 0
		for i := 0; i <= len(q); i++ { // parameters split on & and on ; (some servers take both)
			if i < len(q) && q[i] != '&' && q[i] != ';' {
				continue
			}
			kv := q[start:i]
			if k, _, ok := strings.Cut(kv, "="); ok && sensitiveName(k) {
				kv = k + "=[REDACTED]"
			}
			b.WriteString(kv)
			if i < len(q) {
				b.WriteByte(q[i])
			}
			start = i + 1
		}
		q = "?" + b.String()
	}
	s := hostenv.MaskSecrets(strings.TrimSpace(rec.Method + " " + rec.Path + q))
	if len(s) > MaxSample {
		n := MaxSample
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n]
	}
	return s
}
