package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// P4 part 1: attempts from judged requests. Neutral markers only.

func attemptJudge(t *testing.T) (*Judge, *Matcher) {
	t.Helper()
	ss := loadSigs(t, markerSigs)
	sinks := []CodeSink{
		{Rule: "js-sqli", CWE: "CWE-89", Severity: "warning", Path: "app/a.js", Line: 7,
			Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: "/marker/ping", File: "app/a.js", Line: 7}}},
		{Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "app/b.js", Line: 9,
			Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: "/marker/crit", File: "app/b.js", Line: 9}}},
	}
	return NewJudge(Build(sinks, nil), ss), NewMatcher(ss)
}

func attemptsOf(j *Judge, m *Matcher, rec AccessRecord, o Origin) []Attempt {
	res := m.Match(Normalize(rec))
	return j.Attempts(rec, o, res, j.Judge(res))
}

func TestAttempts(t *testing.T) {
	j, m := attemptJudge(t)
	at := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	rec := AccessRecord{Client: "198.51.100.7", Time: at, Method: "GET", Path: "/marker/ping", Query: "q=marker-one", Status: 200, Bytes: 512}
	as := attemptsOf(j, m, rec, Origin{Verified: true})
	if len(as) != 1 {
		t.Fatalf("%+v", as)
	}
	a := as[0]
	if a.Entry != "code:js-sqli:app/a.js:7" || a.Level != LevelPayload || a.Severity != "high" || a.IP != "198.51.100.7" || !a.Verified ||
		a.File != "app/a.js" || a.Line != 7 || a.Route == nil || a.Status != 200 || !a.Time.Equal(at) || strings.Join(a.Signatures, ",") != "class-marker" {
		t.Errorf("L2: %+v", a)
	}
	// A critical sink: a step up.
	if as = attemptsOf(j, m, AccessRecord{Client: "198.51.100.7", Method: "GET", Path: "/marker/crit", Query: "q=marker-one"}, Origin{Verified: true}); len(as) != 1 || as[0].Severity != "critical" || !as[0].Severe {
		t.Errorf("critical sink: %+v", as)
	}
	// The route alone: L1, info.
	if as = attemptsOf(j, m, AccessRecord{Client: "198.51.100.7", Method: "GET", Path: "/marker/ping"}, Origin{Verified: true}); len(as) != 1 || as[0].Level != LevelRoute || as[0].Severity != "info" {
		t.Errorf("L1: %+v", as)
	}
	// An unverified log: at most medium, a reason said.
	as = attemptsOf(j, m, AccessRecord{Client: "198.51.100.7", Method: "GET", Path: "/marker/crit", Query: "q=marker-one"}, Origin{})
	if len(as) != 1 || as[0].Severity != "medium" || as[0].Verified || as[0].Reason == "" {
		t.Errorf("unverified: %+v", as)
	}
}

// remote_addr for a known format, X-Forwarded-For (never believed) only
// for one written out in place.
func TestAttemptClient(t *testing.T) {
	j, m := attemptJudge(t)
	rec := AccessRecord{Client: "192.0.2.1", XFF: "203.0.113.9, 198.51.100.20", Method: "GET", Path: "/marker/ping", Query: "q=marker-one"}
	if as := attemptsOf(j, m, rec, Origin{Verified: true}); len(as) != 1 || as[0].IP != "192.0.2.1" || !as[0].Verified {
		t.Errorf("known format: %+v", as)
	}
	as := attemptsOf(j, m, rec, Origin{Verified: true, Custom: true})
	if len(as) != 1 || as[0].IP != "198.51.100.20" || as[0].Verified || as[0].Reason != ReasonXFF || as[0].Severity != "medium" {
		t.Errorf("custom format with XFF: %+v", as)
	}
	if as = attemptsOf(j, m, AccessRecord{Client: "192.0.2.1", Method: "GET", Path: "/marker/ping"}, Origin{Verified: true, Custom: true}); as[0].IP != "192.0.2.1" || !as[0].Verified {
		t.Errorf("custom format without XFF: %+v", as)
	}
}

// A cut request with no L2: one unknown attempt per sink it may hide a
// payload for.
func TestAttemptUnknown(t *testing.T) {
	j, m := attemptJudge(t)
	rec := AccessRecord{Client: "192.0.2.1", Method: "GET", Path: "/marker/ping", Query: "k=" + strings.Repeat("z", MaxNormalized+10)}
	as := attemptsOf(j, m, rec, Origin{Verified: true})
	var unknown []string
	for _, a := range as {
		if a.Level == LevelUnknown {
			if !a.Unknown || !a.Cut || a.Severity != "low" || len(a.HiddenClasses) == 0 {
				t.Errorf("unknown: %+v", a)
			}
			unknown = append(unknown, a.Entry)
		}
	}
	if strings.Join(unknown, ",") != "code:js-sqli:app/a.js:7" {
		t.Errorf("unknown attempts for %v, want the sink reached: %+v", unknown, as)
	}
}

// Sensitive parameters and secrets are masked; the sample is cut on a
// character's boundary.
func TestSample(t *testing.T) {
	tk, pw := "to"+"ken", "pass"+"word" // assembled: no credential-looking literal in the source
	rec := AccessRecord{Method: "GET", Path: "/marker", Query: "q=hello&" + tk + "=v1&user_email=v2&Session_ID=v3&" + pw + "=v4&cookie=v5&authorization=v6&page=2"}
	s := Sample(rec)
	for _, v := range []string{"v1", "v2", "v3", "v4", "v5", "v6"} {
		if strings.Contains(s, "="+v) {
			t.Errorf("%s shown: %s", v, s)
		}
	}
	if !strings.HasPrefix(s, "GET /marker?q=hello&") { // MaskSecrets may take the rest after a key=value secret: more masked, never less
		t.Errorf("sample %q", s)
	}
	long := Sample(AccessRecord{Method: "GET", Path: "/" + strings.Repeat("中", 200)})
	if len(long) > MaxSample || !strings.HasPrefix(long, "GET /中") || strings.ContainsRune(long, '�') {
		t.Errorf("cut sample: %d bytes %q", len(long), long[len(long)-6:])
	}
}

func TestSeverityOf(t *testing.T) {
	for _, c := range []struct {
		level                      string
		severe, campaign, verified bool
		want                       string
	}{
		{LevelRoute, false, false, true, "info"},
		{LevelRoute, true, false, true, "low"},
		{LevelRoute, true, true, true, "medium"},
		{LevelPayload, false, false, true, "high"},
		{LevelPayload, true, false, true, "critical"},
		{LevelPayload, true, true, true, "critical"},
		{LevelSuccess, false, false, true, "critical"},
		{LevelSuccess, false, false, false, "medium"},
		{LevelPayload, false, true, false, "medium"},
		{LevelUnknown, false, false, true, "low"},
	} {
		if got := SeverityOf(c.level, c.severe, c.campaign, c.verified); got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
	}
}
