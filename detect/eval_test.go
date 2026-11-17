package detect

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/rules/engine"
)

// evalRequest is one request of an evaluation set (detect/testdata/holdout:
// written apart from the signatures, read only by this evaluation).
type evalRequest struct {
	ID        string `json:"id"`
	Set       string `json:"set"`   // attack or normal
	Class     string `json:"class"` // the payload class an attack carries; "" for a normal request
	Method    string `json:"method"`
	Path      string `json:"path"`
	Query     string `json:"query"`
	UserAgent string `json:"user_agent"`
	Referer   string `json:"referer"`
	Note      string `json:"note"`
}

// evalSet is what one set came to.
type evalSet struct {
	Name     string         `json:"name"`
	Requests int            `json:"requests"`
	Caught   int            `json:"caught"`         // attack: a hit of its own class
	Missed   []string       `json:"missed"`         // attack: ids with none
	Hit      int            `json:"hit"`            // normal: a hit of any vulnerability class (a false positive)
	Hits     []string       `json:"false_positive"` // normal: ids and signatures
	Levels   map[string]int `json:"levels"`         // L1, L2, noise, unanchored, none: Judge on the evaluation surface
}

// evaluate runs the signatures over requests. Judge needs a host: the
// evaluation surface has, for every class, a code sink registered at every
// path the requests use, so a request's level says what it would be on a
// host vulnerable there: an attack L2 when its payload is seen, a normal
// request L1 (route only) unless a signature takes it for an attack.
func evaluate(name string, rs []evalRequest, ss []sig.Signature) evalSet {
	out := evalSet{Name: name, Requests: len(rs), Levels: map[string]int{}}
	paths := map[string]bool{}
	for _, r := range rs {
		paths[strings.ToLower(cleanPath(r.Path))] = true
	}
	var sinks []CodeSink
	for class, cwe := range map[string]string{"sqli": "CWE-89", "cmdi": "CWE-78", "path": "CWE-22", "ssrf": "CWE-918", "xss": "CWE-79",
		"deser": "CWE-502", "xxe": "CWE-611", "code": "CWE-94", "nosqli": "CWE-943", "ldapi": "CWE-90", "xpathi": "CWE-643", "redirect": "CWE-601", "upload": "CWE-434"} {
		var routes []engine.RouteRef
		for p := range paths {
			routes = append(routes, engine.RouteRef{Model: "eval", Framework: "eval", Pattern: p, File: "eval", Line: 1})
			if len(routes) == 16 {
				sinks = append(sinks, CodeSink{Rule: "eval-" + class, CWE: cwe, Path: "eval/" + class, Line: len(sinks) + 1, Routes: routes})
				routes = nil
			}
		}
		if len(routes) > 0 {
			sinks = append(sinks, CodeSink{Rule: "eval-" + class, CWE: cwe, Path: "eval/" + class, Line: len(sinks) + 1, Routes: routes})
		}
	}
	surface := Build(sinks, nil)
	m, j := NewMatcher(ss), NewJudge(surface, ss)
	for _, r := range rs {
		rec := AccessRecord{Method: r.Method, Path: r.Path, Query: r.Query, UserAgent: r.UserAgent, Referer: r.Referer}
		res := m.Match(Normalize(rec))
		classes := map[string][]string{}
		for _, h := range res.Hits {
			classes[h.Class] = append(classes[h.Class], h.Signature)
		}
		g := j.Judge(res)
		level := "none"
		switch {
		case len(g.Candidates) > 0:
			level = g.Candidates[0].Level
		case len(g.Unanchored) > 0:
			level = "unanchored"
		case len(g.Noise) > 0:
			level = "noise"
		}
		out.Levels[level]++
		switch r.Set {
		case "attack":
			if len(classes[r.Class]) > 0 {
				out.Caught++
			} else {
				out.Missed = append(out.Missed, r.ID)
			}
		case "normal":
			var fp []string
			for c, ids := range classes {
				if c != "scanner" {
					fp = append(fp, ids...)
				}
			}
			if len(fp) > 0 {
				sort.Strings(fp)
				out.Hit++
				out.Hits = append(out.Hits, r.ID+": "+strings.Join(fp, ","))
			}
		}
	}
	return out
}

func readEvalSet(t *testing.T, dir string) []evalRequest {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	var rs []evalRequest
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for n := 1; sc.Scan(); n++ {
			if strings.TrimSpace(sc.Text()) == "" {
				continue
			}
			var r evalRequest
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatalf("%s:%d: %v", f, n, err)
			}
			rs = append(rs, r)
		}
		fh.Close()
	}
	return rs
}

// TestHoldoutEvaluation runs only when asked (SHENTU_HOLDOUT=1): the
// held-out set is not read while signatures are written.
func TestHoldoutEvaluation(t *testing.T) {
	if os.Getenv("SHENTU_HOLDOUT") != "1" {
		t.Skip("set SHENTU_HOLDOUT=1 to evaluate on detect/testdata/holdout")
	}
	rs := readEvalSet(t, filepath.Join("testdata", "holdout"))
	if len(rs) == 0 { // asked for and not there: a failure, not a pass that evaluated nothing
		t.Fatal("SHENTU_HOLDOUT=1 but no held-out set under detect/testdata/holdout")
	}
	ss, err := sig.Load()
	if err != nil {
		t.Fatal(err)
	}
	var attack, normal []evalRequest
	for _, r := range rs {
		if r.Set == "attack" {
			attack = append(attack, r)
		} else {
			normal = append(normal, r)
		}
	}
	for _, s := range []evalSet{evaluate("holdout attack", attack, ss), evaluate("holdout normal", normal, ss)} {
		b, _ := json.MarshalIndent(s, "", "  ")
		t.Logf("%s", b)
		if out := os.Getenv("SHENTU_HOLDOUT_OUT"); out != "" {
			os.WriteFile(filepath.Join(out, strings.ReplaceAll(s.Name, " ", "-")+".json"), b, 0o600)
		}
	}
}

// The harness itself, on made-up requests (not the held-out set).
func TestEvaluateHarness(t *testing.T) {
	ss, err := sig.Load()
	if err != nil {
		t.Fatal(err)
	}
	attack := evaluate("a", []evalRequest{
		{ID: "a1", Set: "attack", Class: "sqli", Method: "GET", Path: "/item.php", Query: "id=1%20union%20select%201"},
		{ID: "a2", Set: "attack", Class: "cmdi", Method: "GET", Path: "/ping", Query: "h=1"},
	}, ss)
	if attack.Caught != 1 || len(attack.Missed) != 1 || attack.Missed[0] != "a2" || attack.Levels["L2"] != 1 || attack.Levels["L1"] != 1 {
		t.Errorf("attack %+v", attack)
	}
	normal := evaluate("n", []evalRequest{
		{ID: "n1", Set: "normal", Method: "GET", Path: "/search", Query: "q=cats"},
		{ID: "n2", Set: "normal", Method: "GET", Path: "/search", Query: "q=1%20union%20select%202"},
	}, ss)
	if normal.Hit != 1 || !strings.HasPrefix(normal.Hits[0], "n2:") || normal.Levels["L1"] != 1 || normal.Levels["L2"] != 1 {
		t.Errorf("normal %+v", normal)
	}
}
