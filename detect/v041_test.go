package detect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// v0.4.1 (n35-a): a hit one entry takes at L2 is not also unanchored
// because another entry of its class, reached first in map order, did
// not take it. Run with -count=200: map order changes every run.
func TestUnanchoredOrderFree(t *testing.T) {
	ss := loadSigs(t, markerSigs)
	m := NewMatcher(ss)
	sink := func(line int, pattern string) CodeSink {
		return CodeSink{Rule: "js-sqli", CWE: "CWE-89", Severity: "critical", Path: "a.js", Line: line,
			Routes: []engine.RouteRef{{Model: "m", Framework: "express", Method: "get", Pattern: pattern, File: "a.js", Line: line}}}
	}
	// The same request reaches both: one takes the segment in its
	// placeholder, the other has it as its own word.
	j := NewJudge(Build([]CodeSink{sink(1, "/user/:id"), sink(2, "/user/marker-one")}, nil), ss)
	mr := m.Match(Normalize(AccessRecord{Method: "GET", Path: "/user/marker-one"}))
	for i := 0; i < 50; i++ {
		g := j.Judge(mr)
		if len(g.Candidates) != 2 || g.Candidates[0].Level != LevelPayload || g.Candidates[1].Level != LevelRoute || len(g.Unanchored) != 0 {
			t.Fatalf("run %d: %+v", i, g)
		}
	}
	// No entry takes it: unanchored once, whichever comes first.
	j = NewJudge(Build([]CodeSink{sink(1, "/user/marker-one"), sink(2, "/:a/marker-one")}, nil), ss)
	for i := 0; i < 50; i++ {
		if g := j.Judge(mr); len(g.Unanchored) != 1 {
			t.Fatalf("run %d: %+v", i, g)
		}
	}
}

// v0.4.1 (n36): the size baseline leaves out only requests at L2; one
// whose hit stays unanchored (L1) is an ordinary response of the route.
func TestBaselineSkipsOnlyL2(t *testing.T) {
	_, d, in := passSetup(t)
	write(t, filepath.Join(d, "access.log"), accessLine("203.0.113.9", t0.Add(70*time.Second), "/marker-one/marker/5", 200, 4321), os.O_APPEND)
	p, err := RunPass(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	b := p.baselines.Routes["GET /marker/{id}"]
	if b == nil {
		t.Fatalf("no baseline: %+v", p.baselines.Routes)
	}
	if !slices.Contains(b.Sizes, 4321) || slices.Contains(b.Sizes, 9000) || len(b.Sizes) != 31 {
		t.Errorf("sizes %v: want the 30 ordinary and the unanchored one, not the L2 one", fmt.Sprint(b.Sizes))
	}
}
