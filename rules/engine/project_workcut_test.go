package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

// A file whose parse the work cap cuts is marked unread, so the project knows
// its calls were not all followed; the clock is not the only cut that counts
// (S-210r-1). An index that did not mark the file Limited (one made before the
// cap, from the cache) is what lets context() reach the parse.
func TestContextWorkCutWhileParsing(t *testing.T) {
	e := engineForTest(t)
	src := "<?php\n" + strings.Repeat("function f($a) { if ($a) { return g($a, [1, 2, 3]); } return h($a); }\n", 40)
	b := newBudget(Limits{MaxWork: 1 << 40})
	toks := lex("php", src, b)
	lexWork := b.work
	parse("php", toks, b)
	if b.work <= lexWork+2 {
		t.Fatalf("parsing did no work past lexing (%d, %d)", lexWork, b.work)
	}
	small := *e
	small.Limits.MaxWork = lexWork + (b.work-lexWork)/2 // the lexing fits, the parse does not

	sum := sha256.Sum256([]byte(src))
	cache := filepath.Join(t.TempDir(), "codeindex.json")
	saveIndexCache(cache, small.indexKey(), map[string]*fileIndex{"a.php": {Lang: "php", Hash: hex.EncodeToString(sum[:])}})
	read := func(string) ([]byte, error) { return []byte(src), nil }
	pr := small.NewProject([]string{"a.php"}, read, ProjectOptions{CacheFile: cache})
	if fi := pr.files["a.php"]; fi == nil || fi.Limited {
		t.Fatalf("a.php from the cache: %+v; want it not Limited", fi)
	}
	pr.context("a.php")
	if !pr.unread["a.php"] || !pr.unsteady {
		t.Errorf("parse cut by the work cap: unread %v, unsteady %v; want both", pr.unread["a.php"], pr.unsteady)
	}
}
