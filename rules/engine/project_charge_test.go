package engine

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// What a summary costs is its own work, whatever the project held when it was
// worked out: a file the token cap let go of and read again must not make a
// summary of it pay again for what was worked out before (whether a function
// of the file returns a guess, returnsUnknown) and kept small; and a summary
// the memory cap let go of (shrink(true)) is paid for at its first cost when
// worked out again.
func TestSummaryCostIndependentOfEviction(t *testing.T) {
	files := map[string]string{
		"c.php": "<?php\nfunction w($x) { return trim($x); }\n" +
			"function s1($v) { mysqli_query($db, \"SELECT \" . w($v)); }\n" +
			"function s2($v) { mysqli_query($db, \"SELECT \" . w($v) . 'x'); }\n",
		"a.php": "<?php\ns1($_GET['a']);\n",
		"b.php": "<?php\ns2($_GET['b']);\n",
		"d.php": "<?php\ns1($_GET['d']);\n", // s1 again: worked out again once the memory cap let it go
	}
	for i := range 4 { // filler, so that the cap lets c.php go between the two scans
		files[fmt.Sprintf("f%d.php", i)] = fmt.Sprintf("<?php\nfunction f%d($x) { return $x . '%d'; }\n", i, i)
	}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
	run := func(maxTokens int, shrinkAll bool) (map[string]int, []string) {
		e := engineForTest(t)
		e.Limits.MaxTime = time.Minute
		pr := e.NewProject(paths, read, ProjectOptions{MaxTime: time.Hour, MaxTokens: maxTokens})
		var res []string
		for _, p := range []string{"a.php", "f0.php", "f1.php", "f2.php", "f3.php", "b.php", "d.php"} {
			if p == "d.php" && shrinkAll {
				pr.shrink(true) // as the memory cap does: s1 is worked out again for d.php
			}
			fs, _, err := pr.ScanCallsTimed(p, []byte(files[p]))
			res = append(res, fmt.Sprintf("%s %d %v", p, len(fs), err))
		}
		costs := map[string]int{}
		for k, sc := range pr.sums {
			if sc == nil || k.file != "c.php" {
				continue
			}
			for name, s := range sc.done {
				costs[k.rule+" "+name] = s.cost
			}
		}
		return costs, res
	}
	held, heldRes := run(1<<30, false)
	if len(held) == 0 {
		t.Fatal("no summary of c.php worked out")
	}
	for _, c := range []struct {
		name      string
		maxTokens int
		shrinkAll bool
	}{{"c.php let go of and read again", 40, false}, {"every cache let go of before d.php", 1 << 30, true}} {
		got, res := run(c.maxTokens, c.shrinkAll)
		if !slices.Equal(heldRes, res) {
			t.Errorf("%s: results differ:\nheld %v\nhere %v", c.name, heldRes, res)
		}
		for k, cost := range held {
			if g, ok := got[k]; ok && g != cost {
				t.Errorf("%s costs %d with every file held, %d with %s", k, cost, g, c.name)
			}
		}
	}
}

// Whether a function returns a guess (returnsUnknown) is kept only when the
// body was read to its end: an asker whose budget runs out in the middle
// must not leave its half answer to the next asker, who has budget left.
func TestReturnsUnknownNotKeptWhenCut(t *testing.T) {
	e := engineForTest(t)
	var r *crule
	for _, x := range e.byLang["php"] {
		if x.rule.ID == "php-sqli-string-concat" {
			r = x
		}
	}
	if r == nil {
		t.Fatal("no rule php-sqli-string-concat")
	}
	src := "<?php\nfunction w($x) {\n" + strings.Repeat("\t$y = $x . 'a';\n", 50) + "\treturn $x;\n}\n"
	b := newBudget(Limits{MaxTokens: DefaultLimits.MaxTokens, MaxTime: 10 * time.Second})
	toks := lex("php", src, b)
	ff := newFileFuncs(collectFuncs(parse("php", toks, b), "php"), "php")
	sc := newSummaries(ff)
	ask := func(maxWork int) bool {
		b := &budget{maxTok: DefaultLimits.MaxTokens, deadline: time.Now().Add(10 * time.Second), maxWork: maxWork}
		a := &analysis{r: r, php: true, b: b, kw: keywords["php"], seen: map[loc]bool{}, sc: sc, file: "a.php", ftoks: toks}
		return a.returnsUnknown("w")
	}
	if ask(0) {
		t.Fatal("w returns its parameter: not a guess")
	}
	clear(sc.retUnk)
	ask(20) // runs out of budget in the middle of w
	if ask(0) {
		t.Errorf("w read in full by an asker with budget left: a guess, as left by an asker cut short (retUnk %v)", sc.retUnk)
	}
}
