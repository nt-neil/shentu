package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The listing finds each kind of site and follows calls to the functions it
// is asked about: a list that came out empty for want of either would pass
// the approved-list check without checking anything.
func TestListSample(t *testing.T) {
	sites, err := list("testdata/sample", engineReach)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i, s := range sites {
		if (len(s.body) == 12) != (i != 4) || i > 0 && i < 4 && s.body == sites[i-1].body {
			t.Errorf("%s: body hash %q: want 12 hex digits for each loop, its own, and none for a maps iterator not ranged over", s.pos, s.body)
		}
		got = append(got, fmt.Sprintf("%s %s %s %d [%s] [%s]", s.pos, s.fn, s.expr, s.n, strings.Join(s.reach, ","), strings.Join(s.unknown, ",")))
	}
	want := []string{
		"sample.go:23 walk m 1 [load] []",
		"sample.go:26 walk m 2 [load] [value g]",
		"sample.go:30 walk m 3 [] [iface r.read,value cb]",
		"sample.go:34 walk m 4 [] []",
		"sample.go:41 walk maps.Values(m) 1 [] []",
		"sample.go:42 walk maps.Keys(m) 1 [] []",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sites:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Every range over a map in rules/engine is in approved.tsv with its body's
// hash and what the body reaches, and the list has nothing that is gone: a
// loop whose body changed is read again. A new one fails here
// until it is read and added; `go run ./internal/devtools/maprange rules/engine`
// prints the current list with positions.
func TestEngineMapRanges(t *testing.T) {
	sites, err := list("../../../rules/engine", engineReach)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("approved.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	approved := map[string]string{} // function, ranged over, ordinal → body, reached, not followed
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		c := strings.Split(l, "\t")
		if len(c) != 8 || (c[6] != "SAFE" && c[6] != "SORTED") || c[7] == "" {
			t.Fatalf("approved.tsv: want function, ranged over, ordinal, body hash, reached, not followed, SAFE or SORTED, why: %q", l)
		}
		approved[strings.Join(c[:3], "\t")] = strings.Join(c[3:6], "\t")
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for _, s := range sites {
		k := fmt.Sprintf("%s\t%s\t%d", s.fn, s.expr, s.n)
		body := s.body + "\t" + strings.Join(s.reach, ",") + "\t" + strings.Join(s.unknown, ",")
		a, ok := approved[k]
		switch {
		case !ok:
			t.Errorf("%s: %s ranges over %s in map order (reaches [%s], not followed [%s]); read it and add it to approved.tsv", s.pos, s.fn, s.expr, strings.Join(s.reach, ","), strings.Join(s.unknown, ","))
		case a != body:
			t.Errorf("%s: %s over %s now has body hash, reaches and leaves unfollowed %q, approved.tsv has %q; read it again", s.pos, s.fn, s.expr, body, a)
		}
		delete(approved, k)
	}
	for k := range approved {
		t.Errorf("approved.tsv lists %q, which is no longer in rules/engine", k)
	}
}
