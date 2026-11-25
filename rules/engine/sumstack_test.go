package engine

import (
	"fmt"
	"strings"
	"testing"
)

// A cross-file cycle is worked out by file, then key. Members alike in both
// (other analyses of the same file) keep the order they joined in, and one
// that joined twice is there once, the first time: what a sort happens to
// leave among equals would otherwise choose which one is kept and which goes
// first, and with it where the rounds and the caps fall.
func TestCycleOrderFixed(t *testing.T) {
	var as []*analysis
	for range 30 {
		as = append(as, &analysis{file: "c.php", sc: &summaries{}})
	}
	b := &analysis{file: "b.php", sc: &summaries{}}
	keys := []string{"g", "f", "h"}
	var in []sumMember
	for i := range 90 {
		in = append(in, sumMember{as[(i*7)%30], keys[i%3]})
	}
	in = append(in, sumMember{b, "z"}, sumMember{as[0], "f"}, sumMember{as[3], "g"})
	name := func(ms []sumMember) string {
		var s []string
		for _, m := range ms {
			n := "b"
			for i, a := range as {
				if m.a == a {
					n = fmt.Sprint(i)
				}
			}
			s = append(s, m.a.file+"/"+m.key+"/"+n)
		}
		return strings.Join(s, " ")
	}
	// b.php first; then c.php by key, each key's members in the order they joined.
	want := []sumMember{{b, "z"}}
	for _, k := range []string{"f", "g", "h"} {
		seen := map[*analysis]bool{}
		for _, m := range in {
			if m.key == k && m.a.file == "c.php" && !seen[m.a] {
				seen[m.a] = true
				want = append(want, m)
			}
		}
	}
	if got := cycleOrder(in); name(got) != name(want) {
		t.Errorf("cycle order:\n%s\nwant:\n%s", name(got), name(want))
	}
}

// A member's summaries join its cycle in key order, not map order.
func TestHoldKeyOrder(t *testing.T) {
	a := &analysis{file: "a.php", sc: &summaries{}}
	p := &Project{stack: []*sumFrame{{a: a}}}
	fr := &sumFrame{a: a, root: 0}
	sums := map[string]*summary{}
	var want []string
	for i := range 40 {
		k := fmt.Sprintf("k%02d", i)
		sums[k] = &summary{}
		want = append(want, k)
	}
	p.hold(fr, sums)
	var got []string
	for _, m := range p.stack[0].members {
		got = append(got, m.key)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("held in order %v, want %v", got, want)
	}
}
