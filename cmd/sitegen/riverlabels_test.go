package main

import (
	"fmt"
	"testing"
)

// shownLabels: at river width w, the centre and width of each label that
// shows, oldest first.
func shownLabels(rs []Release, tr func(string) string, w int) (px, lw []float64, newest bool) {
	n := len(rs)
	ws := riverLabels(rs, tr)
	for i, min := range ws {
		if w >= min {
			px = append(px, (7+86*float64(i)/float64(n-1))*float64(w)/100)
			lw = append(lw, labelWidth(rs[i], tr))
			newest = i == n-1
		}
	}
	return
}

// checkRoom: the labels that show at every river width have room, none past
// the river's edge, and the newest shows wherever its own label fits.
func checkRoom(t *testing.T, name string, rs []Release, tr func(string) string, from, to, step int) {
	t.Helper()
	n := len(rs)
	for w := from; w <= to; w += step {
		px, lw, newest := shownLabels(rs, tr, w)
		for k := range px {
			if px[k]-lw[k]/2 < 0 || px[k]+lw[k]/2 > float64(w) {
				t.Errorf("%s w=%d: a label %.0fpx wide at %.0fpx runs past the river", name, w, lw[k], px[k])
			}
			if k > 0 && px[k]-px[k-1] < (lw[k]+lw[k-1])/2+labelPad {
				t.Errorf("%s w=%d: labels at %.0f and %.0f px run into each other", name, w, px[k-1], px[k])
			}
		}
		// widths are tried every labelStep, so it shows once it fits one step narrower
		x := 93 * float64(w-labelStep) / 100
		if nw := labelWidth(rs[n-1], tr); w-labelStep >= labelMinWidth && x+nw/2 <= float64(w-labelStep) && !newest {
			t.Errorf("%s w=%d: the newest label fits but does not show", name, w)
		}
	}
}

func enT(k string) string { return en[k] }

func releases(n int, ver func(i int) string, rules int, bench *Bench) []Release {
	rs := make([]Release, n)
	for i := range rs {
		rs[i] = Release{Version: ver(i), Date: "2026-11-24", Rules: rules, Bench: bench}
	}
	return rs
}

// 2 to 40 releases, every fourth a minor release (x.y.0), at every width.
func TestRiverLabelsHaveRoom(t *testing.T) {
	for n := 2; n <= 40; n++ {
		rs := releases(n, func(i int) string { return fmt.Sprintf("0.%d.%d", i/4, i%4) }, 127, nil)
		checkRoom(t, fmt.Sprintf("n=%d", n), rs, enT, labelMinWidth, labelMaxWidth, 7)
	}
}

// Longer labels than the site has now (S-231-1): a version like v0.10.12, a
// three-digit bench and a long English word for what the bench caught still
// get room, because each label's width comes from its own text.
func TestRiverLabelsLongText(t *testing.T) {
	long := func(k string) string {
		if k == "river.caught" {
			return "caught in the vulnerable releases"
		}
		return enT(k)
	}
	bench := &Bench{Groups: []BenchRow{{Group: "all", Cases: 300, Caught: 150}}}
	for _, n := range []int{2, 12, 30} {
		rs := releases(n, func(i int) string { return fmt.Sprintf("0.10.%d", 10+i) }, 1270, bench)
		if w := labelWidth(rs[0], long); w < textWidth("150/300 caught in the vulnerable releases", 13) {
			t.Errorf("n=%d: the bench line is %.0fpx, estimated narrower", n, w)
		}
		checkRoom(t, fmt.Sprintf("long n=%d", n), rs, long, labelMinWidth, labelMaxWidth, 7)
	}
}

// Just above the list layout (a river 641 to 760px wide), the rightmost
// label that shows stays inside the river, in both languages.
func TestRiverLabelsNarrowEdge(t *testing.T) {
	zhT := func(k string) string { return zh[k] }
	bench := &Bench{Groups: []BenchRow{{Group: "all", Cases: 97, Caught: 16}}}
	for _, tr := range []func(string) string{enT, zhT} {
		for _, n := range []int{2, 21, 30} {
			rs := releases(n, func(i int) string { return fmt.Sprintf("0.5.%d", i) }, 127, bench)
			for w := 641; w <= 760; w++ {
				px, lw, _ := shownLabels(rs, tr, w)
				if k := len(px) - 1; k >= 0 && px[k]+lw[k]/2 > float64(w) {
					t.Errorf("n=%d w=%d: the rightmost label ends at %.0fpx", n, w, px[k]+lw[k]/2)
				}
			}
		}
	}
}
