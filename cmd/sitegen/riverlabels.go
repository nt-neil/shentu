package main

import (
	"fmt"
	"sort"
	"strings"
)

// The river's labels (version, date, rule count, bench) sit under each lamp.
// With many releases on a narrow river they run into each other, so each
// lamp gets the narrowest river width at which its label still has room;
// below that its label shows only on hover or focus. Which labels keep their
// room is chosen by priority: the newest, then the minor releases (x.y.0),
// newest first, then the rest, newest first. The widths come from the lamps'
// positions (xpos) and from each label's own text (labelWidth), so they
// follow the number of releases and the length of what the labels say, with
// nothing fixed per lamp.
const (
	labelPad      = 8    // px kept between two labels (a label may reach the river's edge, not past it)
	labelLamp     = 84   // px a lamp takes at least (min-width 76px, padding 4px each side)
	labelStep     = 20   // px between the river widths tried
	labelMinWidth = 640  // below this the river is a list (site.css), every label shows
	labelMaxWidth = 2400 // wider than any river the site has
	labelNever    = 99999
)

// textWidth estimates s set at px: a CJK character is about 1em, anything
// else at most 0.6em (digits and Latin in the site's serif, sans and mono
// faces are narrower; the estimate errs wide).
func textWidth(s string, px float64) float64 {
	w := 0.0
	for _, r := range s {
		if r >= 0x2E80 {
			w += px
		} else {
			w += 0.6 * px
		}
	}
	return w
}

// labelWidth estimates the widest line of a release's label in px, as
// layout.html sets it: the version (serif 22px), the date (mono 12px) or the
// coming-soon badge (sans 12px, 16px padding), the rule count and the bench
// (numbers serif 20px, words 13px). tr translates as the page does.
func labelWidth(r Release, tr func(string) string) float64 {
	w := float64(labelLamp)
	max := func(v float64) {
		if v > w {
			w = v
		}
	}
	max(textWidth("v"+r.Version, 22))
	if len(r.Date) > 5 {
		max(textWidth(r.Date[5:], 12))
	} else {
		max(textWidth(tr("soon"), 12) + 16)
	}
	if r.Rules > 0 {
		max(textWidth(fmt.Sprint(r.Rules), 20) + textWidth(" "+tr("hist.rules"), 13))
	}
	if r.Bench != nil {
		a := r.Bench.All()
		max(textWidth(fmt.Sprint(a.Caught), 20) + textWidth(fmt.Sprintf("/%d %s", a.Cases, tr("river.caught")), 13))
	}
	return w
}

// labelWidths: for releases oldest first (as the river draws them) and the
// width of each one's label, the narrowest river width in px from which
// each label shows.
func labelWidths(rs []Release, lw []float64) []int {
	n := len(rs)
	out := make([]int, n)
	if n < 2 {
		return out
	}
	x := make([]float64, n)
	for i := range rs {
		x[i] = 7 + 86*float64(i)/float64(n-1)
	}
	order := []int{n - 1}
	for i := n - 2; i >= 0; i-- {
		if strings.HasSuffix(rs[i].Version, ".0") {
			order = append(order, i)
		}
	}
	for i := n - 2; i >= 0; i-- {
		if !strings.HasSuffix(rs[i].Version, ".0") {
			order = append(order, i)
		}
	}
	// At each river width the labels are placed greedily in priority order.
	// A label shows from the narrowest width from which it is placed at every
	// wider width, so the labels shown at a width are always some of those
	// placed there and never run into each other or past the edge.
	for i := range out {
		out[i] = labelMinWidth
	}
	for w := labelMaxWidth; w >= labelMinWidth; w -= labelStep {
		placed := map[int]bool{}
		for _, i := range order {
			px := x[i] * float64(w) / 100
			if px-lw[i]/2 < 0 || px+lw[i]/2 > float64(w) {
				continue
			}
			ok := true
			for j := range placed {
				d := px - x[j]*float64(w)/100
				if d < 0 {
					d = -d
				}
				if d < (lw[i]+lw[j])/2+labelPad {
					ok = false
					break
				}
			}
			if ok {
				placed[i] = true
			}
		}
		for i := range out {
			if !placed[i] && out[i] <= w {
				out[i] = w + labelStep
			}
		}
	}
	for i := range out {
		if out[i] > labelMaxWidth {
			out[i] = labelNever
		}
	}
	return out
}

// labelSteps: the distinct widths above the list layout, for the rules that
// hide a label below its width.
func labelSteps(ws []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, w := range ws {
		if w > labelMinWidth && !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	sort.Ints(out)
	return out
}

// riverLabels: the label widths of releases oldest first, for a page in the
// language tr translates to.
func riverLabels(rs []Release, tr func(string) string) []int {
	lw := make([]float64, len(rs))
	for i, r := range rs {
		lw[i] = labelWidth(r, tr)
	}
	return labelWidths(rs, lw)
}
