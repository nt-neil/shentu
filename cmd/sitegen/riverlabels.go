package main

import (
	"sort"
	"strings"
)

// The river's labels (version, date, rule count) sit under each lamp. With
// many releases on a narrow river they run into each other, so each lamp gets
// the narrowest river width at which its label still has room; below that its
// label shows only on hover or focus. Which labels keep their room is chosen
// by priority: the newest, then the minor releases (x.y.0), newest first,
// then the rest, newest first. The widths come from the lamps' positions
// (xpos), so they follow the number of releases with nothing fixed per lamp.
const (
	labelGap      = 104  // px a label needs, centre to centre (the widest: "15/97 樣本抓到")
	labelEdge     = 44   // px from the river's edge to a label's centre (half a lamp's 76px and padding)
	labelStep     = 20   // px between the river widths tried
	labelMinWidth = 640  // below this the river is a list (site.css), every label shows
	labelMaxWidth = 2400 // wider than any river the site has
	labelNever    = 99999
)

// labelWidths: for releases oldest first (as the river draws them), the
// narrowest river width in px from which each one's label shows.
func labelWidths(rs []Release) []int {
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
	// shown[w][i]: the label of i has room at river width w, chosen greedily
	// in priority order. A label shows from the narrowest width from which it
	// has room at every wider width, so the labels shown at a width are always
	// some of the greedy choice there and never run into each other.
	for i := range out {
		out[i] = labelMinWidth
	}
	for w := labelMaxWidth; w >= labelMinWidth; w -= labelStep {
		var placed []float64
		for _, i := range order {
			px := x[i] * float64(w) / 100
			if px < labelEdge || float64(w)-px < labelEdge {
				continue
			}
			ok := true
			for _, p := range placed {
				if d := px - p; d < labelGap && d > -labelGap {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			placed = append(placed, px)
		}
		for _, i := range order {
			px := x[i] * float64(w) / 100
			in := false
			for _, p := range placed {
				if p == px {
					in = true
					break
				}
			}
			if !in && out[i] <= w {
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
