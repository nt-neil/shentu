package main

import (
	"fmt"
	"testing"
)

// At every river width, the labels that show have room: no two are closer
// than labelGap, none is nearer the edge than labelEdge, and the newest
// always shows. Checked for 2 to 40 releases, so it holds as the river grows.
func TestRiverLabelsHaveRoom(t *testing.T) {
	for n := 2; n <= 40; n++ {
		rs := make([]Release, n)
		for i := range rs {
			rs[i].Version = fmt.Sprintf("0.%d.%d", i/4, i%4) // every fourth a minor release (x.y.0)
		}
		ws := labelWidths(rs)
		if ws[n-1] != labelMinWidth {
			t.Errorf("n=%d: the newest shows from %d, want %d", n, ws[n-1], labelMinWidth)
		}
		for w := labelMinWidth; w <= labelMaxWidth; w += 7 {
			var shown []float64
			for i, min := range ws {
				if w >= min {
					shown = append(shown, (7+86*float64(i)/float64(n-1))*float64(w)/100)
				}
			}
			for k, p := range shown {
				if p < labelEdge || float64(w)-p < labelEdge {
					t.Errorf("n=%d w=%d: a label at %.0fpx is too near the edge", n, w, p)
				}
				if k > 0 && p-shown[k-1] < labelGap {
					t.Errorf("n=%d w=%d: labels at %.0f and %.0f px run into each other", n, w, shown[k-1], p)
				}
			}
		}
	}
}
