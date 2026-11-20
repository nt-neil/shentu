package main

import "testing"

func TestItemLinks(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"see [the limits](" + repo + "/blob/main/docs/x.md#a-b).", `see <a href="` + repo + `/blob/main/docs/x.md#a-b">the limits</a>.`},
		{"[other](https://example.com/x) stays", "[other](https://example.com/x) stays"},
		{"`[c](" + repo + "/x)` is code", "<code>[c](" + repo + "/x)</code> is code"},
		{"[a\"b](" + repo + "/x)", `<a href="` + repo + `/x">a&#34;b</a>`},
		// A path that steps out with /.. or an encoded dot stays text.
		{"[up](" + repo + "/../other)", "[up](" + repo + "/../other)"},
		{"[up](" + repo + "/blob/main/..)", "[up](" + repo + "/blob/main/..)"},
		{"[enc](" + repo + "/%2e%2e/other)", "[enc](" + repo + "/%2e%2e/other)"},
		{"[enc](" + repo + "/%2E./other)", "[enc](" + repo + "/%2E./other)"},
		{"[enc](" + repo + "/blob/x%2Ey)", "[enc](" + repo + "/blob/x%2Ey)"},
		{"[dot](" + repo + "/blob/main/a.b.md)", `<a href="` + repo + `/blob/main/a.b.md">dot</a>`},
		// Browsers read a backslash as a slash, so it stays text; %5c does not step out.
		{"[bs](" + repo + "/x\\..\\..\\o)", "[bs](" + repo + "/x\\..\\..\\o)"},
		{"[pct](" + repo + "/x%5c..%5co)", `<a href="` + repo + `/x%5c..%5co">pct</a>`},
	} {
		if got := string(item(c.in)); got != c.want {
			t.Errorf("item(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
