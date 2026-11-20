package main

import "testing"

func TestItemLinks(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"see [the limits](" + repo + "/blob/main/docs/x.md#a-b).", `see <a href="` + repo + `/blob/main/docs/x.md#a-b">the limits</a>.`},
		{"[other](https://example.com/x) stays", "[other](https://example.com/x) stays"},
		{"`[c](" + repo + "/x)` is code", "<code>[c](" + repo + "/x)</code> is code"},
		{"[a\"b](" + repo + "/x)", `<a href="` + repo + `/x">a&#34;b</a>`},
	} {
		if got := string(item(c.in)); got != c.want {
			t.Errorf("item(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
