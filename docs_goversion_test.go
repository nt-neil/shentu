package main

import (
	"os"
	"regexp"
	"testing"
)

// The Go version the docs ask for is the one go.mod's go line needs (it went
// from 1.23 to 1.26 with golang.org/x/sys and README and models.md lagged).
func TestDocsGoVersionMatchesGoMod(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+)`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("no go line in go.mod")
	}
	want := string(m[1])
	re := regexp.MustCompile(`\bGo (\d+\.\d+)\b`)
	for _, f := range []string{"README.md", "docs/models.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		found := re.FindAllSubmatch(b, -1)
		if len(found) == 0 {
			t.Errorf("%s names no Go version", f)
		}
		for _, v := range found {
			if string(v[1]) != want {
				t.Errorf("%s says Go %s, go.mod needs %s", f, v[1], want)
			}
		}
	}
}
