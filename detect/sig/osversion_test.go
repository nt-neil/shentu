package sig

import (
	"strings"
	"testing"
	"testing/fstest"
)

// dpkgVectors are dpkg's own: scripts/t/Dpkg_Version.t's __DATA__ (dpkg
// main, 2026-11-16), each "a b result".
const dpkgVectors = `1.0-1 2.0-2 -1
2.2~rc-4 2.2-1 -1
2.2-1 2.2~rc-4 1
1.0000-1 1.0-1 0
1 0:1 0
0 0:0-0 0
2:2.5 1:7.5 1
1:0foo 0foo 1
0:0foo 0foo 0
0foo 0foo 0
0foo-0 0foo 0
0foo 0foo-0 0
0foo 0fo 1
0foo-0 0foo+ -1
0foo~1 0foo -1
0foo~foo+Bar 0foo~foo+bar -1
0foo~~ 0foo~ -1
1~ 1 -1
12345+that-really-is-some-ver-0 12345+that-really-is-some-ver-10 -1
0foo-0 0foo-01 -1
0foo.bar 0foobar 1
0foo.bar 0foo1bar 1
0foo.bar 0foo0bar 1
0foo1bar-1 0foobar-1 -1
0foo2.0 0foo2 1
0foo2.0.0 0foo2.10.0 -1
0foo2.0 0foo2.0.0 -1
0foo2.0 0foo2.10 -1
0foo2.1 0foo2.10 -1
1.09 1.9 0
1.0.8+nmu1 1.0.8 1
3.11 3.10+nmu1 1
0.9j-20080306-4 0.9i-20070324-2 1
1.2.0~b7-1 1.2.0~b6-1 1
1.011-1 1.06-2 1
0.0.9+dfsg1-1 0.0.8+dfsg1-3 1
4.6.99+svn6582-1 4.6.99+svn6496-1 1
53 52 1
0.9.9~pre122-1 0.9.9~pre111-1 1
2:2.3.2-2+lenny2 2:2.3.2-2 1
1:3.8.1-1 3.8.GA-1 1
1.0.1+gpl-1 1.0.1-2 1
1a 1000a -1`

func TestDpkgCompare(t *testing.T) {
	for _, l := range strings.Split(dpkgVectors, "\n") {
		f := strings.Fields(l)
		want := map[string]int{"-1": -1, "0": 0, "1": 1}[f[2]]
		if got := DpkgCompare(f[0], f[1]); got != want {
			t.Errorf("DpkgCompare(%s, %s) = %d, want %d", f[0], f[1], got, want)
		}
		if got := DpkgCompare(f[1], f[0]); got != -want {
			t.Errorf("DpkgCompare(%s, %s) = %d, want %d", f[1], f[0], got, -want)
		}
	}
	// lib/dpkg/t/t-version.c's test_version_compare.
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0:0-0", "0:0-0", 0}, {"0:0-00", "0:00-0", 0}, {"1:2-3", "1:2-3", 0}, {"0:0-0", "1:0-0", -1},
		{"0:a-0", "0:b-0", -1}, {"0:0-a", "0:0-b", -1}, {"0:1-1", "0:2-1", -1}, {"0:1-1", "0:1-2", -1},
	} {
		if got := DpkgCompare(c.a, c.b); got != c.want {
			t.Errorf("DpkgCompare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// Ranges of Debian, Ubuntu and rpm distributions are taken and compared
// in their own order; a bound not of their syntax is refused.
func TestOSRanges(t *testing.T) {
	for _, c := range []struct {
		eco, versions, v string
		in               bool
	}{
		{"Debian", "<2.4.62-1~deb12u1", "2.4.61-1~deb12u1", true},
		{"Debian:12", "<2.4.62-1~deb12u1", "2.4.62-1~deb12u1", false},
		{"Debian", "<2.4.62-1", "2.4.62-1~deb12u1", true}, // ~ before the end
		{"Ubuntu", "<1:2.0-1", "2.9-1", true},             // the epoch first
		{"Red Hat", "<2.4.57-11.el9", "2.4.57-5.el9", true},
		{"Rocky Linux", ">=1.0-1, <1.0-10", "1.0-9", true},
		{"AlmaLinux", "<1.0~rc1-1", "1.0-1", false},
	} {
		in, ok := InRange(Range{Ecosystem: c.eco, Package: "x", Versions: c.versions}, c.v)
		if !ok || in != c.in {
			t.Errorf("%s %s in %q: in %v ok %v, want %v", c.eco, c.v, c.versions, in, ok, c.in)
		}
	}
	if _, ok := InRange(Range{Ecosystem: "Debian", Package: "x", Versions: "<1.0"}, "abc"); ok {
		t.Error("a version not starting with a digit compared as Debian's")
	}
	load := func(eco, versions string) error {
		_, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(good + "[[signature.applies_to]]\necosystem = \"" + eco + "\"\npackage = \"x\"\nversions = \"" + versions + "\"\n")}}, "s")
		return err
	}
	for _, eco := range []string{"Debian", "Debian:12", "Ubuntu", "Red Hat", "Rocky Linux", "AlmaLinux", "Amazon Linux"} {
		if err := load(eco, "<1:2.4.62-1~deb12u1"); err != nil {
			t.Errorf("%s: %v", eco, err)
		}
	}
	if err := load("Debian", "<abc"); err == nil {
		t.Error("a Debian bound not a version taken")
	}
}
