package hostenv

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// H-057-1: dpkg's package state decides, not what it is asked to do next.
// A package held with apt-mark hold is "hi": installed, and checked. On
// 9a5cfb3 only "ii" was kept, so a held package was not checked, nor said.
// Made-up packages and versions.
const dpkgStatesOut = "bash\t\t5.2.15-2+b7\tarm64\tii \n" +
	"libssl3\topenssl\t3.0.14-1~deb12u2\tarm64\thi \n" + // held
	"curl\t\t7.88.1-10+deb12u8\tarm64\tri \n" + // to be removed, still installed
	"libexample1\t\t1.2-3\tarm64\tpi \n" + // to be purged, still installed
	"apache2-data\tapache2\t2.4.62-1~deb12u2\tall\trc \n" + // removed, configuration left
	"halfpkg\t\t0.9-1\tarm64\tiH \n" +
	"unpackedpkg\t\t0.8-1\tarm64\tiU \n" +
	"purged\t\t0.1-1\tarm64\tpn \n"

func TestDpkgHeldInstalled(t *testing.T) {
	var names []string
	for _, p := range ParseDpkgQuery([]byte(dpkgStatesOut)) {
		names = append(names, p.Name)
	}
	if want := []string{"bash", "libssl3", "curl", "libexample1", "unpackedpkg"}; !slices.Equal(names, want) {
		t.Errorf("installed packages %q, want %q", names, want)
	}
	h := aptHost()
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte(dpkgStatesOut)}
	p := Collect(context.Background(), h).Packages
	if !slices.ContainsFunc(p.Value.Items, func(x Package) bool { return x.Name == "libssl3" && x.Source == "openssl" }) {
		t.Errorf("a held package not collected: %+v", p.Value.Items)
	}
}

// What is not installed in full is said: config-files in NotChecked only
// (nothing to run is left), half-installed and unpacked ones there and the
// list partial (their programs may be on the disk); purged ones are gone.
func TestDpkgOtherStatesSaid(t *testing.T) {
	pkgs, other, half := ParseDpkgQueryStates([]byte(dpkgStatesOut + "oddpkg\t\t1-1\tarm64\ti? \n" + "nostate\t\t2-1\tarm64\t\n"))
	want := []string{"apache2-data 2.4.62-1~deb12u2 (config-files)", "halfpkg 0.9-1 (half-installed)",
		"oddpkg 1-1 (state i? not read)", "nostate 2-1 (state not read)"}
	if !slices.Equal(other, want) {
		t.Errorf("not installed in full %q, want %q", other, want)
	}
	if slices.ContainsFunc(pkgs, func(p Package) bool { return p.Name == "oddpkg" || p.Name == "nostate" }) ||
		!slices.Contains(half, "oddpkg 1-1 (state i? not read, not checked)") {
		t.Errorf("a state not read is not checked, and is partial: %+v %q", pkgs, half)
	}
	h := aptHost()
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte(dpkgStatesOut)}
	p := Collect(context.Background(), h).Packages
	if p.Status != StatusPartial || !strings.Contains(p.Detail, "2 package(s) not fully installed: halfpkg 0.9-1 (half-installed, not checked), unpackedpkg 0.8-1 (unpacked)") {
		t.Errorf("half-installed not said: %s %q", p.Status, p.Detail)
	}
	if want := []string{"halfpkg 0.9-1 (half-installed)", "apache2-data 2.4.62-1~deb12u2 (config-files)"}; !slices.Equal(p.Value.NotChecked, want) {
		t.Errorf("not checked %q", p.Value.NotChecked)
	}
	// Only configuration left: listed, the list not partial.
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte("bash\t\t5.2.15-2+b7\tarm64\tii \napache2-data\tapache2\t2.4.62-1~deb12u2\tall\trc \n")}
	p = Collect(context.Background(), h).Packages
	if p.Status != StatusOK || !slices.Equal(p.Value.NotChecked, []string{"apache2-data 2.4.62-1~deb12u2 (config-files)"}) {
		t.Errorf("config-files only: %s %q %q", p.Status, p.Detail, p.Value.NotChecked)
	}
}

// S-251-1: a package whose files are all unpacked (unpacked, half-configured,
// triggers awaited or pending) is checked at the version dpkg records, the
// list partial still; half-installed is not (no version known on the disk).
// S-251-3: a cut list keeps the ones not fully installed, configuration-only
// ones after; the partial detail names 20 at most.
func TestDpkgUnpackedChecked(t *testing.T) {
	out := "bash\t\t5.2.15-2+b7\tarm64\tii \n"
	for i, st := range []string{"iU", "iF", "iW", "it", "hU"} {
		out += fmt.Sprintf("libmid%d\t\t1.%d-1\tarm64\t%s \n", i, i, st)
	}
	h := aptHost()
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte(out + "halfpkg\t\t0.9-1\tarm64\tiH \n")}
	p := Collect(context.Background(), h).Packages
	var names []string
	for _, x := range p.Value.Items {
		names = append(names, x.Name+" "+x.Version)
	}
	if want := []string{"bash 5.2.15-2+b7", "libmid0 1.0-1", "libmid1 1.1-1", "libmid2 1.2-1", "libmid3 1.3-1", "libmid4 1.4-1"}; !slices.Equal(names, want) {
		t.Errorf("checked %q, want %q", names, want)
	}
	if p.Status != StatusPartial || !strings.HasPrefix(p.Detail, "6 package(s) not fully installed: libmid0 1.0-1 (unpacked), libmid1 1.1-1 (half-configured), libmid2 1.2-1 (triggers-awaited), libmid3 1.3-1 (triggers-pending), libmid4 1.4-1 (unpacked), halfpkg 0.9-1 (half-installed, not checked)") ||
		!slices.Equal(p.Value.NotChecked, []string{"halfpkg 0.9-1 (half-installed)"}) {
		t.Errorf("partial %s %q, not checked %q", p.Status, p.Detail, p.Value.NotChecked)
	}
	out = ""
	for i := 1; i <= 21; i++ {
		out += fmt.Sprintf("linux-image-6.1.0-%d-arm64\t\t6.1.%d-1\tarm64\trc \n", i, i)
	}
	for i := 1; i <= 24; i++ {
		out += fmt.Sprintf("libmid%d\t\t1-%d\tarm64\tiU \n", i, i)
	}
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte(out + "halfpkg\t\t0.9-1\tarm64\tiH \n")}
	p = Collect(context.Background(), h).Packages
	if nc := p.Value.NotChecked; len(nc) != 22 || nc[0] != "halfpkg 0.9-1 (half-installed)" || nc[1] != "linux-image-6.1.0-1-arm64 6.1.1-1 (config-files)" {
		t.Errorf("not fully installed first: %q", nc)
	}
	if !strings.HasPrefix(p.Detail, "25 package(s) not fully installed: libmid1 1-1 (unpacked), ") ||
		!strings.HasSuffix(p.Detail, "libmid20 1-20 (unpacked), and 5 more") {
		t.Errorf("partial detail not cut at 20: %q", p.Detail)
	}
}
