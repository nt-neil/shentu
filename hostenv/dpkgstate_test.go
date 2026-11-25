package hostenv

import (
	"context"
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
	if want := []string{"bash", "libssl3", "curl", "libexample1"}; !slices.Equal(names, want) {
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
	_, other := ParseDpkgQueryStates([]byte(dpkgStatesOut + "oddpkg\t\t1-1\tarm64\ti? \n"))
	want := []string{"apache2-data 2.4.62-1~deb12u2 (config-files)", "halfpkg 0.9-1 (half-installed)",
		"unpackedpkg 0.8-1 (unpacked)", "oddpkg 1-1 (state i? not read)"}
	if !slices.Equal(other, want) {
		t.Errorf("not installed in full %q, want %q", other, want)
	}
	h := aptHost()
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte(dpkgStatesOut)}
	p := Collect(context.Background(), h).Packages
	if p.Status != StatusPartial || !strings.Contains(p.Detail, "2 package(s) not fully installed, not checked: halfpkg 0.9-1 (half-installed), unpackedpkg 0.8-1 (unpacked)") {
		t.Errorf("half-installed not said: %s %q", p.Status, p.Detail)
	}
	if len(p.Value.NotChecked) != 3 {
		t.Errorf("not checked %q", p.Value.NotChecked)
	}
	// Only configuration left: listed, the list not partial.
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte("bash\t\t5.2.15-2+b7\tarm64\tii \napache2-data\tapache2\t2.4.62-1~deb12u2\tall\trc \n")}
	p = Collect(context.Background(), h).Packages
	if p.Status != StatusOK || !slices.Equal(p.Value.NotChecked, []string{"apache2-data 2.4.62-1~deb12u2 (config-files)"}) {
		t.Errorf("config-files only: %s %q %q", p.Status, p.Detail, p.Value.NotChecked)
	}
}
