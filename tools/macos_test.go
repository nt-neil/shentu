package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

func TestMacOSVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"PublicAssetSets":{"macOS":[{"ProductVersion":"27.2.1"},{"ProductVersion":"26.7.3"},{"ProductVersion":"27.2"},{"ProductVersion":"14.8.9"}]}}`))
	}))
	defer srv.Close()
	old := appleUpdatesURL
	appleUpdatesURL = srv.URL
	t.Cleanup(func() { appleUpdatesURL = old })
	rp, err := hostenv.LoadReplay("../hostenv/testdata/darwin/macos27-synthetic-user")
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
	out, err := PackageVulns(context.Background(), srv.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	if out["os_up_to_date"] != false || out["latest_in_major"] != "27.2.1" || !strings.HasPrefix(out["packages"].(string), "cannot tell: ") {
		t.Errorf("macOS 27.2: %v", out)
	}
	for v, want := range map[string]int{"27.2.1|27.2": 1, "27.2|27.2.0": 0, "9.1|10.0": -1, "|1": -1} {
		a, b, _ := strings.Cut(v, "|")
		if got := compareVersions(a, b); got != want {
			t.Errorf("compareVersions(%q, %q) = %d", a, b, got)
		}
	}
}

// A macOS newer than every release Apple lists (a beta) is cannot tell, never
// "upgrade to" an older one.
func TestMacOSBetaIsCannotTell(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"PublicAssetSets":{"macOS":[{"ProductVersion":"26.7.3"},{"ProductVersion":"25.9"}]}}`))
	}))
	defer srv.Close()
	old := appleUpdatesURL
	appleUpdatesURL = srv.URL
	t.Cleanup(func() { appleUpdatesURL = old })
	rp, err := hostenv.LoadReplay("../hostenv/testdata/darwin/macos27-synthetic-user")
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
	out, err := PackageVulns(context.Background(), srv.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := out["os_updates"].(string); !strings.HasPrefix(s, "cannot tell") || strings.Contains(s, "upgrade to") || out["os_up_to_date"] != nil {
		t.Errorf("beta: %v", out)
	}
}

// An empty update list is cannot tell, never "upgrade to macOS 0".
func TestMacOSEmptyListCannotTell(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"PublicAssetSets":{"macOS":[]}}`))
	}))
	defer srv.Close()
	old := appleUpdatesURL
	appleUpdatesURL = srv.URL
	t.Cleanup(func() { appleUpdatesURL = old })
	rp, err := hostenv.LoadReplay("../hostenv/testdata/darwin/macos27-synthetic-user")
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
	out, err := PackageVulns(context.Background(), srv.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := out["os_updates"].(string); !strings.HasPrefix(s, "cannot tell") || out["os_up_to_date"] != nil {
		t.Errorf("empty list: %v", out)
	}
}
