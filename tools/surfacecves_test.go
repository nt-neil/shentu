package tools

import (
	"sync"
	"testing"

	"github.com/nt-neil/shentu/detect"
)

// Final check of #91 (N-B1): with the KEV list unavailable (nothing looked
// up), DSA/USN/RLSA/ALSA entries get their CVEs by lookup; those the
// lookup cannot answer are counted as missing, those OSV gives none are not.
func TestSurfaceCVEsWithoutKEV(t *testing.T) {
	surface := []detect.PackageVuln{
		{ID: "DSA-0000-1"}, {ID: "USN-0000-1"}, {ID: "RLSA-0000:1"}, {ID: "ALSA-0000:1"},
		{ID: "DEBIAN-CVE-2099-0001", CVEs: []string{"CVE-2099-0001"}}, // from its id
		{ID: "DSA-0000-2"}, // lookup fails
		{ID: "USN-0000-2"}, // OSV knows no CVE
		{ID: "DSA-0000-3"}, // looked up by the KEV check
	}
	answers := map[string][]string{"DSA-0000-1": {"CVE-2099-0101"}, "USN-0000-1": {"CVE-2099-0102"}, "RLSA-0000:1": {"CVE-2099-0103"}, "ALSA-0000:1": {"CVE-2099-0104"}, "USN-0000-2": nil}
	var mu sync.Mutex
	memo := map[string][]string{"DSA-0000-3": {"CVE-2099-0105"}}
	asked := map[string]bool{}
	missing := surfaceCVEs(surface, memo, &mu, func(id string) ([]string, bool) {
		mu.Lock()
		asked[id] = true
		mu.Unlock()
		c, ok := answers[id]
		return c, ok
	})
	if missing != 1 {
		t.Errorf("missing %d (want DSA-0000-2 only)", missing)
	}
	for i, want := range []string{"CVE-2099-0101", "CVE-2099-0102", "CVE-2099-0103", "CVE-2099-0104"} {
		if len(surface[i].CVEs) != 1 || surface[i].CVEs[0] != want {
			t.Errorf("%s: %v", surface[i].ID, surface[i].CVEs)
		}
	}
	if asked["DEBIAN-CVE-2099-0001"] || asked["DSA-0000-3"] {
		t.Errorf("asked again: %v", asked)
	}
}
