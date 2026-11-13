package tools

import "testing"

func TestMatchKEV(t *testing.T) {
	kev := map[string]kevEntry{
		"CVE-2024-2961": {Name: "glibc iconv", Added: "2024-06-01", Ransomware: "Known"},
		"CVE-2026-1111": {Name: "openssh", Added: "2026-10-01"},
	}
	resolved := map[string][]string{"RLSA-2024:3339": {"CVE-2024-2961", "CVE-2024-33599"}}
	asked := 0
	got, unchecked := matchKEV(kev, []string{"DEBIAN-CVE-2026-1111", "UBUNTU-CVE-2020-0001", "RLSA-2024:3339"}, func(id string) ([]string, bool) {
		asked++
		return resolved[id], true
	})
	if unchecked != 0 {
		t.Errorf("unchecked %d", unchecked)
	}
	if asked != 1 {
		t.Errorf("resolved %d IDs online, want 1 (IDs that contain a CVE need no lookup)", asked)
	}
	if len(got) != 2 || got[0].ID != "DEBIAN-CVE-2026-1111" || got[1].CVE != "CVE-2024-2961" || !got[1].Ransomware {
		t.Errorf("matchKEV = %+v", got)
	}
	// The same CVE under several advisory IDs is one finding.
	got, _ = matchKEV(kev, []string{"CVE-2026-1111", "DEBIAN-CVE-2026-1111", "DLA-4000-1"}, func(string) ([]string, bool) { return []string{"CVE-2026-1111"}, true })
	if len(got) != 1 {
		t.Errorf("one CVE under three IDs gave %d findings: %+v", len(got), got)
	}
	// N-C: a lookup that failed, and IDs past the 300 cap, are counted as unchecked.
	ids := []string{"RLSA-2024:9999"}
	for i := 0; i < 305; i++ {
		ids = append(ids, "CVE-2026-1111")
	}
	_, unchecked = matchKEV(kev, ids, func(string) ([]string, bool) { return nil, false })
	if unchecked != 7 {
		t.Errorf("unchecked %d, want 7 (1 lookup failed, 6 of 306 past the cap)", unchecked)
	}
}

func TestUpgradeHint(t *testing.T) {
	for eco, want := range map[string]string{"Debian:12": "apt-get update && apt-get upgrade", "Ubuntu:24.04:LTS": "apt-get update && apt-get upgrade",
		"Rocky Linux:9": "dnf upgrade --security", "AlmaLinux:9": "dnf upgrade --security", "Alpine:v3.20": "apk upgrade", "Other": ""} {
		if got := upgradeHint(eco); got != want {
			t.Errorf("upgradeHint(%s) = %q", eco, got)
		}
	}
}
