package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// month is a CVRF document with Windows Server 2022 fixes "CVE|KB|build|severity".
func month(fixes ...[4]string) string {
	var vulns []any
	for _, f := range fixes {
		vulns = append(vulns, map[string]any{"CVE": f[0], "Title": map[string]string{"Value": f[0] + " title"},
			"Threats":      []any{map[string]any{"Type": 3, "Description": map[string]string{"Value": f[3]}, "ProductID": []string{"9"}}},
			"Remediations": []any{map[string]any{"Type": 2, "Description": map[string]string{"Value": f[1]}, "ProductID": []string{"9"}, "FixedBuild": f[2]}}})
	}
	b, _ := json.Marshal(map[string]any{"ProductTree": map[string]any{"FullProductName": []any{
		map[string]string{"ProductID": "9", "Value": "Windows Server 2022"}}}, "Vulnerability": vulns})
	return string(b)
}

func TestMSRCVulns(t *testing.T) {
	// The recorded windows-2022 runner: build 20348.5773, KB5127693 installed.
	src, err := hostenv.LoadReplay("../hostenv/testdata/windows/server2022-admin")
	if err != nil {
		t.Fatal(err)
	}
	novKB := "5999999"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/updates":
			fmt.Fprint(w, `{"value":[{"ID":"2026-Oct","InitialReleaseDate":"2026-10-14T00:00:00Z"},{"ID":"2026-Nov","InitialReleaseDate":"2026-11-11T00:00:00Z"}]}`)
		case "/cvrf/2026-Nov":
			fmt.Fprint(w, month([4]string{"CVE-2026-1111", novKB, "10.0.20348.9000", "Important"},
				[4]string{"CVE-2026-2222", novKB, "10.0.20348.9000", "Critical"}))
		case "/cvrf/2026-Oct":
			fmt.Fprint(w, month([4]string{"CVE-2026-0001", "5127693", "10.0.20348.5000", "Critical"}))
		case "/kev":
			fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"CVE-2026-1111","vulnerabilityName":"Win EoP","dateAdded":"2026-11-12","knownRansomwareCampaignUse":"Known"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldAPI, oldKEV := msrcAPI, kevURL
	msrcAPI, kevURL = srv.URL, srv.URL+"/kev"
	t.Cleanup(func() { msrcAPI, kevURL = oldAPI, oldKEV })

	out, err := msrcVulns(context.Background(), srv.Client(), t.TempDir(), src)
	if err != nil {
		t.Fatal(err)
	}
	if out["product"] != "Windows Server 2022" || out["host_build"] != "10.0.20348.5773" || out["missing_fixes"] != 2 || out["current_with"] != "2026-Oct" {
		t.Errorf("summary: %+v", out)
	}
	ex := out["actively_exploited"].([]Exploit)
	if len(ex) != 1 || ex[0].CVE != "CVE-2026-1111" || !ex[0].Ransomware {
		t.Errorf("KEV: %+v", ex)
	}
	b, _ := json.Marshal(out["missing"])
	var list []struct{ CVE string }
	json.Unmarshal(b, &list)
	if len(list) != 2 || list[0].CVE != "CVE-2026-1111" || list[1].CVE != "CVE-2026-2222" {
		t.Errorf("exploited first, then by severity: %s", b)
	}

	novKB = "5127693" // November's KB is the one the runner has installed
	out, err = msrcVulns(context.Background(), srv.Client(), t.TempDir(), src)
	if err != nil || out["missing_fixes"] != 0 || out["current_with"] != "2026-Nov" {
		t.Errorf("installed KB covers the month: %+v %v", out, err)
	}

	msrcAPI = srv.URL + "/down"
	if _, err := msrcVulns(context.Background(), srv.Client(), "", src); err == nil {
		t.Error("MSRC unreachable must be an error, not an empty result")
	}
}
