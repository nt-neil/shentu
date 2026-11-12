package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/internal/msrc"
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

// B3: the product comes from the install type, not from the build alone.
func TestMSRCProduct(t *testing.T) {
	for _, c := range []struct {
		p    hostenv.Platform
		want string
	}{
		{hostenv.Platform{Family: "windows-server", Build: "20348.2762"}, "Windows Server 2022"},
		{hostenv.Platform{Family: "windows-server", Build: "26100.2314", ServerCore: true}, "Windows Server 2025 (Server Core installation)"},
		{hostenv.Platform{Family: "windows-server", Build: "25398.1189", ServerCore: true}, "Windows Server 2022, 23H2 Edition (Server Core installation)"},
		{hostenv.Platform{Family: "windows-client", Build: "20348.2762", PrettyName: "Windows 10 Enterprise"}, ""}, // same build, not a server
		{hostenv.Platform{Family: "windows-client", Build: "26100.2314", PrettyName: "Windows 11 Pro"}, ""},
		{hostenv.Platform{Family: "windows-server", Build: "19042.1"}, ""}, // semi-annual channel
		{hostenv.Platform{Build: "17763.1"}, ""}, // install type unknown
	} {
		got, err := msrcProduct(c.p)
		if got != c.want || (c.want == "") != (err != nil) {
			t.Errorf("%+v: %q, %v; want %q", c.p, got, err, c.want)
		}
		if err != nil && !strings.Contains(err.Error(), "cannot tell") {
			t.Errorf("%+v: the error must say it cannot tell: %v", c.p, err)
		}
	}
}

// Windows Server 2019 (build 17763) is best effort: not checked on a real
// host, but its product name, CVRF parsing and comparison path work.
func TestMSRCServer2019(t *testing.T) {
	for _, c := range []struct {
		p    hostenv.Platform
		want string
	}{
		{hostenv.Platform{Family: "windows-server", Build: "17763.6414"}, "Windows Server 2019"},
		{hostenv.Platform{Family: "windows-server", Build: "17763.6414", ServerCore: true}, "Windows Server 2019 (Server Core installation)"},
	} {
		if got, err := msrcProduct(c.p); got != c.want || err != nil {
			t.Fatalf("%+v: %q %v", c.p, got, err)
		}
	}
	doc := `{"ProductTree":{"FullProductName":[{"ProductID":"19","Value":"Windows Server 2019"},` +
		`{"ProductID":"22","Value":"Windows Server 2022"}]},"Vulnerability":[{"CVE":"CVE-2026-1919",` +
		`"Threats":[{"Type":3,"Description":{"Value":"Critical"},"ProductID":["19"]}],` +
		`"Remediations":[{"Type":2,"SubType":"Security Update","Description":{"Value":"5070001"},"ProductID":["19"],"FixedBuild":"10.0.17763.7000"}]}]}`
	prods, err := msrc.ParseCVRF(strings.NewReader(doc), msrc.Server)
	if err != nil || len(prods["Windows Server 2019"]) != 1 {
		t.Fatalf("2019 kept by the parser: %+v %v", prods, err)
	}
	get := func(string) (msrc.Month, error) { return msrc.Month{Products: prods}, nil }
	r, err := msrc.Check("Windows Server 2019", "10.0.17763.6414", nil, []string{"2026-Nov"}, 24, get)
	if err != nil || len(r.Missing) != 1 || r.Missing[0].CVE != "CVE-2026-1919" || r.Missing[0].Severity != "Critical" {
		t.Errorf("an older 2019 build lacks the fix: %+v %v", r, err)
	}
	r, err = msrc.Check("Windows Server 2019", "10.0.17763.7000", nil, []string{"2026-Nov"}, 24, get)
	if err != nil || len(r.Missing) != 0 || r.Current != "2026-Nov" {
		t.Errorf("the fixed 2019 build is current: %+v %v", r, err)
	}
}
