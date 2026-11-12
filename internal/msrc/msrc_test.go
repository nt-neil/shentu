package msrc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cvrf builds a small CVRF document in MSRC's layout. Each fix is
// "CVE|productID|KB|fixedBuild|severity".
func cvrf(products map[string]string, fixes ...string) string {
	type pn struct{ ProductID, Value string }
	var tree []pn
	for id, name := range products {
		tree = append(tree, pn{id, name})
	}
	var vulns []map[string]any
	for _, f := range fixes {
		p := strings.Split(f, "|")
		vulns = append(vulns, map[string]any{
			"CVE": p[0], "Title": map[string]string{"Value": "title of " + p[0]},
			"Notes": []any{map[string]string{"Value": strings.Repeat("x", 100)}},
			"Threats": []any{map[string]any{"Type": 3, "Description": map[string]string{"Value": p[4]}, "ProductID": []string{p[1]}},
				map[string]any{"Type": 1, "Description": map[string]string{"Value": "ignored"}, "ProductID": []string{p[1]}}},
			"Remediations": []any{
				map[string]any{"Type": 2, "Description": map[string]string{"Value": p[2]}, "ProductID": []string{p[1]}, "FixedBuild": p[3]},
				map[string]any{"Type": 5, "Description": map[string]string{"Value": "workaround"}, "ProductID": []string{p[1]}},
			},
		})
	}
	b, _ := json.Marshal(map[string]any{"DocumentTitle": map[string]string{"Value": "t"}, "ProductTree": map[string]any{
		"Branch": []any{}, "FullProductName": tree}, "Vulnerability": vulns})
	return string(b)
}

var prods = map[string]string{"1": "Windows Server 2022", "2": "Windows Server 2022 (Server Core installation)", "3": "Microsoft Edge"}

func TestParseCVRF(t *testing.T) {
	doc := cvrf(prods, "CVE-1|1|5001|10.0.20348.100|Critical", "CVE-2|2|5001|10.0.20348.100|Important", "CVE-3|3|9999|1.0|Low")
	got, err := ParseCVRF(strings.NewReader(doc), Server)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got["Microsoft Edge"]) != 0 {
		t.Fatalf("only Windows Server products are kept: %+v", got)
	}
	f := got["Windows Server 2022"][0]
	if f != (Fix{CVE: "CVE-1", Title: "title of CVE-1", Severity: "Critical", KB: "5001", FixedBuild: "10.0.20348.100"}) {
		t.Errorf("fix %+v", f)
	}
	bad := `{"Vulnerability":[],"ProductTree":{"FullProductName":[]}}`
	if _, err := ParseCVRF(strings.NewReader(bad), Server); err == nil {
		t.Error("Vulnerability before ProductTree must be refused (it would be dropped)")
	}
	for _, s := range []string{``, `[]`, `{"ProductTree":`, `{"DocumentTitle":{}}`} {
		if _, err := ParseCVRF(strings.NewReader(s), Server); err == nil {
			t.Errorf("%q must be an error", s)
		}
	}
}

func TestCompareBuild(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"10.0.20348.2762", "10.0.20348.2762", 0}, {"10.0.20348.999", "10.0.20348.2762", -1},
		{"10.0.20348.10000", "10.0.20348.2762", 1}, {"10.0.20348", "10.0.20348.1", -1}} {
		if got := CompareBuild(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s: %d", c.a, c.b, got)
		}
	}
}

func TestCheck(t *testing.T) {
	months := map[string]Month{
		"2026-Nov": {Products: map[string][]Fix{"Windows Server 2022": {{CVE: "CVE-N1", KB: "5003", FixedBuild: "10.0.20348.300"}, {CVE: "CVE-N2", KB: "5003", FixedBuild: "10.0.20348.300"}}}},
		"2026-Oct": {Products: map[string][]Fix{"Windows Server 2025": {{CVE: "CVE-X", FixedBuild: "10.0.26100.1"}}}},
		"2026-Sep": {Products: map[string][]Fix{"Windows Server 2022": {{CVE: "CVE-S1", KB: "5002", FixedBuild: "10.0.20348.200"}}}},
		"2026-Aug": {Products: map[string][]Fix{"Windows Server 2022": {{CVE: "CVE-A1", KB: "5001", FixedBuild: "10.0.20348.100"}}}},
		"2026-Jul": {Products: map[string][]Fix{"Windows Server 2022": {{CVE: "CVE-J1", FixedBuild: "10.0.20348.50"}}}},
	}
	ids := []string{"2026-Nov", "2026-Oct", "2026-Sep", "2026-Aug", "2026-Jul"}
	var fetched []string
	get := func(id string) (Month, error) { fetched = append(fetched, id); return months[id], nil }

	r, _ := Check("Windows Server 2022", "10.0.20348.150", nil, ids, 24, get)
	if len(r.Missing) != 3 || r.Current != "2026-Aug" || strings.Join(fetched, ",") != "2026-Nov,2026-Oct,2026-Sep,2026-Aug" {
		t.Errorf("walk stops at the first month the host has: %+v fetched %v", r, fetched)
	}
	r, _ = Check("Windows Server 2022", "10.0.20348.150", map[string]bool{"5003": true}, ids, 24, get)
	if len(r.Missing) != 0 || r.Current != "2026-Nov" {
		t.Errorf("the newest cumulative KB installed: nothing missing: %+v", r)
	}
	r, _ = Check("Windows Server 2022", "10.0.20348.50", map[string]bool{"5002": true}, ids, 24, get)
	if len(r.Missing) != 2 || r.Current != "2026-Sep" {
		t.Errorf("September's KB installed: November's fixes missing: %+v", r)
	}
	r, _ = Check("Windows Server 2022", "10.0.20348.10", nil, ids, 2, get)
	if r.Current != "" || len(r.Months) != 2 {
		t.Errorf("maxMonths bounds the walk: %+v", r)
	}
	_, err := Check("Windows Server 2022", "1", nil, ids, 24, func(string) (Month, error) { return Month{}, fmt.Errorf("offline") })
	if err == nil {
		t.Error("a failed month is an error, not a clean result")
	}
}

func TestClientCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/updates":
			fmt.Fprint(w, `{"value":[{"ID":"2026-Oct","InitialReleaseDate":"2026-10-14T07:00:00Z"},{"ID":"2026-Nov","InitialReleaseDate":"2026-11-11T08:00:00Z"}]}`)
		case "/cvrf/2026-Nov":
			fmt.Fprint(w, cvrf(prods, "CVE-1|1|5001|10.0.20348.100|Critical"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	c := &Client{HTTP: srv.Client(), API: srv.URL, CacheDir: t.TempDir(), Now: func() time.Time { return now }}
	ctx := context.Background()
	ids, err := c.Releases(ctx)
	if err != nil || strings.Join(ids, ",") != "2026-Nov,2026-Oct" {
		t.Fatalf("newest first: %v %v", ids, err)
	}
	m, err := c.Month(ctx, "2026-Nov", true)
	if err != nil || len(m.Products["Windows Server 2022"]) != 1 {
		t.Fatalf("month: %+v %v", m, err)
	}
	before := hits.Load()
	if _, err := c.Releases(ctx); err != nil {
		t.Fatal(err)
	}
	if m2, err := c.Month(ctx, "2026-Nov", true); err != nil || hits.Load() != before || m2.ID != "2026-Nov" {
		t.Errorf("cached release list and month must not refetch: %d → %d, %v", before, hits.Load(), err)
	}
	now = now.Add(8 * 24 * time.Hour) // past the weekly refresh of a recent month
	c.Now = func() time.Time { return now }
	if _, err := c.Month(ctx, "2026-Nov", true); err != nil || hits.Load() == before {
		t.Errorf("a stale recent month is refetched: %v", err)
	}
	if _, err := c.Month(ctx, "2026-Dec", true); err == nil {
		t.Error("HTTP 404 must be an error")
	}
	if _, err := c.Month(ctx, "../../etc", true); err == nil {
		t.Error("a release id with a path in it must be refused")
	}
}

// N9: a CVE with a cumulative update and a hotpatch (as Server 2022 and
// 2025 have in MSRC's 2025-Mar release) is covered by either.
func TestCheckAnyFixCovers(t *testing.T) {
	m := Month{Products: map[string][]Fix{"Windows Server 2022": {
		{CVE: "CVE-2024-9157", KB: "5053603", FixedBuild: "10.0.20348.3328"},                 // Security Update
		{CVE: "CVE-2024-9157", KB: "5053638", FixedBuild: "10.0.20348.3270", Hotpatch: true}, // SecurityHotpatchUpdate
	}}}
	get := func(string) (Month, error) { return m, nil }
	r, err := Check("Windows Server 2022", "10.0.20348.3270", nil, []string{"2025-Mar"}, 24, get)
	if err != nil || len(r.Missing) != 0 || r.Current != "2025-Mar" {
		t.Errorf("a hotpatched host has the fix: %+v %v", r, err)
	}
	r, _ = Check("Windows Server 2022", "10.0.20348.3207", nil, []string{"2025-Mar"}, 24, get)
	if len(r.Missing) != 1 || r.Missing[0].KB != "5053603" {
		t.Errorf("one missing CVE, reported with its cumulative update: %+v", r.Missing)
	}
	// A cumulative-chain build past the hotpatch's number is not the hotpatch.
	r, _ = Check("Windows Server 2022", "10.0.20348.3300", nil, []string{"2025-Mar"}, 24, get)
	if len(r.Missing) != 1 {
		t.Errorf("a hotpatch build counts only exactly or by its KB: %+v", r.Missing)
	}
	r, _ = Check("Windows Server 2022", "10.0.20348.3300", map[string]bool{"5053638": true}, []string{"2025-Mar"}, 24, get)
	if len(r.Missing) != 0 {
		t.Errorf("the installed hotpatch KB covers it: %+v", r.Missing)
	}
}

func TestParseCVRFHotpatch(t *testing.T) {
	doc := `{"ProductTree":{"FullProductName":[{"ProductID":"1","Value":"Windows Server 2025"}]},"Vulnerability":[{"CVE":"CVE-1",` +
		`"Remediations":[{"Type":2,"SubType":"Security Update","Description":{"Value":"5053598"},"ProductID":["1"],"FixedBuild":"10.0.26100.3476"},` +
		`{"Type":2,"SubType":"SecurityHotpatchUpdate","Description":{"Value":"5053636"},"ProductID":["1"],"FixedBuild":"10.0.26100.3403"}]}]}`
	got, err := ParseCVRF(strings.NewReader(doc), Server)
	if err != nil {
		t.Fatal(err)
	}
	f := got["Windows Server 2025"]
	if len(f) != 2 || f[0].Hotpatch || !f[1].Hotpatch {
		t.Errorf("hotpatch marked from SubType: %+v", f)
	}
}

// N7: no checked release names the product: unknown, not "nothing missing".
func TestCheckProductNeverNamed(t *testing.T) {
	get := func(string) (Month, error) {
		return Month{Products: map[string][]Fix{"Windows Server 2025": {{CVE: "CVE-1", FixedBuild: "10.0.26100.1"}}}}, nil
	}
	if r, err := Check("Windows Server 2019", "10.0.17763.1", nil, []string{"a", "b"}, 24, get); err == nil || len(r.Missing) != 0 {
		t.Errorf("a product no release names must be an error: %+v %v", r, err)
	}
}

// N13: the cache never creates the state directory it lives in.
func TestCacheNeedsStateDir(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, cvrf(prods, "CVE-1|1|5001|10.0.20348.100|Critical"))
	}))
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "state") // not made
	c := &Client{HTTP: srv.Client(), API: srv.URL, CacheDir: filepath.Join(state, "cache")}
	if _, err := c.Month(context.Background(), "2026-Nov", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("the cache created the state directory: %v", err)
	}
}

// Round 2: a CVE listed with a hotpatch alone is judged, on a host off the
// hotpatch, by the month's cumulative update; without one it cannot be told.
func TestCheckHotpatchOnlyCVE(t *testing.T) {
	month := Month{Products: map[string][]Fix{"Windows Server 2025": {
		{CVE: "CVE-CU", KB: "5070001", FixedBuild: "10.0.26100.4000"},
		{CVE: "CVE-HP", KB: "5070002", FixedBuild: "10.0.26100.3900", Hotpatch: true},
	}}}
	get := func(string) (Month, error) { return month, nil }
	r, _ := Check("Windows Server 2025", "10.0.26100.4000", nil, []string{"m"}, 24, get)
	if len(r.Missing) != 0 || len(r.CannotTell) != 0 || r.Current != "m" {
		t.Errorf("the month's CU covers the hotpatch-only CVE: %+v", r)
	}
	r, _ = Check("Windows Server 2025", "10.0.26100.3950", nil, []string{"m"}, 24, get)
	if len(r.Missing) != 2 {
		t.Errorf("below the CU, both are missing: %+v", r.Missing)
	}
	// Round 3 (S1): the fix to install is the month's cumulative update,
	// for the hotpatch-only CVE too; a host short of it cannot take the
	// hotpatch.
	for _, m := range r.Missing {
		if m.KB != "5070001" || m.Hotpatch {
			t.Errorf("%s: advises KB%s (hotpatch %v), want the CU KB5070001", m.CVE, m.KB, m.Hotpatch)
		}
	}
	// Round 3 re-review (N-2): only the KB and build come from the CU; the
	// CVE keeps its own title and severity.
	sev := Month{Products: map[string][]Fix{"Windows Server 2025": {
		{CVE: "CVE-CU", Title: "Low thing", Severity: "Low", KB: "5070001", FixedBuild: "10.0.26100.4000"},
		{CVE: "CVE-HP", Title: "Critical thing", Severity: "Critical", KB: "5070002", FixedBuild: "10.0.26100.3900", Hotpatch: true},
	}}}
	r, _ = Check("Windows Server 2025", "10.0.26100.3950", nil, []string{"m"}, 24, func(string) (Month, error) { return sev, nil })
	for _, m := range r.Missing {
		if m.CVE == "CVE-HP" && (m.Severity != "Critical" || m.Title != "Critical thing" || m.KB != "5070001" || m.FixedBuild != "10.0.26100.4000" || m.Hotpatch) {
			t.Errorf("hotpatch-only CVE reported as %+v", m)
		}
	}
	// A CVE listing both: the CU is reported even when the hotpatch's
	// build number sorts higher.
	both := Month{Products: map[string][]Fix{"Windows Server 2025": {
		{CVE: "CVE-X", KB: "5070003", FixedBuild: "10.0.26100.4100", Hotpatch: true},
		{CVE: "CVE-X", KB: "5070001", FixedBuild: "10.0.26100.4000"},
	}}}
	r, _ = Check("Windows Server 2025", "10.0.26100.3950", nil, []string{"m"}, 24, func(string) (Month, error) { return both, nil })
	if len(r.Missing) != 1 || r.Missing[0].KB != "5070001" || r.Missing[0].CVE != "CVE-X" {
		t.Errorf("CU and hotpatch: %+v", r.Missing)
	}
	only := Month{Products: map[string][]Fix{"Windows Server 2025": {{CVE: "CVE-HP", KB: "5070002", FixedBuild: "10.0.26100.3900", Hotpatch: true}}}}
	r, _ = Check("Windows Server 2025", "10.0.26100.4000", nil, []string{"m"}, 24, func(string) (Month, error) { return only, nil })
	if len(r.Missing) != 0 || len(r.CannotTell) != 1 || r.Current != "" {
		t.Errorf("no CU in the month: cannot tell, not missing, not current: %+v", r)
	}
}
