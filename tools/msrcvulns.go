package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/internal/msrc"
)

// cacheDir holds downloaded vulnerability data (the MSRC index) under the
// state directory; empty means no cache. Set by SetCacheDir.
var cacheDir string

// SetCacheDir sets where vulnerability data is cached.
func SetCacheDir(dir string) { cacheDir = dir }

// msrcAPI overrides msrc.DefaultAPI (tests).
var msrcAPI string

// msrcMaxMonths bounds the walk back through monthly releases.
const msrcMaxMonths = 24

// msrcListed caps the CVEs listed by name; counts cover the rest.
const msrcListed = 40

// msrcVulns is package_vulns on Windows Server: the OS build against
// MSRC's monthly releases, with CISA KEV marking the exploited CVEs.
// Third-party software is not covered (MSRC lists Microsoft products only).
func msrcVulns(ctx context.Context, hc *http.Client, cacheDir string, src hostenv.Source) (map[string]any, error) {
	plat, patches := hostenv.WindowsCollector{}.PatchLevel(src)
	if !plat.Known() {
		return nil, fmt.Errorf("Windows version unknown: %s", plat.Detail)
	}
	p := plat.Value
	name := hostenv.WindowsServerName(p.Build)
	if name == "" || !strings.Contains(p.Build, ".") {
		return nil, errors.New("package_vulns covers Windows Server 2016 and later; this build is " + p.Build)
	}
	product := name
	if p.ServerCore {
		product += " (Server Core installation)"
	}
	kbs := map[string]bool{}
	for _, x := range patches.Value {
		kbs[strings.TrimPrefix(strings.ToUpper(x.ID), "KB")] = true
	}
	// A monthly CVRF document is ~30 MB: allow it more than the 30 s the
	// shared client gives an API call (the context still bounds it).
	c := &msrc.Client{HTTP: &http.Client{Transport: hc.Transport, Timeout: 5 * time.Minute}, API: msrcAPI, CacheDir: cacheDir}
	ids, err := c.Releases(ctx)
	if err != nil {
		return nil, fmt.Errorf("MSRC release list unavailable (is the server online?): %w", err)
	}
	n := 0
	res, err := msrc.Check(product, "10.0."+p.Build, kbs, ids, msrcMaxMonths, func(id string) (msrc.Month, error) {
		n++
		return c.Month(ctx, id, n <= 2)
	})
	if err != nil {
		return nil, fmt.Errorf("MSRC data unavailable: %w", err)
	}
	out := map[string]any{"source": "MSRC security update guide (CVRF)", "product": product, "host_build": res.HostBuild,
		"months_checked": res.Months, "missing_fixes": len(res.Missing)}
	switch {
	case res.Current != "":
		out["current_with"] = res.Current
	case len(res.Months) >= msrcMaxMonths:
		out["note"] = fmt.Sprintf("this server lacks fixes from every one of the last %d monthly releases; it may be missing older ones too", msrcMaxMonths)
	}
	if !patches.Known() {
		out["patches"] = "installed KBs unknown (" + patches.Detail + "); judged by the OS build alone"
	}
	if len(res.Missing) > 0 {
		out["update_command"] = "install the latest cumulative update (Settings > Windows Update, or WSUS / your patch tool)"
	}
	sev := map[string]int{}
	for _, m := range res.Missing {
		sev[m.Severity]++
	}
	out["by_severity"] = sev

	var exploited []Exploit
	kev, kerr := loadKEV(ctx, hc)
	if kerr != nil {
		out["kev"] = "CISA KEV list unavailable: " + kerr.Error()
	}
	rank := func(m msrc.Missing) int {
		r := map[string]int{"Critical": 1, "Important": 2, "Moderate": 3, "Low": 4}[m.Severity]
		if r == 0 {
			r = 5
		}
		if _, ok := kev[m.CVE]; ok {
			r = 0
		}
		return r
	}
	sort.SliceStable(res.Missing, func(i, j int) bool { return rank(res.Missing[i]) < rank(res.Missing[j]) })
	for _, m := range res.Missing {
		if e, ok := kev[m.CVE]; ok {
			exploited = append(exploited, Exploit{Package: product, Version: res.HostBuild, ID: m.CVE, CVE: m.CVE, Name: e.Name, Added: e.Added,
				Ransomware: e.Ransomware == "Known"})
		}
	}
	if kerr == nil {
		out["actively_exploited"] = exploited
		if len(exploited) == 0 {
			out["kev"] = "none of the missing fixes is on the CISA KEV list of actively exploited vulnerabilities"
		}
	}
	type listed struct {
		CVE, Severity, KB, FixedIn, Month, Title string
	}
	var list []listed
	for _, m := range res.Missing[:min(len(res.Missing), msrcListed)] {
		list = append(list, listed{m.CVE, m.Severity, "KB" + m.KB, m.FixedBuild, m.Month, Cut(m.Title, 120)})
	}
	out["missing"] = list
	return out, nil
}
