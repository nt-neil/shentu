package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/nt-neil/shentu/hostenv"
)

var packageVulns = Tool{
	Name:        "package_vulns",
	Description: "Checks installed OS packages against the OSV vulnerability database (online, api.osv.dev) and marks vulnerabilities that CISA lists as actively exploited (KEV); fix those first. Without arguments returns affected packages, vulnerability IDs and the exploited ones; with package set, returns the summary, severity and fixed version of that package's vulnerabilities.",
	Params: schema(`{"type":"object","properties":{
		"package":{"type":"string","description":"show details for this package"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			Package string `json:"package"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		return PackageVulns(ctx, env.HTTP, a.Package)
	},
}

type pkg struct{ Name, Version string }

const osvAPI = "https://api.osv.dev/v1"

// PackageVulns queries OSV for every installed package.
func PackageVulns(ctx context.Context, hc *http.Client, detailFor string) (map[string]any, error) {
	eco, feed, pkgs, err := installedPackages(ctx)
	if err != nil {
		return nil, err
	}
	type affected struct {
		Package string   `json:"package"`
		Version string   `json:"version"`
		IDs     []string `json:"ids"`
	}
	var found []affected
	var advisories map[string]hostenv.Advisory // ALAS id -> advisory (Amazon Linux)
	total := 0
	switch feed.Kind {
	case "alas":
		plat, _ := hostPlatform()
		hits, advs, err := alasAffected(ctx, hc, feed.Release, hostenv.RPMArch(plat.Arch), pkgs)
		if err != nil {
			return nil, fmt.Errorf("Amazon Linux security advisories (ALAS) unavailable (is the server online?): %w", err)
		}
		advisories = advs
		for _, h := range hits {
			total += len(h.IDs)
			found = append(found, affected(h))
		}
	default:
		type query struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version string `json:"version"`
		}
		at := map[string]int{} // package -> index in found (SLES asks one ecosystem per module)
		for _, e := range feed.Ecosystems {
			for start := 0; start < len(pkgs); start += 500 {
				chunk := pkgs[start:min(start+500, len(pkgs))]
				qs := make([]query, len(chunk))
				for i, p := range chunk {
					qs[i].Package.Name, qs[i].Package.Ecosystem, qs[i].Version = p.Name, e, feed.FeedVersion(p.Version)
				}
				var resp struct {
					Results []struct {
						Vulns []struct {
							ID string `json:"id"`
						} `json:"vulns"`
					} `json:"results"`
				}
				if err := postJSON(ctx, hc, osvAPI+"/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
					return nil, fmt.Errorf("OSV query failed (is the server online?): %w", err)
				}
				for i, r := range resp.Results {
					if len(r.Vulns) == 0 || i >= len(chunk) {
						continue
					}
					k, ok := at[chunk[i].Name]
					if !ok {
						k = len(found)
						at[chunk[i].Name] = k
						found = append(found, affected{Package: chunk[i].Name, Version: chunk[i].Version})
					}
					for _, v := range r.Vulns {
						if !slices.Contains(found[k].IDs, v.ID) {
							found[k].IDs = append(found[k].IDs, v.ID)
							total++
						}
					}
				}
			}
		}
	}
	out := map[string]any{"ecosystem": eco, "packages_checked": len(pkgs), "affected_packages": len(found), "total_vulns": total}
	hint := feed.Upgrade
	if hint == "" {
		hint = upgradeHint(eco)
	}
	if hint != "" {
		out["upgrade_command"] = hint
	}
	cvesOf := func(id string) []string { return osvCVEs(ctx, hc, id) }
	if advisories != nil {
		cvesOf = func(id string) []string { return advisories[id].CVEs }
	}
	exploited := map[string][]Exploit{} // package -> KEV matches
	if kev, err := loadKEV(ctx, hc); err != nil {
		out["kev"] = "CISA KEV list unavailable: " + err.Error()
	} else {
		var all []Exploit
		for _, a := range found {
			for _, e := range matchKEV(kev, a.IDs, cvesOf) {
				e.Package, e.Version = a.Package, a.Version
				exploited[a.Package] = append(exploited[a.Package], e)
				all = append(all, e)
			}
		}
		out["actively_exploited"] = all
		if len(all) == 0 {
			out["kev"] = "none of these vulnerabilities is on the CISA KEV list of actively exploited vulnerabilities"
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		ei, ej := len(exploited[found[i].Package]), len(exploited[found[j].Package])
		if ei != ej {
			return ei > ej
		}
		return len(found[i].IDs) > len(found[j].IDs)
	})
	known := false
	for _, a := range found {
		known = known || a.Package == detailFor
	}
	if detailFor != "" && !known {
		// A wrong name (models send "*" or a binary name) gets the overview, not an empty answer.
		out["note"] = fmt.Sprintf("no affected package is named %q; this is the overview", detailFor)
		detailFor = ""
	}
	if detailFor == "" {
		// Counts and a few IDs keep the overview small enough for small local models.
		type row struct {
			Package string   `json:"package"`
			Version string   `json:"version"`
			Count   int      `json:"vulns"`
			Sample  []string `json:"sample_ids"`
			Exploit int      `json:"actively_exploited,omitempty"`
		}
		var rows []row
		for i, a := range found {
			if i >= 20 {
				out["top"] = "only the 20 packages with the most vulnerabilities are listed; call again with package set for details"
				break
			}
			rows = append(rows, row{a.Package, a.Version, len(a.IDs), a.IDs[:min(3, len(a.IDs))], len(exploited[a.Package])})
		}
		out["affected"] = rows
		return out, nil
	}
	type detail struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity any    `json:"severity,omitempty"`
		Fixed    string `json:"fixed_version,omitempty"`
		Exploit  string `json:"actively_exploited,omitempty"`
	}
	var details []detail
	for _, a := range found {
		if a.Package != detailFor {
			continue
		}
		for i, id := range a.IDs {
			if i >= 20 {
				break
			}
			if adv, ok := advisories[id]; ok { // ALAS: not in OSV; the advisory itself says it
				d := detail{ID: id, Summary: strings.Join(adv.CVEs, ", "), Severity: adv.Severity, Fixed: adv.Fixed[a.Package]}
				for _, e := range exploited[a.Package] {
					if e.ID == id {
						d.Exploit = e.CVE + ": " + e.Name + " (CISA KEV since " + e.Added + ")"
					}
				}
				details = append(details, d)
				continue
			}
			var v struct {
				Summary  string `json:"summary"`
				Details  string `json:"details"`
				Severity any    `json:"severity"`
				Affected []struct {
					Ranges []struct {
						Events []map[string]string `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			}
			if err := getJSON(ctx, hc, osvAPI+"/vulns/"+id, &v); err != nil {
				details = append(details, detail{ID: id, Summary: "details unavailable: " + err.Error()})
				continue
			}
			d := detail{ID: id, Summary: v.Summary, Severity: v.Severity}
			for _, e := range exploited[a.Package] {
				if e.ID == id {
					d.Exploit = e.CVE + ": " + e.Name + " (CISA KEV since " + e.Added + ")"
				}
			}
			if d.Summary == "" {
				d.Summary = firstLine(v.Details, 200)
			}
			for _, af := range v.Affected {
				for _, r := range af.Ranges {
					for _, e := range r.Events {
						if f := e["fixed"]; f != "" {
							d.Fixed = f
						}
					}
				}
			}
			details = append(details, d)
		}
	}
	out["package"] = detailFor
	out["vulns"] = details
	return out, nil
}

// kevURL is CISA's catalog of vulnerabilities known to be exploited in the wild.
var kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevEntry struct {
	Name       string `json:"vulnerabilityName"`
	Added      string `json:"dateAdded"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

// Exploit is an installed package vulnerability that CISA lists as exploited in the wild.
type Exploit struct {
	Package    string `json:"package"`
	Version    string `json:"version"`
	ID         string `json:"id"`
	CVE        string `json:"cve"`
	Name       string `json:"name"`
	Added      string `json:"kev_since"`
	Ransomware bool   `json:"used_by_ransomware,omitempty"`
}

func loadKEV(ctx context.Context, hc *http.Client) (map[string]kevEntry, error) {
	var feed struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
			kevEntry
		} `json:"vulnerabilities"`
	}
	if err := getJSON(ctx, hc, kevURL, &feed); err != nil {
		return nil, err
	}
	m := make(map[string]kevEntry, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		m[v.CVE] = v.kevEntry
	}
	return m, nil
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// matchKEV returns the KEV entries for ids. Debian and Ubuntu IDs contain the CVE;
// others (RLSA, ALSA) are resolved with cves, concurrently and at most 300 of them.
func matchKEV(kev map[string]kevEntry, ids []string, cves func(id string) []string) []Exploit {
	var mu sync.Mutex
	var out []Exploit
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, id := range ids {
		if i >= 300 {
			break
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			list := cveRe.FindAllString(id, -1)
			if len(list) == 0 {
				sem <- struct{}{}
				list = cves(id)
				<-sem
			}
			for _, c := range list {
				if e, ok := kev[c]; ok {
					mu.Lock()
					out = append(out, Exploit{ID: id, CVE: c, Name: e.Name, Added: e.Added, Ransomware: e.Ransomware == "Known"})
					mu.Unlock()
				}
			}
		}(id)
	}
	wg.Wait()
	// One CVE often has several advisory IDs (DSA, DLA, DEBIAN-CVE, the CVE itself): report it once.
	sort.Slice(out, func(i, j int) bool { return out[i].ID+out[i].CVE < out[j].ID+out[j].CVE })
	seen := map[string]bool{}
	var uniq []Exploit
	for _, e := range out {
		if !seen[e.CVE] {
			seen[e.CVE] = true
			uniq = append(uniq, e)
		}
	}
	return uniq
}

// osvCVEs returns the CVEs an OSV advisory covers (aliases and upstream).
func osvCVEs(ctx context.Context, hc *http.Client, id string) []string {
	var v struct {
		Aliases  []string `json:"aliases"`
		Upstream []string `json:"upstream"`
	}
	if getJSON(ctx, hc, osvAPI+"/vulns/"+id, &v) != nil {
		return nil
	}
	return cveRe.FindAllString(strings.Join(append(v.Aliases, v.Upstream...), " "), -1)
}

func upgradeHint(eco string) string {
	switch {
	case strings.HasPrefix(eco, "Debian"), strings.HasPrefix(eco, "Ubuntu"):
		return "apt-get update && apt-get upgrade"
	case strings.HasPrefix(eco, "Rocky"), strings.HasPrefix(eco, "AlmaLinux"):
		return "dnf upgrade --security"
	case strings.HasPrefix(eco, "Alpine"):
		return "apk upgrade"
	}
	return ""
}

// installedPackages lists packages from hostenv's packages fact, named as
// the distribution's security feed names them (dpkg's source packages, apk
// origins, rpm names), duplicates dropped, order kept, and the feed: OSV
// (Debian, Ubuntu, Alpine, Rocky, Alma, SUSE, openSUSE) or ALAS (Amazon
// Linux). eco names the distribution in the result.
func installedPackages(ctx context.Context) (string, hostenv.PatchFeed, []pkg, error) {
	_, osr := hostPlatform()
	id, ver := osr["ID"], osr["VERSION_ID"]
	feed := hostenv.PatchFeedFor(osr)
	if feed.Kind == "" {
		return "", feed, nil, errors.New("unsupported distribution for package_vulns: " + id + " " + ver)
	}
	eco := ""
	if len(feed.Ecosystems) > 0 {
		eco = feed.Ecosystems[0]
	}
	if feed.Kind == "alas" {
		eco = "Amazon Linux " + feed.Release
	}
	set := linux.Packages(ctx, hostSource(), osr)
	if !set.Known() {
		cmd := map[string]string{"dpkg": "dpkg-query", "rpm": "rpm", "apk": "/lib/apk/db/installed"}[set.Value.Manager]
		if cmd == "" {
			cmd = "packages"
		}
		return "", feed, nil, fmt.Errorf("%s: %s", cmd, set.Detail)
	}
	var pkgs []pkg
	for _, p := range set.Value.Items {
		name := p.Name
		if p.Source != "" {
			name = p.Source
		}
		pkgs = append(pkgs, pkg{name, p.Version})
	}
	return eco, feed, uniq(pkgs), nil
}

func uniq(in []pkg) []pkg {
	seen := map[pkg]bool{}
	var out []pkg
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func firstLine(s string, n int) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return Cut(s, n)
}

func postJSON(ctx context.Context, hc *http.Client, url string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doJSON(hc, req, out)
}

func getJSON(ctx context.Context, hc *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	return doJSON(hc, req, out)
}

func doJSON(hc *http.Client, req *http.Request, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
