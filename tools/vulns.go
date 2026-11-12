package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
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
	eco, pkgs, err := installedPackages(ctx)
	if err != nil {
		return nil, err
	}
	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	type affected struct {
		Package string   `json:"package"`
		Version string   `json:"version"`
		IDs     []string `json:"ids"`
	}
	var found []affected
	total := 0
	for start := 0; start < len(pkgs); start += 500 {
		chunk := pkgs[start:min(start+500, len(pkgs))]
		qs := make([]query, len(chunk))
		for i, p := range chunk {
			qs[i].Package.Name, qs[i].Package.Ecosystem, qs[i].Version = p.Name, eco, p.Version
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
			a := affected{Package: chunk[i].Name, Version: chunk[i].Version}
			for _, v := range r.Vulns {
				a.IDs = append(a.IDs, v.ID)
			}
			total += len(a.IDs)
			found = append(found, a)
		}
	}
	out := map[string]any{"ecosystem": eco, "packages_checked": len(pkgs), "affected_packages": len(found), "total_vulns": total}
	if hint := upgradeHint(eco); hint != "" {
		out["upgrade_command"] = hint
	}
	exploited := map[string][]Exploit{} // package -> KEV matches
	if kev, err := loadKEV(ctx, hc); err != nil {
		out["kev"] = "CISA KEV list unavailable: " + err.Error()
	} else {
		var all []Exploit
		for _, a := range found {
			for _, e := range matchKEV(kev, a.IDs, func(id string) []string { return osvCVEs(ctx, hc, id) }) {
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

// installedPackages detects the distro and lists packages in OSV naming.
func installedPackages(ctx context.Context) (string, []pkg, error) {
	_, osr := hostPlatform()
	id, ver := osr["ID"], osr["VERSION_ID"]
	switch id {
	case "ubuntu", "debian":
		eco := "Debian:" + strings.Split(ver, ".")[0]
		if id == "ubuntu" {
			eco = "Ubuntu:" + ver
			if strings.Contains(osr["VERSION"], "LTS") {
				eco += ":LTS"
			}
		}
		// OSV Debian/Ubuntu advisories use source package names.
		out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${source:Package}\t${Version}\t${db:Status-Abbrev}\n").Output()
		if err != nil {
			return "", nil, fmt.Errorf("dpkg-query: %w", err)
		}
		return eco, uniq(parseTSV(string(out), func(f []string) bool { return len(f) > 2 && strings.HasPrefix(f[2], "ii") })), nil
	case "alpine":
		parts := strings.Split(ver, ".")
		eco := "Alpine:v" + strings.Join(parts[:min(2, len(parts))], ".")
		b, err := os.ReadFile("/lib/apk/db/installed")
		if err != nil {
			return "", nil, err
		}
		var pkgs []pkg
		var name, version, origin string
		for _, l := range strings.Split(string(b)+"\n", "\n") {
			switch {
			case strings.HasPrefix(l, "P:"):
				name = l[2:]
			case strings.HasPrefix(l, "V:"):
				version = l[2:]
			case strings.HasPrefix(l, "o:"):
				origin = l[2:]
			case l == "":
				if origin == "" {
					origin = name
				}
				if origin != "" {
					pkgs = append(pkgs, pkg{origin, version})
				}
				name, version, origin = "", "", ""
			}
		}
		return eco, uniq(pkgs), nil
	case "rocky", "almalinux":
		eco := map[string]string{"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}[id] + ":" + strings.Split(ver, ".")[0]
		out, err := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n").Output()
		if err != nil {
			return "", nil, fmt.Errorf("rpm: %w", err)
		}
		return eco, uniq(parseTSV(string(out), nil)), nil
	}
	return "", nil, errors.New("unsupported distribution for package_vulns: " + id + " " + ver)
}

func parseTSV(s string, keep func([]string) bool) []pkg {
	var out []pkg
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 2 || f[0] == "" || (keep != nil && !keep(f)) {
			continue
		}
		out = append(out, pkg{f[0], f[1]})
	}
	return out
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
