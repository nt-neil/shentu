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

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/hostenv"
)

var packageVulns = Tool{
	Name: "package_vulns",
	Description: "Checks installed OS packages against the OSV vulnerability database (online, api.osv.dev) and marks vulnerabilities that CISA lists as actively exploited (KEV); fix those first. Without arguments returns affected packages, vulnerability IDs and the exploited ones; with package set, returns the summary, severity and fixed version of that package's vulnerabilities. " +
		"partial says what could not be checked (an advisory feed or topic that failed): those packages may have fixes pending. ecosystems_not_queried lists ecosystems the host may have that OSV does not carry; ecosystems lists every one queried when there are several (SUSE). kev_unchecked counts vulnerabilities not checked against KEV (lookups failed, or over 300 for one package): exploited ones among them are not marked. " +
		"packages_not_checked lists packages the package manager knows but that were not checked, with their state: half-installed or a state not read (no version known to be on the disk), then config-files (only their configuration left); the first 20, packages_not_checked_more counts the rest. Packages not fully installed (unpacked, half-configured...) are checked at the version recorded, and named in partial.",
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

// osvMaxPages is how many pages of advisories (1000 each) one package is
// read to; past it the rest are said not checked.
const osvMaxPages = 10

// PackageVulns queries OSV for every installed package.
func PackageVulns(ctx context.Context, hc *http.Client, detailFor string) (map[string]any, error) {
	out, _, err := packageVulnsAll(ctx, hc, detailFor)
	return out, err
}

// PackageVulnsSurface is PackageVulns' overview, and every affected
// installed package's advisories as the vulnerability surface's entries
// (attack detection, plan 0743f0 P5): the list the overview cuts for the
// model, whole.
func PackageVulnsSurface(ctx context.Context, hc *http.Client) (map[string]any, []detect.PackageVuln, error) {
	return packageVulnsAll(ctx, hc, surfaceDetail)
}

// surfaceDetail is packageVulnsAll's detailFor for the surface: no package's
// detail, and every entry's CVEs looked up (surfaceCVEs).
const surfaceDetail = "\x00surface"

// surfaceCVELookups bounds the advisories looked up for their CVEs past the
// KEV check (KEV unavailable, or past its 300 per package).
const surfaceCVELookups = 3000

// maxNotChecked is how many packages_not_checked lists; the rest are counted.
const maxNotChecked = 20

func packageVulnsAll(ctx context.Context, hc *http.Client, detailFor string) (map[string]any, []detect.PackageVuln, error) {
	forSurface := detailFor == surfaceDetail
	if forSurface {
		detailFor = ""
	}
	switch hostSource().Info().GOOS { // the host read, so a fixture of another OS is checked as that OS
	case "windows":
		out, err := msrcVulns(ctx, hc, cacheDir, winSource())
		surface, note := phpWinSurface(ctx, hc) // php-cgi under Apache: CVE-2024-4577, CVE-2024-8926
		if note != "" && out != nil {
			out["php_cgi"] = note
		}
		return out, surface, err
	case "darwin":
		out, err := macOSVulns(ctx, hc)
		return out, nil, err
	}
	eco, feed, set, setPartial, err := installedSet(ctx)
	if err != nil {
		return nil, nil, err
	}
	items := set.Items
	pkgs := pkgsOf(items)
	if len(pkgs) == 0 { // a package list that parsed to nothing is not "no vulnerabilities"
		return nil, nil, fmt.Errorf("cannot tell: no installed packages were read from the %s package list", eco)
	}
	type affected struct {
		Package string   `json:"package"`
		Version string   `json:"version"`
		IDs     []string `json:"ids"`
	}
	var found []affected
	var advisories map[string]hostenv.Advisory // ALAS id -> advisory (Amazon Linux)
	partial := ""                              // what could not be checked
	total := 0
	switch feed.Kind {
	case "alas":
		plat, _ := hostPlatform()
		hits, advs, failed, err := alasAffected(ctx, hc, feed, hostenv.RPMArch(plat.Arch), items)
		if len(failed) > 0 {
			partial = "not checked, so their packages may have fixes pending: " + strings.Join(failed, "; ")
		}
		if err != nil {
			if errors.Is(err, errCacheDropped) {
				return nil, nil, fmt.Errorf("Amazon Linux security advisories (ALAS): a damaged cached copy was dropped; the next run fetches it again: %w", err)
			}
			return nil, nil, fmt.Errorf("Amazon Linux security advisories (ALAS) unavailable (is the server online?): %w", err)
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
			Version   string `json:"version"`
			PageToken string `json:"page_token,omitempty"`
		}
		at := map[string]int{} // package -> index in found (SLES asks one ecosystem per module)
		var cut []string       // packages OSV had more pages for than are read
		for _, e := range feed.Ecosystems {
			for start := 0; start < len(pkgs); start += 500 {
				chunk := pkgs[start:min(start+500, len(pkgs))]
				qs := make([]query, len(chunk))
				idx := make([]int, len(chunk)) // query -> its package in chunk
				for i, p := range chunk {
					qs[i].Package.Name, qs[i].Package.Ecosystem, qs[i].Version = p.Name, e, feed.FeedVersion(p.Version)
					idx[i] = i
				}
				// OSV gives at most 1000 advisories a query (the kernel has
				// more): the rest come on the pages its next_page_token names,
				// asked again until none is left.
				for page := 0; len(qs) > 0; page++ {
					if page == osvMaxPages {
						for _, i := range idx {
							cut = append(cut, chunk[i].Name)
						}
						break
					}
					var resp struct {
						Results []struct {
							Vulns []struct {
								ID string `json:"id"`
							} `json:"vulns"`
							NextPageToken string `json:"next_page_token"`
						} `json:"results"`
					}
					if err := postJSON(ctx, hc, osvAPI+"/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
						return nil, nil, fmt.Errorf("OSV query failed (is the server online?): %w", err)
					}
					var nqs []query
					var nidx []int
					for i, r := range resp.Results {
						if i >= len(qs) {
							continue
						}
						c := chunk[idx[i]]
						if r.NextPageToken != "" {
							q := qs[i]
							q.PageToken = r.NextPageToken
							nqs, nidx = append(nqs, q), append(nidx, idx[i])
						}
						if len(r.Vulns) == 0 {
							continue
						}
						k, ok := at[c.Name]
						if !ok {
							k = len(found)
							at[c.Name] = k
							found = append(found, affected{Package: c.Name, Version: c.Version})
						}
						for _, v := range r.Vulns {
							if !slices.Contains(found[k].IDs, v.ID) {
								found[k].IDs = append(found[k].IDs, v.ID)
								total++
							}
						}
					}
					qs, idx = nqs, nidx
				}
			}
		}
		if len(cut) > 0 {
			slices.Sort(cut)
			partial = strings.TrimPrefix(partial+"; "+fmt.Sprintf("OSV listed more than %d pages of advisories for %s: the rest not checked", osvMaxPages, strings.Join(slices.Compact(cut), ", ")), "; ")
		}
	}
	out := map[string]any{"ecosystem": eco, "packages_checked": len(pkgs), "affected_packages": len(found), "total_vulns": total}
	if setPartial != "" { // the package list was read in part: those packages are not checked either
		partial = strings.TrimPrefix(partial+"; package list: "+setPartial, "; ")
	}
	if partial != "" {
		out["partial"] = partial
	}
	if len(feed.NotQueried) > 0 {
		out["ecosystems_not_queried"] = feed.NotQueried
	}
	if feed.Note != "" {
		out["ecosystems_note"] = feed.Note
	}
	if len(set.NotChecked) > 0 { // known to the package manager, not installed in full: not checked, said
		nc := set.NotChecked
		if len(nc) > maxNotChecked { // a long-run host may keep dozens of config-files (old kernels)
			out["packages_not_checked_more"] = len(nc) - maxNotChecked
			nc = nc[:maxNotChecked]
		}
		out["packages_not_checked"] = nc
	}
	up, upWhy := upstreamCompare(ctx, set) // third-party PHP and nginx, against php.net's and nginx.org's advisories
	thirdPartyOut(out, set, up, upWhy)
	if len(feed.Ecosystems) > 1 { // SUSE: one per module; ecosystem shows the first only
		out["ecosystems"] = feed.Ecosystems
	}
	hint := feed.Upgrade
	if hint == "" {
		hint = upgradeHint(eco)
	}
	if hint != "" {
		out["upgrade_command"] = hint
	}
	cvesOf := func(id string) ([]string, bool) { return osvCVEs(ctx, hc, id) }
	if advisories != nil {
		cvesOf = func(id string) ([]string, bool) { return advisories[id].CVEs, true }
	}
	// What the KEV check looks up is kept for the surface's entries: their
	// advisories (DSA-, USN-, RLSA-, ALAS) name their CVEs only there.
	var cveMu sync.Mutex
	cveMemo := map[string][]string{}
	lookup := cvesOf
	cvesOf = func(id string) ([]string, bool) {
		c, ok := lookup(id)
		if ok {
			cveMu.Lock()
			cveMemo[id] = c
			cveMu.Unlock()
		}
		return c, ok
	}
	// The upstream hits, counted in the summary every reader goes by (the
	// patrol, the report, the model) as OSV's are: by source package and CVE.
	// The binaries of one source (php8.3-fpm, -cli) are one affected package,
	// as OSV names them, and a CVE OSV already reports for that source (also
	// as an advisory's alias, a DSA's CVE) is not counted again.
	ups := upstreamBySource(up)
	osvHas := map[srcCVE]bool{}
	inFound := map[string]bool{}
	for _, a := range found {
		inFound[a.Package] = true
		if !ups.sources[a.Package] {
			continue
		}
		for _, id := range a.IDs {
			cves := cveRe.FindAllString(strings.ToUpper(id), -1)
			if len(cves) == 0 {
				cves, _ = cvesOf(id)
				cves, _ = releaseCVEs(id, cves, a.IDs)
			}
			for _, c := range cves {
				osvHas[srcCVE{a.Package, c}] = true
			}
		}
	}
	newSources := map[string]bool{}
	for _, k := range ups.order {
		if !osvHas[k] {
			total++
			if !inFound[k.src] {
				newSources[k.src] = true
			}
		}
	}
	out["total_vulns"], out["affected_packages"] = total, len(found)+len(newSources)
	exploited := map[string][]Exploit{} // package -> KEV matches
	kev, kevErr := loadKEV(ctx, hc)     // kept for the upstream entries of the surface
	if err := kevErr; err != nil {
		out["kev"] = "CISA KEV list unavailable: " + err.Error()
	} else {
		var all []Exploit
		unchecked := 0
		var unsureMu sync.Mutex
		var unsure []string // USNs whose CVEs could not be told to apply here
		for _, a := range found {
			ids := a.IDs
			list, n := matchKEV(kev, ids, func(id string) ([]string, bool) {
				c, ok := cvesOf(id)
				c, u := releaseCVEs(id, c, ids) // a USN's CVEs of other releases are not this host's
				if u {
					unsureMu.Lock()
					unsure = append(unsure, id)
					unsureMu.Unlock()
					return nil, false // not checked against KEV: counted in kev_unchecked
				}
				return c, ok
			})
			unchecked += n
			for _, e := range list {
				e.Package, e.Version = a.Package, a.Version
				exploited[a.Package] = append(exploited[a.Package], e)
				all = append(all, e)
			}
		}
		// Upstream's, as OSV's (the patrol's KEV alert reads this list): one
		// per source package and CVE, naming the binaries; OSV's own entry
		// for it, when there is one, gets them instead of a second entry.
		for _, k := range ups.order {
			e, ok := kev[k.cve]
			if !ok {
				continue
			}
			if i := slices.IndexFunc(all, func(x Exploit) bool { return x.Package == k.src && x.CVE == k.cve }); i >= 0 {
				all[i].Binaries = ups.binaries[k]
				continue
			}
			all = append(all, Exploit{Package: k.src, Version: ups.version[k.src], ID: k.cve, CVE: k.cve, Name: e.Name, Added: e.Added,
				Ransomware: e.Ransomware == "Known", Binaries: ups.binaries[k]})
		}
		out["actively_exploited"] = all
		switch {
		case unchecked > 0:
			out["kev_unchecked"] = unchecked
			out["kev"] = fmt.Sprintf("%d vulnerabilities could not be checked against the CISA KEV list (their CVEs could not be looked up, or over 300 for one package): exploited ones among them are not marked", unchecked)
			if len(unsure) > 0 {
				slices.Sort(unsure)
				out["kev"] = out["kev"].(string) + fmt.Sprintf("; for %s, whether its CVEs apply to this release could not be told (the package has no CVE-named advisory to tell by)", strings.Join(slices.Compact(unsure), ", "))
			}
		case len(all) == 0:
			out["kev"] = "none of these vulnerabilities is on the CISA KEV list of actively exploited vulnerabilities"
		}
	}
	// The surface's entries: every affected package's every advisory, in the
	// ecosystem a signature's range names (OSV's Debian:12, Red Hat...).
	osEco := eco
	if len(feed.Ecosystems) > 0 {
		osEco = feed.Ecosystems[0]
	}
	if feed.Kind == "alas" {
		osEco = "Amazon Linux"
	}
	var surface []detect.PackageVuln
	for _, a := range found {
		for _, id := range a.IDs {
			v := detect.PackageVuln{Source: "os", Ecosystem: osEco, Package: a.Package, Version: a.Version, ID: id}
			// Its CVEs: in the id (CVE-, DEBIAN-CVE-, UBUNTU-CVE-), else as
			// the KEV check looked them up (an ALAS advisory's, OSV's
			// aliases); a signature written for a CVE finds the entry.
			v.CVEs = cveRe.FindAllString(strings.ToUpper(id), -1)
			if len(v.CVEs) == 0 {
				cveMu.Lock()
				v.CVEs = cveMemo[id] // a USN's: this release's kept below
				cveMu.Unlock()
				if v.CVEs == nil && advisories != nil {
					v.CVEs = advisories[id].CVEs
				}
			}
			for _, e := range exploited[a.Package] {
				if e.ID == id {
					v.KEV, v.KEVSince, v.KEVCVE = true, e.Added, e.CVE
					if v.CVE == "" {
						v.CVE = e.CVE
					}
				}
			}
			surface = append(surface, v)
		}
	}
	surface = append(surface, upstreamSurface(up, kev)...)
	missing := 0
	if forSurface {
		// The KEV check did not look up every advisory's CVEs (the list
		// unavailable, or past 300 for one package): those it did not,
		// looked up now; those still unknown are said.
		missing = surfaceCVEs(surface, cveMemo, &cveMu, lookup)
	}
	// A USN's CVEs, from the KEV check or the lookup just made, are every
	// release's: this release's kept, as for KEV (N-258-1); a USN that
	// cannot tell is missing.
	idsOf := map[string][]string{}
	for _, a := range found {
		idsOf[a.Package] = a.IDs
	}
	for i := range surface {
		if v := &surface[i]; v.Source == "os" && strings.HasPrefix(v.ID, "USN-") {
			var u bool
			if v.CVEs, u = releaseCVEs(v.ID, v.CVEs, idsOf[v.Package]); u {
				missing++
			}
		}
	}
	if forSurface && missing > 0 {
		out["surface_cves_missing"] = missing
	}
	for i := range surface {
		if v := &surface[i]; v.CVE == "" && len(v.CVEs) > 0 {
			v.CVE = v.CVEs[0]
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
		return out, surface, nil
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
	return out, surface, nil
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
	// Binaries are the installed packages of Package (a source package) the
	// upstream compare found affected (php8.3-fpm, php8.3-cli).
	Binaries []string `json:"binaries,omitempty"`
}

// surfaceCVEs fills the CVEs of surface's entries neither their id nor
// the KEV check (memo) gave, by lookup, at most surfaceCVELookups, 8 at a
// time; it gives how many are left without (lookup failed, or past it).
// An advisory OSV knows no CVE for is not missing.
func surfaceCVEs(surface []detect.PackageVuln, memo map[string][]string, mu *sync.Mutex, lookup func(string) ([]string, bool)) (missing int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	var cnt sync.Mutex
	asked := 0
	for i := range surface {
		v := &surface[i]
		if len(v.CVEs) > 0 || v.KEVCVE != "" {
			continue
		}
		mu.Lock()
		_, done := memo[v.ID]
		mu.Unlock()
		if done {
			continue
		}
		if asked++; asked > surfaceCVELookups {
			cnt.Lock()
			missing++
			cnt.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			c, ok := lookup(v.ID)
			if !ok {
				cnt.Lock()
				missing++
				cnt.Unlock()
				return
			}
			v.CVEs = c
		}()
	}
	wg.Wait()
	return missing
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
func matchKEV(kev map[string]kevEntry, ids []string, cves func(id string) ([]string, bool)) (found []Exploit, unchecked int) {
	var mu sync.Mutex
	var out []Exploit
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	if len(ids) > 300 { // past the cap, not looked up: said, never taken as "not exploited"
		unchecked = len(ids) - 300
		ids = ids[:300]
	}
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			list := cveRe.FindAllString(id, -1)
			if len(list) == 0 {
				sem <- struct{}{}
				var ok bool
				list, ok = cves(id)
				<-sem
				if !ok {
					mu.Lock()
					unchecked++
					mu.Unlock()
				}
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
	return uniq, unchecked
}

// releaseCVEs are the CVEs of advisory id that apply to the host's release.
// A USN covers every Ubuntu release it fixed, and its aliases name CVEs only
// some of them have (USN-7980-1 names CVE-2025-11187, which OSV has for
// 25.10 and 26.04, not 24.04): of a USN, only the CVEs OSV also lists for
// this package, as UBUNTU-CVE-... or the CVE itself (ids, the package's
// advisories), are kept. A CVE of another release is never marked
// exploited on this host. Other advisories are per release already.
//
// unsure: the package has no CVE-named advisory to tell by, so none of the
// USN's CVEs is known to apply (nor kept: that would bring other releases'
// back); the caller says so.
func releaseCVEs(id string, cves, ids []string) (out []string, unsure bool) {
	if !strings.HasPrefix(id, "USN-") {
		return cves, false
	}
	has := map[string]bool{}
	for _, x := range ids {
		for _, c := range cveRe.FindAllString(strings.ToUpper(x), -1) {
			has[c] = true
		}
	}
	if len(has) == 0 {
		return nil, len(cves) > 0
	}
	for _, c := range cves {
		if has[c] {
			out = append(out, c)
		}
	}
	return out, false
}

// osvCVEs returns the CVEs an OSV advisory covers (aliases and upstream).
// osvCVEs is the CVEs an OSV id stands for; ok is false when OSV could not
// be asked (offline, rate limited), which is not "no CVE".
func osvCVEs(ctx context.Context, hc *http.Client, id string) ([]string, bool) {
	var v struct {
		Aliases  []string `json:"aliases"`
		Upstream []string `json:"upstream"`
	}
	if getJSON(ctx, hc, osvAPI+"/vulns/"+id, &v) != nil {
		return nil, false
	}
	return cveRe.FindAllString(strings.Join(append(v.Aliases, v.Upstream...), " "), -1), true
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
	eco, feed, set, _, err := installedSet(ctx)
	if err != nil {
		return "", feed, nil, err
	}
	return eco, feed, pkgsOf(set.Items), nil
}

// pkgsOf names each item as the security feed does (dpkg's source
// package), one per name and version.
func pkgsOf(items []hostenv.Package) []pkg {
	var pkgs []pkg
	for _, p := range items {
		pkgs = append(pkgs, pkg{sourceOf(p), p.Version})
	}
	return uniq(pkgs)
}

// installedSet is the package fact as collected: every item (several
// versions of one name, with their architecture) and the feed (with the
// amazon-linux-extras topics on Amazon Linux 2).
func installedSet(ctx context.Context) (string, hostenv.PatchFeed, hostenv.PackageSet, string, error) {
	_, osr := hostPlatform()
	id, ver := osr["ID"], osr["VERSION_ID"]
	feed := hostenv.PatchFeedFor(osr)
	if feed.Kind == "" {
		if id == "amzn" {
			return "", feed, hostenv.PackageSet{}, "", errors.New("cannot tell: Amazon Linux " + ver + " is past its end of life and has no security feed here")
		}
		return "", feed, hostenv.PackageSet{}, "", errors.New("unsupported distribution for package_vulns: " + id + " " + ver)
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
		return "", feed, hostenv.PackageSet{}, "", fmt.Errorf("%s: %s", cmd, set.Detail)
	}
	if set.Value.Feed != nil {
		feed = *set.Value.Feed
	}
	partial := "" // what the package list itself could not read (e.g. amzn2-extras.repo)
	if set.Status == hostenv.StatusPartial {
		partial = set.Detail
	}
	return eco, feed, set.Value, partial, nil
}

// thirdPartyOut names the packages that came from a repository other than
// the distribution's. OSV publishes the distribution's packages only, so
// these were compared as if the distribution had built them and matched
// nothing: that silence is not "no vulnerabilities", and says so.
func thirdPartyOut(out map[string]any, set hostenv.PackageSet, up []upstreamHit, why map[string]string) {
	type thirdParty struct {
		Package string `json:"package"`
		Version string `json:"version"`
		Origin  string `json:"origin"`
		FoundBy string `json:"found_by"`
		Why     string `json:"why,omitempty"` // a PHP or nginx package not compared with its upstream: why
	}
	compared := map[string]bool{}
	for _, h := range up {
		compared[h.Package] = true
	}
	var tp []thirdParty
	for _, it := range set.Items {
		if it.Origin != "" && !compared[it.Name] {
			tp = append(tp, thirdParty{it.Name, it.Version, it.Origin, it.OriginBy, why[it.Name]})
		}
	}
	if len(up) > 0 {
		out["third_party_upstream"] = up
	}
	if len(tp) > 0 {
		out["third_party_unchecked"] = tp
		out["third_party_note"] = fmt.Sprintf("%d package(s) came from other repositories than the distribution's; OSV does not cover them, so they were not checked against their own advisories", len(tp))
	}
	if len(set.ThirdParty) > 0 {
		out["third_party_repositories"] = set.ThirdParty
		if len(tp) == 0 {
			out["third_party_note"] = "third-party repositories are configured, but which packages they installed is unknown: those packages were checked as the distribution's own, and may not be covered"
		}
	}
	if len(set.OriginNotes) > 0 {
		out["origin_unread"] = set.OriginNotes
	}
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
