package tools

import "github.com/nt-neil/shentu/detect"

// The code audit's and the vulnerability checks' results as detect's inputs
// (detect.Build). The OS package vulnerabilities come in when the patrol
// step is wired up: PackageVulns gives a summary for the model, not the
// per-advisory list detect needs.

// SurfaceCode is the injection findings of a code audit as code sinks.
func SurfaceCode(fs []CodeFinding) []detect.CodeSink {
	var out []detect.CodeSink
	for _, f := range fs {
		if f.Kind != "injection" || f.Rule == "" {
			continue
		}
		out = append(out, detect.CodeSink{Rule: f.Rule, CWE: f.CWE, Severity: f.Severity, Path: f.Path, Line: f.Line,
			Routes: f.Routes, RoutesTruncated: f.RoutesTruncated})
	}
	return out
}

// SurfaceApps is the vulnerable dependencies of lock files, one entry per
// advisory, marked KEV where the lock file's scan found it exploited. An
// exploited one is kept even when Affected, cut for the model (20 packages,
// 5 advisories each), left it out. Severity stays empty: OSV's batch
// query gives only ids, and asking for each advisory is a request per id;
// detect.Build therefore cuts these before rated entries (KEV ones excepted).
// Each id's CVE is the one OSV gave for it during the KEV check (the
// lowest, when several; all of them go in CVEs), KEV or not, so that Build makes one entry of a
// GHSA id and a PYSEC id of the same vulnerability; the CVE KEV matched is
// used only when OSV gave none. Ids OSV was not asked about (the KEV
// list unavailable, past matchKEV's 300) or that name no CVE stay apart.
func SurfaceApps(rs []AppResult) []detect.PackageVuln {
	var out []detect.PackageVuln
	for _, r := range rs {
		kev := map[string]Exploit{} // package\x00version\x00advisory: two versions in one lock file are two
		key := func(p, v, id string) string { return p + "\x00" + v + "\x00" + id }
		for _, x := range r.Exploited {
			kev[key(x.Package, x.Version, x.ID)] = x
		}
		for _, h := range r.Affected {
			for _, id := range h.IDs {
				v := detect.PackageVuln{Source: r.Path, Ecosystem: r.Ecosystem, Package: h.Package, Version: h.Version, ID: id, CVE: firstCVE(r.cves[id]), CVEs: r.cves[id]}
				if x, ok := kev[key(h.Package, h.Version, id)]; ok {
					v.KEV, v.KEVSince, v.KEVCVE = true, x.Added, x.CVE
					if v.CVE == "" { // OSV's answer, the same rule as for the others; else the CVE KEV matched
						v.CVE = x.CVE
					}
					delete(kev, key(h.Package, h.Version, id))
				}
				out = append(out, v)
			}
		}
		for _, x := range r.Exploited { // in the order found: those Affected no longer lists
			k := key(x.Package, x.Version, x.ID)
			if _, ok := kev[k]; !ok {
				continue
			}
			delete(kev, k)
			cve := firstCVE(r.cves[x.ID])
			if cve == "" {
				cve = x.CVE
			}
			out = append(out, detect.PackageVuln{Source: r.Path, Ecosystem: r.Ecosystem, Package: x.Package, Version: x.Version,
				ID: x.ID, CVE: cve, CVEs: r.cves[x.ID], KEV: true, KEVSince: x.Added, KEVCVE: x.CVE})
		}
	}
	return out
}

// firstCVE is the lowest of an advisory's CVEs, "" for none.
func firstCVE(list []string) string {
	best := ""
	for _, c := range list {
		if best == "" || c < best {
			best = c
		}
	}
	return best
}
