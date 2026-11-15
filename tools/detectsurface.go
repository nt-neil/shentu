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
		out = append(out, detect.CodeSink{Rule: f.Rule, CWE: f.CWE, Severity: f.Severity, Path: f.Path, Line: f.Line, Routes: f.Routes})
	}
	return out
}

// SurfaceApps is the vulnerable dependencies of lock files, one entry per
// advisory, marked KEV where the lock file's scan found it exploited.
func SurfaceApps(rs []AppResult) []detect.PackageVuln {
	var out []detect.PackageVuln
	for _, r := range rs {
		kev := map[string]Exploit{} // package\x00advisory
		for _, x := range r.Exploited {
			kev[x.Package+"\x00"+x.ID] = x
		}
		for _, h := range r.Affected {
			for _, id := range h.IDs {
				v := detect.PackageVuln{Source: r.Path, Ecosystem: r.Ecosystem, Package: h.Package, Version: h.Version, ID: id}
				if x, ok := kev[h.Package+"\x00"+id]; ok {
					v.KEV, v.KEVSince, v.CVE = true, x.Added, x.CVE
				}
				out = append(out, v)
			}
		}
	}
	return out
}
