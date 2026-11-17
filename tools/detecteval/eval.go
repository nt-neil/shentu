package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/rules/engine"
)

// Stats is what an evaluation comes to: counts, rule ids and template ids,
// never a request.
type Stats struct {
	NucleiCommit   string                `json:"nuclei_commit"`
	TemplatesHash  string                `json:"templates_hash"`
	Templates      int                   `json:"templates"`       // http/**/*.yaml
	NotConverted   int                   `json:"not_converted"`   // no request a log keeps could be made of it
	Unclassified   int                   `json:"unclassified"`    // converted, its tags name no payload class: not in the rates
	RCEUnspecified int                   `json:"rce_unspecified"` // converted, tagged rce, no tag or CWE says what it carries: not in the rates
	Classes        map[string]*ClassStat `json:"classes"`
	AttackLevels   map[string]int        `json:"attack_levels"` // per classified template, its best level
	Host           HostStat              `json:"host"`
	NormalRequests int                   `json:"normal_requests"`
	FalsePositives int                   `json:"false_positives"`
	NormalLevels   map[string]int        `json:"normal_levels"`
	FalseHits      []string              `json:"false_positive_ids,omitempty"` // request id: signature ids
	GradedHash     string                `json:"graded_sha256"`
}

// ClassStat: of the templates of a class, how many a signature of that
// class caught (in any of its requests).
type ClassStat struct {
	Templates int `json:"templates"`
	Caught    int `json:"caught"`
}

// HostStat is the layer "a real vulnerability of this host": the host has
// the packages of hostCases at their vulnerable versions, and nothing else.
type HostStat struct {
	Cases           int `json:"cases"`              // hostCases read
	TemplatesForCVE int `json:"templates_for_cves"` // templates naming one of the cases' CVEs
	Alerted         int `json:"alerted"`            // templates with a candidate of the host's (a package vulnerability)
	AlertedForCVE   int `json:"alerted_for_cves"`   // of those, templates naming one of the cases' CVEs
	NormalAlerted   int `json:"normal_alerted"`     // ordinary requests with such a candidate
	VersionUnknown  int `json:"version_unknown"`    // alerted templates with a candidate whose version could not be compared
}

var classCWE = map[string]string{"sqli": "CWE-89", "cmdi": "CWE-78", "path": "CWE-22", "ssrf": "CWE-918", "xss": "CWE-79",
	"deser": "CWE-502", "xxe": "CWE-611", "code": "CWE-94", "nosqli": "CWE-943", "ldapi": "CWE-90", "xpathi": "CWE-643", "redirect": "CWE-601", "upload": "CWE-434"}

var levelRank = map[string]int{"none": 0, "noise": 1, "unanchored": 2, "L1": 3, "L2": 4}

type evaluator struct {
	sigs   []sig.Signature
	m      *detect.Matcher
	parser *detect.Parser
	host   *detect.Judge
	hostCV map[string]bool
	cases  int // hostCases read
}

func newEvaluator(repo string) (*evaluator, int, error) {
	ss, err := sig.Load()
	if err != nil {
		return nil, 0, err
	}
	p, err := detect.ApacheParser(`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`)
	if err != nil {
		return nil, 0, err
	}
	pkgs, cves, err := hostPackages(repo)
	if err != nil {
		return nil, 0, err
	}
	return &evaluator{sigs: ss, m: detect.NewMatcher(ss), parser: p, host: detect.NewJudge(detect.Build(nil, pkgs), ss), hostCV: cves, cases: len(pkgs)}, len(pkgs), nil
}

// hostPackages reads hostCases.
func hostPackages(repo string) ([]detect.PackageVuln, map[string]bool, error) {
	eco := map[string]string{"composer": "Packagist", "npm": "npm", "pypi": "PyPI", "wordpress-plugin": "WordPress"}
	var out []detect.PackageVuln
	cves := map[string]bool{}
	for _, c := range hostCases {
		var x struct{ ID, Ecosystem, Package, Vulnerable string }
		if _, err := toml.DecodeFile(filepath.Join(repo, "bench", c+".toml"), &x); err != nil {
			return nil, nil, fmt.Errorf("host case %s: %v", c, err)
		}
		if r, ok := registryName[x.Ecosystem+":"+x.Package]; ok {
			x.Ecosystem, x.Package = r.Ecosystem, r.Package
		}
		e, ok := eco[x.Ecosystem]
		if !ok || x.ID == "" || x.Package == "" || x.Vulnerable == "" {
			return nil, nil, fmt.Errorf("host case %s: ecosystem %q, package %q, version %q", c, x.Ecosystem, x.Package, x.Vulnerable)
		}
		id := strings.ToUpper(x.ID)
		out = append(out, detect.PackageVuln{Source: "eval", Ecosystem: e, Package: x.Package, Version: x.Vulnerable, ID: id, CVE: id})
		cves[id] = true
	}
	return out, cves, nil
}

// graded is what one line came to.
type graded struct {
	sigs           map[string][]string // class -> signature ids
	level          string              // on a surface with a sink of every class at its path
	hostAlert      bool                // a package candidate of the host's
	hostWhy        []string            // those candidates: entry level via signatures
	versionUnknown bool                // one of them has its version not known
	parsed         bool
}

func (ev *evaluator) grade(line string) graded {
	g := graded{sigs: map[string][]string{}, level: "none"}
	rec, ok := ev.parser.Parse([]byte(line))
	if !ok {
		return g
	}
	g.parsed = true
	q := detect.Normalize(rec)
	res := ev.m.Match(q)
	for _, h := range res.Hits {
		g.sigs[h.Class] = append(g.sigs[h.Class], h.Signature)
	}
	// A sink of every class at this request's own path: its level is what
	// it would be on a host vulnerable there.
	var sinks []detect.CodeSink
	for c, cwe := range classCWE {
		sinks = append(sinks, detect.CodeSink{Rule: "eval-" + c, CWE: cwe, Path: "eval/" + c, Line: 1,
			Routes: []engine.RouteRef{{Model: "eval", Framework: "eval", Pattern: strings.ToLower(q.Path), File: "eval", Line: 1}}})
	}
	j := detect.NewJudge(detect.Build(sinks, nil), ev.sigs)
	jd := j.Judge(res)
	switch {
	case len(jd.Candidates) > 0:
		g.level = jd.Candidates[0].Level
		for _, c := range jd.Candidates[1:] {
			if levelRank[c.Level] > levelRank[g.level] {
				g.level = c.Level
			}
		}
	case len(jd.Unanchored) > 0:
		g.level = "unanchored"
	case len(jd.Noise) > 0:
		g.level = "noise"
	}
	for _, c := range ev.host.Judge(res).Candidates {
		var ids []string
		for _, h := range c.Hits {
			ids = append(ids, h.Signature)
		}
		w := c.Entry + " " + c.Level + " via " + strings.Join(ids, ",")
		if c.VersionUnknown {
			w += " (version unknown)"
			g.versionUnknown = true
		}
		g.hostWhy = append(g.hostWhy, w)
	}
	g.hostAlert = len(g.hostWhy) > 0
	return g
}

// run evaluates the templates and the ordinary requests.
func (ev *evaluator) run(files map[string][]byte, normal []normalRequest) *Stats {
	st := &Stats{NucleiCommit: templatesCommit, TemplatesHash: manifestHash(files), Templates: len(files),
		Classes: map[string]*ClassStat{}, AttackLevels: map[string]int{}, NormalLevels: map[string]int{}}
	st.Host.Cases = ev.cases
	var lines []string // what the graded hash is of
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a, err := convert(n, files[n])
		if err != nil {
			st.NotConverted++
			lines = append(lines, n+"\tnot-converted")
			continue
		}
		level, caught, host, vu, parsed := "none", false, false, false, 0
		hit := map[string]bool{}
		for _, t := range a.Lines {
			g := ev.grade(logLine(t))
			if !g.parsed {
				continue
			}
			parsed++
			if levelRank[g.level] > levelRank[level] {
				level = g.level
			}
			for c, ids := range g.sigs {
				if c == a.Class {
					caught = true
				}
				for _, id := range ids {
					hit[id] = true
				}
			}
			host = host || g.hostAlert
			vu = vu || g.versionUnknown
		}
		if parsed == 0 {
			st.NotConverted++
			lines = append(lines, n+"\tnot-converted")
			continue
		}
		forCVE := false
		for _, c := range a.CVEs {
			forCVE = forCVE || ev.hostCV[c]
		}
		if forCVE {
			st.Host.TemplatesForCVE++
		}
		if vu {
			st.Host.VersionUnknown++
		}
		if host {
			st.Host.Alerted++
			if forCVE {
				st.Host.AlertedForCVE++
			}
		}
		switch a.Class {
		case "":
			st.Unclassified++
		case rceUnspecified:
			st.RCEUnspecified++
		default:
			cs := st.Classes[a.Class]
			if cs == nil {
				cs = &ClassStat{}
				st.Classes[a.Class] = cs
			}
			cs.Templates++
			if caught {
				cs.Caught++
			}
			st.AttackLevels[level]++
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%v\t%s\t%s\t%v\t%v\t%v", n, a.ID, a.Class, caught, sortedKeys(hit), level, host, forCVE, vu))
	}
	st.NormalRequests = len(normal)
	for _, r := range normal {
		g := ev.grade(r.Line)
		if !g.parsed {
			lines = append(lines, r.ID+"\tnot-parsed")
			continue
		}
		var fp []string
		for c, ids := range g.sigs {
			if c != "scanner" {
				fp = append(fp, ids...)
			}
		}
		sort.Strings(fp)
		if len(fp) > 0 {
			st.FalsePositives++
			st.FalseHits = append(st.FalseHits, r.ID+": "+strings.Join(fp, ","))
		}
		st.NormalLevels[g.level]++
		if g.hostAlert {
			st.Host.NormalAlerted++
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%v", r.ID, strings.Join(fp, ","), g.level, g.hostAlert))
	}
	lines = append(lines, fmt.Sprintf("host\t%+v", st.Host))
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	st.GradedHash = hex.EncodeToString(h[:])
	return st
}

func sortedKeys(m map[string]bool) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

// report prints the stats.
func report(st *Stats) {
	fmt.Printf("nuclei-templates %s, http templates %d (hash %s)\n", st.NucleiCommit, st.Templates, st.TemplatesHash)
	fmt.Printf("not converted %d, unclassified %d, rce unspecified %d (not in the rates)\n", st.NotConverted, st.Unclassified, st.RCEUnspecified)
	fmt.Println("detection by class (templates caught by a signature of their class):")
	cls := make([]string, 0, len(st.Classes))
	for c := range st.Classes {
		cls = append(cls, c)
	}
	sort.Strings(cls)
	tot, caught := 0, 0
	for _, c := range cls {
		s := st.Classes[c]
		tot += s.Templates
		caught += s.Caught
		fmt.Printf("  %-9s %5d / %5d  %5.1f%%\n", c, s.Caught, s.Templates, pct(s.Caught, s.Templates))
	}
	fmt.Printf("  %-9s %5d / %5d  %5.1f%%\n", "all", caught, tot, pct(caught, tot))
	fmt.Printf("attack levels: %s\n", levels(st.AttackLevels))
	fmt.Printf("false positives: %d / %d ordinary requests (%.2f%%)\n", st.FalsePositives, st.NormalRequests, pct(st.FalsePositives, st.NormalRequests))
	for _, f := range st.FalseHits {
		fmt.Printf("  %s\n", f)
	}
	fmt.Printf("normal levels: %s\n", levels(st.NormalLevels))
	fmt.Printf("host layer (%d cvebench cases): templates naming their CVEs %d; templates alerted %d (of them naming the CVEs %d); ordinary requests alerted %d; version unknown %d\n",
		st.Host.Cases, st.Host.TemplatesForCVE, st.Host.Alerted, st.Host.AlertedForCVE, st.Host.NormalAlerted, st.Host.VersionUnknown)
	fmt.Printf("graded sha256 %s\n", st.GradedHash)
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

func levels(m map[string]int) string {
	var out []string
	for _, l := range []string{"L2", "L1", "unanchored", "noise", "none"} {
		out = append(out, fmt.Sprintf("%s %d", l, m[l]))
	}
	return strings.Join(out, ", ")
}

// explainHost says, for each template naming one of the host's CVEs or
// alerting in the host layer, what it came to: ids and reasons, never a
// request.
func (ev *evaluator) explainHost(files map[string][]byte) {
	sigFor := map[string][]string{} // CVE -> signatures written for it
	for _, x := range ev.sigs {
		for _, c := range x.CVEs {
			sigFor[strings.ToUpper(c)] = append(sigFor[strings.ToUpper(c)], x.ID)
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a, err := convert(n, files[n])
		var host []string
		for _, c := range a.CVEs {
			if ev.hostCV[c] {
				host = append(host, c)
			}
		}
		var why, hits []string
		methods := map[string]bool{}
		hit := map[string]bool{}
		for _, t := range a.Lines {
			methods[t.Method] = true
			g := ev.grade(logLine(t))
			why = append(why, g.hostWhy...)
			for c, ids := range g.sigs {
				for _, id := range ids {
					hit[c+":"+id] = true
				}
			}
		}
		if len(host) == 0 && len(why) == 0 {
			continue
		}
		for k := range hit {
			hits = append(hits, k)
		}
		sort.Strings(hits)
		var written []string
		for _, c := range host {
			written = append(written, sigFor[c]...)
		}
		fmt.Printf("%s (%s)\n  host CVEs %v; converted %v (err %v); requests %d %v; body %v\n  signatures for these CVEs %v\n  hits %v\n  host candidates %v\n",
			a.ID, n, host, err == nil, err, len(a.Lines), sortedKeys(methods), a.Body, written, hits, dedup(why))
	}
}

func dedup(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
