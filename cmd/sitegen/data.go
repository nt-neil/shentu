package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/rules"
)

// Release is one section of CHANGELOG.md, with what the rule snapshots and the
// bench results say changed since the release before it.
type Release struct {
	Version    string // "0.2.5"
	Date       string // "2026-11-09", "" when unreleased
	Items      []string
	English    []string // the English items, which the card's groups are chosen by
	Sections   []string // each item's "###" section: "" before any, else fixed, upgrade or known
	Added      []string // rule ids new in this release
	Removed    []string // rule ids gone in this release
	AddedBy    []IDGroup
	RemovedBy  []IDGroup
	Frameworks []string // route models new in this release
	Rules      int      // rules in this release (-1 when no snapshot)
	Bench      *Bench   // the main CVE bench of this release, if measured
	PrevBench  *Bench   // ... and of the release before it that was measured
}

var (
	// sectionKeys are the "###" headings a release may have, in either language.
	sectionKeys = map[string]string{
		"Fixed": "fixed", "Upgrade notes": "upgrade", "Known issues": "known",
		"修正": "fixed", "升級說明": "upgrade", "已知問題": "known",
	}
	headRe = regexp.MustCompile(`^## v(\d+\.\d+\.\d+)(?: — (\d{4}-\d{2}-\d{2})| \(unreleased\))\s*$`)
	verRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// parseChangelog reads the releases of CHANGELOG.md, newest first as written.
// A release's items are its "- " lines (a line indented under one continues it);
// a "###" heading puts the lines after it in that section.
func parseChangelog(path string) ([]Release, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Release
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := headRe.FindStringSubmatch(line); m != nil {
			out = append(out, Release{Version: m[1], Date: m[2], Rules: -1})
			section = ""
			continue
		}
		if strings.HasPrefix(line, "## ") {
			return nil, fmt.Errorf("%s: heading %q is not \"## vX.Y.Z — YYYY-MM-DD\" or \"## vX.Y.Z (unreleased)\"", path, line)
		}
		if len(out) == 0 {
			continue
		}
		r := &out[len(out)-1]
		switch {
		case strings.HasPrefix(line, "### "):
			k, ok := sectionKeys[strings.TrimSpace(line[4:])]
			if !ok {
				return nil, fmt.Errorf("%s: v%s: section %q is not one of Fixed, Upgrade notes, Known issues (修正, 升級說明, 已知問題)", path, r.Version, line)
			}
			section = k
		case strings.HasPrefix(line, "- "):
			r.Items = append(r.Items, strings.TrimSpace(line[2:]))
			r.Sections = append(r.Sections, section)
		case strings.HasPrefix(line, "  ") && strings.TrimSpace(line) != "" && len(r.Items) > 0:
			r.Items[len(r.Items)-1] += " " + strings.TrimSpace(line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no releases", path)
	}
	return out, nil
}

// Snapshot is what a release shipped: its rule ids and its route frameworks.
type Snapshot struct {
	Rules      []string
	Frameworks []string
}

// currentSnapshot is the snapshot of the rules in this tree.
func currentSnapshot(rs []rules.Rule, routes []rules.Route) Snapshot {
	var s Snapshot
	for _, r := range rs {
		s.Rules = append(s.Rules, r.ID)
	}
	seen := map[string]bool{}
	for _, r := range routes {
		if !seen[r.Framework] {
			seen[r.Framework] = true
			s.Frameworks = append(s.Frameworks, r.Framework)
		}
	}
	sort.Strings(s.Rules)
	sort.Strings(s.Frameworks)
	return s
}

func (s Snapshot) text() string {
	var b strings.Builder
	for _, f := range s.Frameworks {
		fmt.Fprintf(&b, "framework %s\n", f)
	}
	for _, r := range s.Rules {
		fmt.Fprintf(&b, "rule %s\n", r)
	}
	return b.String()
}

func readSnapshot(path string) (Snapshot, bool, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, err
	}
	var s Snapshot
	for _, line := range strings.Split(string(b), "\n") {
		switch k, v, _ := strings.Cut(strings.TrimSpace(line), " "); k {
		case "rule":
			s.Rules = append(s.Rules, v)
		case "framework":
			s.Frameworks = append(s.Frameworks, v)
		case "":
		default:
			return s, false, fmt.Errorf("%s: unknown line %q", path, line)
		}
	}
	return s, true, nil
}

func minus(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// fillReleases works out each release's rule changes from the snapshots (the
// unreleased one, if it has none, from this tree) and attaches the bench
// results kept for it.
func fillReleases(rels []Release, src string, current Snapshot) error {
	snaps := make([]*Snapshot, len(rels))
	for i := range rels {
		s, ok, err := readSnapshot(filepath.Join(src, "rules-history", rels[i].Version+".txt"))
		if err != nil {
			return err
		}
		if !ok && rels[i].Date == "" {
			s, ok = current, true
		}
		if ok {
			snaps[i] = &s
			rels[i].Rules = len(s.Rules)
		}
		b, err := loadBench(filepath.Join(src, "bench", rels[i].Version, "cves.md"))
		if err != nil {
			return err
		}
		rels[i].Bench = b
	}
	for i := range rels {
		if snaps[i] == nil {
			continue
		}
		var prev *Snapshot
		for j := i + 1; j < len(rels) && prev == nil; j++ {
			prev = snaps[j]
		}
		if prev == nil {
			prev = &Snapshot{}
		}
		rels[i].Added = minus(snaps[i].Rules, prev.Rules)
		rels[i].Removed = minus(prev.Rules, snaps[i].Rules)
		rels[i].Frameworks = minus(snaps[i].Frameworks, prev.Frameworks)
		rels[i].AddedBy, rels[i].RemovedBy = byLang(rels[i].Added), byLang(rels[i].Removed)
		for j := i + 1; j < len(rels) && rels[i].PrevBench == nil; j++ {
			rels[i].PrevBench = rels[j].Bench
		}
	}
	return nil
}

// IDGroup is the rule ids of one language, as a release lists them.
type IDGroup struct {
	Lang string
	IDs  []string
}

// byLang groups rule ids by the language their id starts with ("php-...").
func byLang(ids []string) []IDGroup {
	var out []IDGroup
	for _, id := range ids {
		l, _, _ := strings.Cut(id, "-")
		i := 0
		for i < len(out) && out[i].Lang != l {
			i++
		}
		if i == len(out) {
			out = append(out, IDGroup{Lang: l})
		}
		out[i].IDs = append(out[i].IDs, id)
	}
	sort.SliceStable(out, func(i, j int) bool { return langOrder(out[i].Lang) < langOrder(out[j].Lang) })
	return out
}

// translate returns the releases with their items taken from a translated
// changelog, which must have the same releases, each with items, and the
// same sections with as many items in each: the card groups a translated
// line where it groups the English one.
func translate(rels, tr []Release, path string) ([]Release, error) {
	if len(tr) != len(rels) {
		return nil, fmt.Errorf("%s has %d releases, CHANGELOG.md has %d", path, len(tr), len(rels))
	}
	out := make([]Release, len(rels))
	for i, r := range rels {
		if tr[i].Version != r.Version || tr[i].Date != r.Date {
			return nil, fmt.Errorf("%s: release %d is v%s %s, CHANGELOG.md has v%s %s", path, i+1, tr[i].Version, tr[i].Date, r.Version, r.Date)
		}
		if len(r.Items) == 0 || len(tr[i].Items) == 0 {
			return nil, fmt.Errorf("v%s has no items in CHANGELOG.md or %s", r.Version, path)
		}
		if strings.Join(tr[i].Sections, ",") != strings.Join(r.Sections, ",") {
			return nil, fmt.Errorf("v%s: %s has %d items in sections %q, CHANGELOG.md has %d in %q", r.Version, path, len(tr[i].Items), tr[i].Sections, len(r.Items), r.Sections)
		}
		out[i] = r
		out[i].Items = tr[i].Items
		out[i].English = r.Items
	}
	return out, nil
}

// Bench is a cvebench result: its summary rows and its cases.
type Bench struct {
	Date    string
	Rules   string
	Groups  []BenchRow
	Cases   []BenchCase
	Gaps    []string // known gaps (cvebench known_gap): run, but out of the rates, the misses and the catches
	Measure string   // the commit the numbers were measured at, from the import
}

// BenchRow is a row of the summary table.
type BenchRow struct {
	Group   string
	Cases   int
	Caught  int
	Rate    string
	FixedFP int
	FPRate  string
}

// BenchCase is a row of the case table.
type BenchCase struct {
	ID, Package, Class, Group, Rule string
	Caught                          bool
}

// All is the "all" row.
func (b *Bench) All() BenchRow {
	for _, r := range b.Groups {
		if r.Group == "all" {
			return r
		}
	}
	return BenchRow{}
}

// Missed lists the cases no rule caught, known gaps left out (as from the
// rates the summary gives).
func (b *Bench) Missed() []BenchCase {
	var out []BenchCase
	for _, c := range b.Cases {
		if !c.Caught && !slices.Contains(b.Gaps, c.ID) {
			out = append(out, c)
		}
	}
	return out
}

// CaughtCases lists the cases a rule caught, known gaps left out.
func (b *Bench) CaughtCases() []BenchCase {
	var out []BenchCase
	for _, c := range b.Cases {
		if c.Caught && !slices.Contains(b.Gaps, c.ID) {
			out = append(out, c)
		}
	}
	return out
}

var measuredRe = regexp.MustCompile(`^<!-- measured at (\S+) -->$`)

// loadBench reads a cvebench Markdown result (nil, nil when there is none).
func loadBench(path string) (*Bench, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &Bench{}
	table := ""
	for _, line := range strings.Split(string(b), "\n") {
		if m := measuredRe.FindStringSubmatch(line); m != nil {
			out.Measure = m[1]
		}
		if d, rest, ok := strings.Cut(line, ", "); ok && len(d) == 10 && strings.HasSuffix(rest, " cases.") && out.Date == "" {
			out.Date, out.Rules = d, strings.TrimSuffix(strings.SplitN(rest, ",", 2)[0], " rules")
		}
		if !strings.HasPrefix(line, "|") {
			table = ""
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		switch {
		case cells[0] == "group" || cells[0] == "case" || cells[0] == "gap":
			table = cells[0]
			continue
		case strings.HasPrefix(cells[0], "---"):
			continue
		}
		switch table {
		case "group":
			if len(cells) < 6 {
				return nil, fmt.Errorf("%s: short summary row %q", path, line)
			}
			out.Groups = append(out.Groups, BenchRow{Group: cells[0], Cases: atoi(cells[1]), Caught: atoi(cells[2]),
				Rate: cells[3], FixedFP: atoi(cells[4]), FPRate: cells[5]})
		case "gap":
			out.Gaps = append(out.Gaps, cells[0])
		case "case":
			if len(cells) < 7 {
				return nil, fmt.Errorf("%s: short case row %q", path, line)
			}
			// one row per rule of the case's class: the case is caught when one is
			caught := cells[6] != "-" && cells[6] != ""
			if n := len(out.Cases); n > 0 && out.Cases[n-1].ID == cells[0] {
				c := &out.Cases[n-1]
				if caught && !c.Caught {
					c.Caught, c.Rule = true, cells[5]
				}
				continue
			}
			c := BenchCase{ID: cells[0], Package: cells[1], Class: cells[3], Group: cells[4], Caught: caught}
			if caught {
				c.Rule = cells[5]
			}
			out.Cases = append(out.Cases, c)
		}
	}
	if len(out.Groups) == 0 {
		return nil, fmt.Errorf("%s: no summary table", path)
	}
	return out, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// importBench copies cvebench results into src/bench/<version>: the main and
// TypeScript sets whole, the hold-out set as its summary only (its cases stay
// unpublished, so they keep measuring what rules were not tuned on).
func importBench(src, version, commit, main, holdout, ts string) error {
	if !verRe.MatchString(version) {
		return fmt.Errorf("version %q is not X.Y.Z", version)
	}
	dir := filepath.Join(src, "bench", version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range []struct {
		from, to    string
		summaryOnly bool
	}{{main, "cves.md", false}, {holdout, "holdout.md", true}, {ts, "cves-ts.md", false}} {
		if f.from == "" {
			continue
		}
		b, err := os.ReadFile(f.from)
		if err != nil {
			return err
		}
		text := string(b)
		if f.summaryOnly {
			var keep []string
			for _, line := range strings.Split(text, "\n") {
				if strings.HasPrefix(line, "## ") && line != "## Summary" {
					break
				}
				keep = append(keep, line)
			}
			text = strings.Join(keep, "\n")
		}
		text = strings.TrimRight(text, "\n") + "\n\n<!-- measured at " + commit + " -->\n"
		if err := os.WriteFile(filepath.Join(dir, f.to), []byte(text), 0o644); err != nil {
			return err
		}
		if _, err := loadBench(filepath.Join(dir, f.to)); err != nil {
			return err
		}
	}
	return nil
}

// AttackEval is attack detection's measurement on synthetic requests, as the
// bench page shows it: tools/detecteval/baseline.json, with what it does not
// keep (the nuclei-templates release, the applications, each host case's
// level) read from the table and text of docs/attack-detection-limits.md.
type AttackEval struct {
	Version      string // the release the limits document is for
	Signatures   int
	Nuclei       string // nuclei-templates release
	Commit       string // its commit, shortened
	Caught       int
	Templates    int
	Rate         string // Caught of Templates
	NotConverted int
	Unclassified int
	RCEUnspec    int
	Distinct     int
	Requests     int
	Routes       int
	Apps         int
	Upper        string // the false-alert rate's 95% upper bound with none seen
	HostCVEs     int
	HostAlerted  int
	HostL1       int // of HostAlerted, those only at L1
}

var (
	limitsVerRe = regexp.MustCompile(`(?m)^# .* in v(\d+\.\d+\.\d+)\s*$`)
	nucleiRe    = regexp.MustCompile(`nuclei-templates v(\d+\.\d+\.\d+) \(commit ([0-9a-f]+)\)`)
	appsRe      = regexp.MustCompile(`(\d+) for each of (\d+) routes of (\d+) applications`)
	hostRowRe   = regexp.MustCompile(`(?m)^\| (CVE-\d+-\d+) \| (L1|L2|L3|none) \|`)
)

// loadAttackEval reads attack detection's measurement under root. It fails
// when the numbers no longer agree with each other or the page's words: a
// false alert, or a host table that does not add up to the baseline.
func loadAttackEval(root string) (*AttackEval, error) {
	bp := filepath.Join(root, "tools", "detecteval", "baseline.json")
	b, err := os.ReadFile(bp)
	if err != nil {
		return nil, err
	}
	var base struct {
		Stats struct {
			NucleiCommit   string `json:"nuclei_commit"`
			NotConverted   int    `json:"not_converted"`
			Unclassified   int    `json:"unclassified"`
			RCEUnspecified int    `json:"rce_unspecified"`
			Classes        map[string]struct {
				Templates int `json:"templates"`
				Caught    int `json:"caught"`
			} `json:"classes"`
			Host struct {
				TemplatesForCVEs int `json:"templates_for_cves"`
				AlertedForCVEs   int `json:"alerted_for_cves"`
			} `json:"host"`
			NormalRequests int `json:"normal_requests"`
			NormalDistinct int `json:"normal_distinct"`
			NormalRoutes   int `json:"normal_routes"`
			FalsePositives int `json:"false_positives"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(b, &base); err != nil {
		return nil, fmt.Errorf("%s: %v", bp, err)
	}
	s := base.Stats
	e := &AttackEval{NotConverted: s.NotConverted, Unclassified: s.Unclassified, RCEUnspec: s.RCEUnspecified,
		Distinct: s.NormalDistinct, Requests: s.NormalRequests, Routes: s.NormalRoutes,
		HostCVEs: s.Host.TemplatesForCVEs, HostAlerted: s.Host.AlertedForCVEs}
	for _, c := range s.Classes {
		e.Caught += c.Caught
		e.Templates += c.Templates
	}
	if e.Templates == 0 || e.Distinct == 0 {
		return nil, fmt.Errorf("%s: no templates or ordinary requests", bp)
	}
	if s.FalsePositives != 0 {
		return nil, fmt.Errorf("%s: %d false alerts: the bench page says there are none, rewrite it", bp, s.FalsePositives)
	}
	e.Rate = fmt.Sprintf("%.1f%%", 100*float64(e.Caught)/float64(e.Templates))
	e.Upper = fmt.Sprintf("%.1f%%", 100*(1-math.Pow(0.05, 1/float64(e.Distinct))))

	lp := filepath.Join(root, "docs", "attack-detection-limits.md")
	lb, err := os.ReadFile(lp)
	if err != nil {
		return nil, err
	}
	l := string(lb)
	m := limitsVerRe.FindStringSubmatch(l)
	n := nucleiRe.FindStringSubmatch(l)
	a := appsRe.FindStringSubmatch(l)
	if m == nil || n == nil || a == nil {
		return nil, fmt.Errorf("%s: no release in its title, nuclei-templates release or routes of applications", lp)
	}
	e.Version, e.Nuclei, e.Commit = m[1], n[1], n[2]
	if !strings.HasPrefix(s.NucleiCommit, e.Commit) {
		return nil, fmt.Errorf("%s names nuclei-templates commit %s, %s has %s", lp, e.Commit, bp, s.NucleiCommit)
	}
	e.Apps, _ = strconv.Atoi(a[3])
	if routes, _ := strconv.Atoi(a[2]); routes != e.Routes {
		return nil, fmt.Errorf("%s names %d routes, %s has %d", lp, routes, bp, e.Routes)
	}
	alerted := 0
	for _, r := range hostRowRe.FindAllStringSubmatch(l, -1) {
		if r[2] != "none" {
			alerted++
		}
		if r[2] == "L1" {
			e.HostL1++
		}
	}
	if alerted != e.HostAlerted {
		return nil, fmt.Errorf("%s: its host table has %d alerted, %s has %d", lp, alerted, bp, e.HostAlerted)
	}
	ss, err := sig.Load()
	if err != nil {
		return nil, err
	}
	e.Signatures = len(ss)
	return e, nil
}
