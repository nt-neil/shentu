package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/rules"
)

// Release is one section of CHANGELOG.md, with what the rule snapshots and the
// bench results say changed since the release before it.
type Release struct {
	Version    string // "0.2.5"
	Date       string // "2026-11-09", "" when unreleased
	Items      []string
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
	headRe = regexp.MustCompile(`^## v(\d+\.\d+\.\d+)(?: — (\d{4}-\d{2}-\d{2})| \(unreleased\))\s*$`)
	verRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// parseChangelog reads the releases of CHANGELOG.md, newest first as written.
// A release's items are its "- " lines (a line indented under one continues it).
func parseChangelog(path string) ([]Release, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Release
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := headRe.FindStringSubmatch(line); m != nil {
			out = append(out, Release{Version: m[1], Date: m[2], Rules: -1})
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
		case strings.HasPrefix(line, "- "):
			r.Items = append(r.Items, strings.TrimSpace(line[2:]))
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
// changelog, which must have the same releases, each with items.
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
		out[i] = r
		out[i].Items = tr[i].Items
	}
	return out, nil
}

// Bench is a cvebench result: its summary rows and its cases.
type Bench struct {
	Date    string
	Rules   string
	Groups  []BenchRow
	Cases   []BenchCase
	Measure string // the commit the numbers were measured at, from the import
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

// Missed lists the cases no rule caught.
func (b *Bench) Missed() []BenchCase {
	var out []BenchCase
	for _, c := range b.Cases {
		if !c.Caught {
			out = append(out, c)
		}
	}
	return out
}

// CaughtCases lists the cases a rule caught.
func (b *Bench) CaughtCases() []BenchCase {
	var out []BenchCase
	for _, c := range b.Cases {
		if c.Caught {
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
		case cells[0] == "group" || cells[0] == "case":
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
