package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/rules"
)

// markdown renders the summary and the per-case table. It names rules, files
// and lines only, never code.
func markdown(results []caseResult, rs []rules.Rule, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# CVE bench\n\n%s, %d rules, %d cases.\n\n", now.Format("2006-01-02"), len(rs), len(results))
	fmt.Fprintf(&b, "- caught: a rule of the case's class reports within %d lines of a line the fix changed, in the vulnerable release.\n", window)
	b.WriteString("- fixed FP: a rule that caught the case still reports at the fix in the fixed release; the rate is over caught cases.\n")
	b.WriteString("- rule source: a rule cites the id in its refs, so the rule was written from it; independent: no rule cites it.\n")
	b.WriteString("- in fix files: reports of the case's class anywhere in the fix files of the vulnerable release, near the fix or not.\n")
	b.WriteString("- findings and time: every report of every rule on the whole release, and the time to scan it.\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString("| group | cases | caught | catch rate | fixed FP | fixed FP rate | findings per release (vulnerable / fixed) | scan time per release |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	groups := []struct {
		name string
		in   func(caseResult) bool
	}{
		{"all", func(caseResult) bool { return true }},
		{"rule source", func(r caseResult) bool { return r.RuleSource }},
		{"independent", func(r caseResult) bool { return !r.RuleSource }},
	}
	for _, key := range sortedKeys(results, func(r caseResult) string { return r.Ecosystem }) {
		groups = append(groups, struct {
			name string
			in   func(caseResult) bool
		}{key, func(r caseResult) bool { return r.Ecosystem == key }})
	}
	for _, key := range sortedKeys(results, func(r caseResult) string { return r.Class }) {
		groups = append(groups, struct {
			name string
			in   func(caseResult) bool
		}{key, func(r caseResult) bool { return r.Class == key }})
	}
	for _, g := range groups {
		var n, caught, fp, vf, ff int
		var t time.Duration
		for _, r := range results {
			if r.Err != "" || !g.in(r) {
				continue
			}
			n++
			if r.Caught {
				caught++
			}
			if r.FixedFP {
				fp++
			}
			vf += len(r.Vuln.Findings)
			ff += len(r.FixedScan.Findings)
			t += r.Vuln.Time + r.FixedScan.Time
		}
		if n == 0 {
			continue
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %s | %d | %s | %.1f / %.1f | %.1fs |\n", g.name, n, caught, pct(caught, n), fp, pct(fp, caught),
			float64(vf)/float64(n), float64(ff)/float64(n), t.Seconds()/float64(2*n))
	}

	var errs []string
	for _, r := range results {
		if r.Err != "" {
			errs = append(errs, fmt.Sprintf("- %s: %s", r.ID, r.Err))
		}
	}
	if len(errs) > 0 {
		fmt.Fprintf(&b, "\n%d cases could not run and are left out of the summary:\n\n%s\n", len(errs), strings.Join(errs, "\n"))
	}

	b.WriteString("\n## Cases\n\n")
	b.WriteString("| case | package | releases | class | group | rule | vulnerable | fixed | in fix files | findings | unfinished files | scan time |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range results {
		group := "independent"
		if r.RuleSource {
			group = "rule source"
		}
		pkg := r.Ecosystem + " " + r.Package
		rel := r.Vulnerable + " → " + r.Fixed
		if r.Err != "" {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | error | | | | | | |\n", r.ID, pkg, rel, r.Class, group)
			continue
		}
		for _, rr := range r.Rules {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %d | %d / %d | %d / %d | %.1fs / %.1fs |\n",
				r.ID, pkg, rel, r.Class, group, rr.Rule, mark(rr.Vuln, "caught"), mark(rr.Fixed, "still reports"), r.InFixFiles,
				len(r.Vuln.Findings), len(r.FixedScan.Findings), r.Vuln.Unfinished, r.FixedScan.Unfinished,
				r.Vuln.Time.Seconds(), r.FixedScan.Time.Seconds())
		}
	}
	return b.String()
}

func mark(ok bool, s string) string {
	if ok {
		return s
	}
	return "-"
}

func pct(n, d int) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(d))
}

func sortedKeys(results []caseResult, key func(caseResult) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		if k := key(r); !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
