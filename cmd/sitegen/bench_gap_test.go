package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A cvebench report with known gaps and cuts by cause loads: the gap table is
// not read as the case table, and a gap is neither a miss nor a catch.
func TestLoadBenchKnownGaps(t *testing.T) {
	md := "# CVE bench\n\n2026-11-22, 120 rules, 3 cases.\n\n" +
		"## Summary\n\n" +
		"| group | cases | caught | catch rate | fixed FP | fixed FP rate | findings per release (vulnerable / fixed) | scan time per release |\n" +
		"|---|---|---|---|---|---|---|---|\n" +
		"| all | 2 | 1 | 50.0% | 0 | 0.0% | 1.0 / 1.0 | 1.0s |\n\n" +
		"## Cuts by cause\n\n| cause | files (vulnerable / fixed) |\n|---|---|\n| callable-param | 3 / 2 |\n\n" +
		"## Known gaps\n\nCases the rules cannot catch yet.\n\n" +
		"| gap | class | why | caught | fixed FP |\n|---|---|---|---|---|\n" +
		"| CVE-2026-42143 | cmdi | not a rule source | - | - |\n\n" +
		"## Cases\n\n" +
		"| case | package | releases | class | group | rule | vulnerable | fixed | in fix files | findings | unfinished files | scan time | calls cut | cuts by cause |\n" +
		"|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n" +
		"| CVE-2020-0001 | composer a/b | 1.0 → 1.1 | sqli | independent | php-sqli-x | caught | - | 1 | 1 / 1 | 0 / 0 | 1.0s / 1.0s | 0 / 0 | - / - |\n" +
		"| CVE-2020-0002 | composer c/d | 1.0 → 1.1 | sqli | independent | php-sqli-x | - | - | 0 | 0 / 0 | 0 / 0 | 1.0s / 1.0s | 0 / 0 | - / - |\n" +
		"| CVE-2026-42143 | composer coollabsio/coolify | v4.0.0-beta.473 → v4.0.0-beta.474 | cmdi | independent | php-cmdi-shell-exec | - | - | 0 | 0 / 0 | 0 / 0 | 1.0s / 1.0s | 0 / 0 | - / - |\n"
	p := filepath.Join(t.TempDir(), "cves.md")
	if err := os.WriteFile(p, []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := loadBench(p)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.Gaps, []string{"CVE-2026-42143"}) {
		t.Errorf("gaps %v", b.Gaps)
	}
	var missed, caught []string
	for _, c := range b.Missed() {
		missed = append(missed, c.ID)
	}
	for _, c := range b.CaughtCases() {
		caught = append(caught, c.ID)
	}
	if !slices.Equal(missed, []string{"CVE-2020-0002"}) || !slices.Equal(caught, []string{"CVE-2020-0001"}) {
		t.Errorf("missed %v, caught %v: a gap counted", missed, caught)
	}
	if all := b.All(); all.Cases != 2 || all.Caught != 1 {
		t.Errorf("summary %+v", all)
	}
}
