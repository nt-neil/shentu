package main

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/nt-neil/shentu/rules"
	"github.com/nt-neil/shentu/rules/engine"
)

// maxScanFile is the largest file scanned; bigger ones are counted as skipped.
const maxScanFile = 1 << 20

// skipped reports whether a path is inside a directory the scan leaves out:
// bundled third-party code and version control.
func skipped(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		switch part {
		case "vendor", "node_modules", ".git":
			return true
		}
	}
	return false
}

// scanResult is what the engine reported on one release.
type scanResult struct {
	Findings   []engine.Finding // Path is relative to the release root, with "/"
	Files      int              // files of a rule language that were scanned
	Unfinished int              // files the engine could not finish (limits) or that were too big
	Time       time.Duration
}

func scan(eng *engine.Engine, root string, perFile bool) scanResult {
	var r scanResult
	start := time.Now()
	var files []string // relative paths, "/"-separated
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && skipped(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if path.Base(rel) == "composer.json" {
			if info, err := d.Info(); err == nil && info.Size() <= maxScanFile {
				files = append(files, rel) // PSR-4 autoload, for the engine's project index
			}
			return nil
		}
		if engine.LangOf(rel) == "" {
			return nil
		}
		r.Files++
		if info, err := d.Info(); err != nil || info.Size() > maxScanFile {
			r.Unfinished++
			return nil
		}
		files = append(files, rel)
		return nil
	})
	read := func(rel string) ([]byte, error) { return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) }
	scanOne := func(rel string, src []byte) ([]engine.Finding, error) { return eng.ScanFile(rel, src) }
	if !perFile {
		if ps, ok := projectScanner(eng, files, read); ok {
			scanOne = ps
		}
	}
	for _, rel := range files {
		if engine.LangOf(rel) == "" {
			continue
		}
		src, err := read(rel)
		if err != nil {
			r.Unfinished++
			continue
		}
		fs, err := scanOne(rel, src)
		if errors.Is(err, engine.ErrLimit) || errors.Is(err, engine.ErrPartial) {
			r.Unfinished++
		}
		r.Findings = append(r.Findings, fs...)
	}
	r.Time = time.Since(start)
	return r
}

// window is how many lines around a changed range still count as the place of the fix.
const window = 10

// ruleResult is one rule's verdict on one case.
type ruleResult struct {
	Rule  string
	Vuln  bool // reported in the vulnerable release, at the fix
	Fixed bool // reported in the fixed release, at the fix
}

type caseResult struct {
	Case
	RuleSource bool // a rule cites this id in its refs: not an independent test
	Vuln       scanResult
	FixedScan  scanResult
	Rules      []ruleResult // every rule of the case's language and class
	Caught     bool         // some rule reported at the fix in the vulnerable release
	FixedFP    bool         // a rule that caught it still reports there in the fixed release
	InFixFiles int          // findings of the case's class anywhere in the fix files (vulnerable release)
	Err        string

	vulnDir, fixedDir string
}

// ruleSource returns the ids that rules cite in refs.
func ruleSource(rs []rules.Rule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		for _, ref := range r.Refs {
			out[ref] = true
		}
	}
	return out
}

func judge(r *caseResult, rs []rules.Rule) {
	files := map[string]bool{}
	for _, ff := range r.FixFiles {
		files[ff.Path] = true
	}
	for _, rule := range rs {
		if rule.Lang != r.Lang || rule.Class != r.Class {
			continue
		}
		for _, f := range r.Vuln.Findings {
			if f.RuleID == rule.ID && files[f.Path] {
				r.InFixFiles++
			}
		}
		rr := ruleResult{Rule: rule.ID}
		for _, ff := range r.FixFiles {
			rr.Vuln = rr.Vuln || near(r.Vuln.Findings, rule.ID, ff.Path, ff.Vulnerable)
			rr.Fixed = rr.Fixed || near(r.FixedScan.Findings, rule.ID, ff.Path, ff.Fixed)
		}
		r.Caught = r.Caught || rr.Vuln
		r.FixedFP = r.FixedFP || rr.Vuln && rr.Fixed
		r.Rules = append(r.Rules, rr)
	}
}

// near reports whether rule has a finding in file within window lines of a range.
func near(fs []engine.Finding, rule, file string, ranges [][]int) bool {
	for _, f := range fs {
		if f.RuleID != rule || f.Path != file {
			continue
		}
		for _, rg := range ranges {
			if f.Line >= rg[0]-window && f.Line <= rg[1]+window {
				return true
			}
		}
	}
	return false
}
