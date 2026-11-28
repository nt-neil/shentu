package main

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
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
	// CallsCut: files checked function by function to the end whose calls were
	// not all followed (ErrCalls): cross-file findings may be missing.
	CallsCut int
	Cuts     map[string]int // files cut short (ErrLimit or ErrCalls), by cause (engine.CutOf)
	// Clock: files a clock or the heap cut short (product path): their results
	// depend on how busy the machine was.
	Clock int
	Time  time.Duration
	// NamesIncomplete: the project did not know every name the release gives
	// (a folder skipped, a file too deep or too big, one not read), so the
	// rules' receivers keep every method sink (Project.NamesComplete).
	NamesIncomplete bool
}

// newScanner makes the scan of one file for a path that follows calls across
// files: projectScanner, or a stand-in in a test.
var newScanner = projectScanner

func scan(eng *engine.Engine, root string, scanPath string) scanResult {
	var r scanResult
	start := time.Now()
	var files []string // relative paths, "/"-separated
	// As app_code_audit gives the project (receivers): the package names under
	// vendor/, which is not read, and whether a file of a rule language was left
	// out (a skipped folder, deeper than the audit goes, too big, not read).
	opts := projectOptions
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			opts.Incomplete = true
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && skipped(rel) {
				if path.Base(rel) == "vendor" {
					pkgs, ok := vendorPackages(p)
					opts.Packages, opts.Incomplete = append(opts.Packages, pkgs...), opts.Incomplete || !ok
				} else {
					opts.Incomplete = true
				}
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if b := path.Base(rel); b == "composer.json" || b == "composer.lock" {
			if info, err := d.Info(); err == nil && info.Size() <= maxScanFile {
				files = append(files, rel) // PSR-4 autoload and the packages, for the engine's project index
			} else {
				opts.Incomplete = true
			}
			return nil
		}
		if engine.LangOf(rel) == "" {
			return nil
		}
		r.Files++
		if strings.Count(rel, "/") > auditDepth {
			opts.Incomplete = true // app_code_audit does not go this deep
		}
		if info, err := d.Info(); err != nil || info.Size() > maxScanFile {
			r.Unfinished++
			opts.Incomplete = true
			return nil
		}
		files = append(files, rel)
		return nil
	})
	read := func(rel string) ([]byte, error) { return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) }
	scanOne := func(rel string, src []byte) scanned {
		fs, err := eng.ScanFile(rel, src)
		return scanned{found: fs, errs: []error{err}}
	}
	namesIncomplete := func() bool { return false }
	if scanPath != pathPerFile {
		if ps, ni, ok := newScanner(eng, files, read, scanPath, opts); ok {
			scanOne, namesIncomplete = ps, ni
		}
	}
	seen := map[string]bool{} // a finding once per release, whichever file's scan found it
	for _, rel := range files {
		if engine.LangOf(rel) == "" {
			continue
		}
		src, err := read(rel)
		if err != nil {
			r.Unfinished++
			continue
		}
		sc := scanOne(rel, src)
		err = errors.Join(sc.errs...)
		switch {
		case errors.Is(err, engine.ErrLimit) || errors.Is(err, engine.ErrPartial):
			r.Unfinished++
		case errors.Is(err, engine.ErrCalls):
			r.CallsCut++
		}
		if sc.timed {
			r.Clock++
		}
		var cut engine.Cut
		for _, e := range sc.errs {
			cut |= engine.CutOf(e)
		}
		for _, n := range cut.Names() {
			if r.Cuts == nil {
				r.Cuts = map[string]int{}
			}
			r.Cuts[n]++
		}
		for _, f := range sc.found {
			if k := f.RuleID + "\x00" + f.Path + "\x00" + strconv.Itoa(f.Line); !seen[k] {
				seen[k] = true
				r.Findings = append(r.Findings, f)
			}
		}
	}
	r.NamesIncomplete = namesIncomplete()
	r.Time = time.Since(start)
	return r
}

// auditDepth is how many folders deep app_code_audit goes (tools auditMaxDepth).
const auditDepth = 8

// vendorPackages lists the Composer packages under a vendor/ folder as
// app_code_audit does, without reading them: vendor/<vendor>/<package>, lower
// case; a vendor folder not listed counts by its name (mongodb/*).
func vendorPackages(dir string) ([]string, bool) {
	vs, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	var out []string
	for _, v := range vs {
		n := v.Name()
		if n == "composer" || n == "bin" || strings.HasPrefix(n, ".") {
			continue
		}
		ps, err := os.ReadDir(filepath.Join(dir, n))
		if err != nil {
			out = append(out, strings.ToLower(n+"/*"))
			continue
		}
		for _, p := range ps {
			out = append(out, strings.ToLower(n+"/"+p.Name()))
		}
	}
	return out, true
}

// window is how many lines around a changed range still count as the place of the fix.
const window = 10

// ruleResult is one rule's verdict on one case.
type ruleResult struct {
	Rule      string
	Vuln      bool // reported in the vulnerable release, at the fix
	Fixed     bool // reported in the fixed release, at the fix
	VulnSink  bool // reported on a sink line of the case in the vulnerable release (with sink lines only)
	FixedSink bool // reported on that sink's line in the fixed release
	Reference bool // a reference-tier rule: counted in the with-reference columns only
}

type caseResult struct {
	Case
	RuleSource bool // a rule cites this id in its refs: not an independent test
	Vuln       scanResult
	FixedScan  scanResult
	Rules      []ruleResult // every rule of the case's language and class
	Caught     bool         // some rule reported at the fix in the vulnerable release
	FixedFP    bool         // a rule that caught it still reports there in the fixed release
	// With sink lines: as Caught and FixedFP, a finding on one of the case's sink
	// lines also counting. Reported next to the main verdict, never in place of it.
	CaughtSink  bool
	FixedFPSink bool
	InFixFiles  int // findings of the case's class anywhere in the fix files (vulnerable release)
	Err         string

	// With reference: as Caught and FixedFP, a reference-tier rule (about how a
	// call is made, not about input) also counting; the main verdict and the
	// with-sink-lines columns leave those rules out.
	CaughtRef  bool
	FixedFPRef bool

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
		if rule.Lang != r.Lang && !(rule.Lang == "js" && r.Lang == "ts") || rule.Class != r.Class {
			continue
		}
		for _, f := range r.Vuln.Findings {
			if f.RuleID == rule.ID && files[f.Path] {
				r.InFixFiles++
			}
		}
		rr := ruleResult{Rule: rule.ID, Reference: rule.Tier == "reference"}
		for _, ff := range r.FixFiles {
			rr.Vuln = rr.Vuln || near(r.Vuln.Findings, rule.ID, ff.Path, ff.Vulnerable)
			rr.Fixed = rr.Fixed || near(r.FixedScan.Findings, rule.ID, ff.Path, ff.Fixed)
		}
		for _, sl := range r.Sinks {
			vs := onLine(r.Vuln.Findings, rule.ID, sl.Path, sl.Vulnerable)
			rr.VulnSink = rr.VulnSink || vs
			rr.FixedSink = rr.FixedSink || vs && sl.Fixed > 0 && onLine(r.FixedScan.Findings, rule.ID, sl.Path, sl.Fixed)
		}
		r.CaughtRef = r.CaughtRef || rr.Vuln
		r.FixedFPRef = r.FixedFPRef || rr.Vuln && rr.Fixed
		r.Rules = append(r.Rules, rr)
		if rr.Reference {
			continue
		}
		r.Caught = r.Caught || rr.Vuln
		r.FixedFP = r.FixedFP || rr.Vuln && rr.Fixed
		r.CaughtSink = r.CaughtSink || rr.Vuln || rr.VulnSink
		r.FixedFPSink = r.FixedFPSink || rr.Vuln && rr.Fixed || rr.VulnSink && rr.FixedSink
	}
}

// onLine reports whether rule has a finding in file on that very line: a sink
// line counts only where the call is, not around it.
func onLine(fs []engine.Finding, rule, file string, line int) bool {
	for _, f := range fs {
		if f.RuleID == rule && f.Path == file && f.Line == line {
			return true
		}
	}
	return false
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
