// Command cvebench measures how well Shentu's code rules find real, published
// vulnerabilities. For every case in bench/cves it downloads the vulnerable and
// the fixed release of the package, scans both with rules/engine, and checks
// whether a rule of the case's class reports near the lines the fix changed
// (caught), and whether that rule still reports there after the fix (a false
// positive on the fixed release).
//
// It runs on a developer machine only: it is not part of the released binary.
// Downloads are cached outside the repository, every release is unpacked into a
// new empty directory, and nothing in them is executed; the engine only reads
// the files.
//
//	go run ./cmd/cvebench                    # all cases, Markdown report on stdout
//	go run ./cmd/cvebench -only CVE-2023-123 # some cases
//	go run ./cmd/cvebench -fetch             # download and unpack only, print the directories
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nt-neil/shentu/rules"
	"github.com/nt-neil/shentu/rules/engine"
)

func main() {
	cache, _ := os.UserCacheDir()
	casesDir := flag.String("cases", "bench/cves", "directory of case files")
	cacheDir := flag.String("cache", filepath.Join(cache, "shentu-cvebench"), "download and unpack cache (outside the repository)")
	only := flag.String("only", "", "comma-separated case ids to run")
	fetchOnly := flag.Bool("fetch", false, "download and unpack only; print each release's directory")
	out := flag.String("out", "", "write the report to this file instead of stdout")
	jobs := flag.Int("j", 2, "cases run at the same time")
	flag.Parse()

	if err := run(*casesDir, *cacheDir, *only, *fetchOnly, *out, *jobs); err != nil {
		fmt.Fprintln(os.Stderr, "cvebench:", err)
		os.Exit(1)
	}
}

func run(casesDir, cacheDir, only string, fetchOnly bool, out string, jobs int) error {
	cases, err := loadCases(casesDir)
	if err != nil {
		return err
	}
	if only != "" {
		want := map[string]bool{}
		for _, id := range strings.Split(only, ",") {
			want[strings.TrimSpace(id)] = true
		}
		var keep []Case
		for _, c := range cases {
			if want[c.ID] {
				keep = append(keep, c)
				delete(want, c.ID)
			}
		}
		for id := range want {
			return fmt.Errorf("no case %s in %s", id, casesDir)
		}
		cases = keep
	}
	rs, err := rules.Load()
	if err != nil {
		return err
	}
	eng, err := engine.New(rs)
	if err != nil {
		return err
	}
	f := &fetcher{dir: cacheDir, client: newClient()}
	cited := ruleSource(rs)

	results := make([]caseResult, len(cases))
	next := make(chan int)
	var wg sync.WaitGroup
	for range max(jobs, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i] = runCase(f, eng, rs, cited, cases[i], fetchOnly)
			}
		}()
	}
	for i := range cases {
		next <- i
	}
	close(next)
	wg.Wait()

	if fetchOnly {
		failed := 0
		for _, r := range results {
			if r.Err != "" {
				failed++
				fmt.Printf("%s\terror: %s\n", r.ID, r.Err)
				continue
			}
			fmt.Printf("%s\t%s\t%s\n", r.ID, r.vulnDir, r.fixedDir)
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d cases failed", failed, len(results))
		}
		return nil
	}
	report := markdown(results, rs, time.Now())
	if out == "" {
		_, err = os.Stdout.WriteString(report)
		return err
	}
	return os.WriteFile(out, []byte(report), 0o644)
}

// runCase fetches and scans both releases of one case and judges the result.
func runCase(f *fetcher, eng *engine.Engine, rs []rules.Rule, cited map[string]bool, c Case, fetchOnly bool) caseResult {
	r := caseResult{Case: c, RuleSource: cited[c.ID]}
	var err error
	if r.vulnDir, err = f.release(c, c.Vulnerable); err != nil {
		r.Err = fmt.Sprintf("vulnerable %s: %v", c.Vulnerable, err)
		return r
	}
	if r.fixedDir, err = f.release(c, c.Fixed); err != nil {
		r.Err = fmt.Sprintf("fixed %s: %v", c.Fixed, err)
		return r
	}
	if err := checkFixFiles(c, r.vulnDir, r.fixedDir); err != nil {
		r.Err = err.Error()
		return r
	}
	if fetchOnly {
		return r
	}
	r.Vuln = scan(eng, r.vulnDir)
	r.FixedScan = scan(eng, r.fixedDir)
	judge(&r, rs)
	return r
}
