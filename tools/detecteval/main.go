// Command detecteval measures shentu's attack detection (plan 0743f0):
// the detection rate of Nuclei's http templates, by payload class; the
// false positive rate on ordinary requests to the applications of the E7
// corpus; and how many alerts reach the layer "a real vulnerability of
// this host" (the cvebench cases' packages). It prints counts, rule ids
// and template ids, never a request.
//
// The templates (nuclei-templates, MIT) are downloaded when it runs, at
// the commit in fetch.go, and checked against the hash there; nothing of
// them is kept in this repository.
//
// It compares what it got with baseline.json: a different templates hash,
// count of ordinary requests (all, those different in more than tracking
// parameters, their routes) or of false positives, of templates not
// converted, unclassified or rce-unspecified, any different count of the
// host layer, or a different hash of the graded results (each template's
// class, hits, level and host alert, each ordinary request's), is an
// error (exit 1). A download that fails, templates whose hash differs or
// an archive refused is "NOT RUN" (exit 3): never a pass. A run that
// cannot start (a missing bench case, an unreadable baseline) is exit 2.
// The graded hash is of what shentu's matching makes of the requests, so
// a Go release that changes how a regular expression or a URL is read
// may move it; CI pins the Go version for that reason.
//
// It is its own module, so that its YAML dependency stays out of shentu.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
)

// baseline is what is compared.
type baseline struct {
	NucleiCommit   string `json:"nuclei_commit"`
	TemplatesHash  string `json:"templates_hash"`
	NotConverted   int    `json:"not_converted"`
	Unclassified   int    `json:"unclassified"`
	RCEUnspecified int    `json:"rce_unspecified"`
	FalsePositives int    `json:"false_positives"`
	NormalRequests int    `json:"normal_requests"`
	NormalDistinct int    `json:"normal_distinct"`
	NormalRoutes   int    `json:"normal_routes"`
	GradedHash     string `json:"graded_sha256"`
	// Stats: its Host is compared too; the rest is said, the graded hash
	// covering it.
	Stats *Stats `json:"stats"`
}

func main() {
	base := flag.String("baseline", "baseline.json", "the baseline to compare with")
	write := flag.Bool("write-baseline", false, "write the baseline instead of comparing")
	repo := flag.String("repo", "../..", "the shentu repository (for bench/)")
	tarball := flag.String("templates", "", "a nuclei-templates tarball already downloaded (default: download it)")
	explain := flag.Bool("explain-host", false, "say, per template of the host layer, what it came to (ids and reasons only), and compare nothing")
	flag.Parse()
	if *explain {
		os.Exit(explainHost(*repo, *tarball))
	}
	os.Exit(run(*base, *write, *repo, *tarball))
}

func run(base string, write bool, repo, tarball string) int {
	ev, _, err := newEvaluator(repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "detecteval:", err)
		return 2
	}
	normal, err := normalRequests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "detecteval:", err)
		return 2
	}
	files, err := templates(tarball)
	if err != nil {
		why := "error"
		switch {
		case errors.Is(err, errDownload):
			why = "download failed"
		case errors.Is(err, errHash):
			why = "hash mismatch"
		case errors.Is(err, errArchive):
			why = "archive refused"
		}
		fmt.Printf("detecteval NOT RUN (%s): %v\n", why, err)
		return 3
	}
	st := ev.run(files, normal)
	report(st)
	b := baseline{st.NucleiCommit, st.TemplatesHash, st.NotConverted, st.Unclassified, st.RCEUnspecified, st.FalsePositives, st.NormalRequests, st.NormalDistinct, st.NormalRoutes, st.GradedHash, st}
	if write {
		out, _ := json.MarshalIndent(b, "", "  ")
		if err := os.WriteFile(base, append(out, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "detecteval:", err)
			return 2
		}
		fmt.Println("baseline written:", base)
		return 0
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "detecteval:", err)
		return 2
	}
	var want baseline
	if err := json.Unmarshal(raw, &want); err != nil {
		fmt.Fprintln(os.Stderr, "detecteval:", base, err)
		return 2
	}
	bad := 0
	diff := func(name string, got, want any) {
		if fmt.Sprint(got) != fmt.Sprint(want) {
			fmt.Printf("CHANGED %s: %v, baseline %v\n", name, got, want)
			bad++
		}
	}
	diff("nuclei_commit", b.NucleiCommit, want.NucleiCommit)
	diff("templates_hash", b.TemplatesHash, want.TemplatesHash)
	diff("false_positives", b.FalsePositives, want.FalsePositives)
	diff("normal_requests", b.NormalRequests, want.NormalRequests)
	diff("normal_distinct", b.NormalDistinct, want.NormalDistinct)
	diff("normal_routes", b.NormalRoutes, want.NormalRoutes)
	diff("not_converted", b.NotConverted, want.NotConverted)
	diff("unclassified", b.Unclassified, want.Unclassified)
	diff("rce_unspecified", b.RCEUnspecified, want.RCEUnspecified)
	diff("graded_sha256", b.GradedHash, want.GradedHash)
	if want.Stats == nil {
		diff("host", fmt.Sprintf("%+v", st.Host), "(none)")
	} else {
		diff("host", fmt.Sprintf("%+v", st.Host), fmt.Sprintf("%+v", want.Stats.Host))
	}
	if want.Stats != nil && bad > 0 { // which counts and templates moved, to help read the change
		for _, c := range sortedClasses(st.Classes, want.Stats.Classes) {
			s, w := st.Classes[c], want.Stats.Classes[c]
			if s == nil {
				s = &ClassStat{}
			}
			if w == nil {
				w = &ClassStat{}
			}
			if s.Templates != w.Templates || s.Caught != w.Caught {
				fmt.Printf("  class %s: templates %d caught %d, baseline templates %d caught %d\n", c, s.Templates, s.Caught, w.Templates, w.Caught)
			}
			if w.Caught > 0 && len(w.CaughtIDs) == 0 {
				fmt.Printf("  class %s: the baseline lists no caught template ids (written before they were kept)\n", c)
				continue
			}
			gained, lost := idDiff(s.CaughtIDs, w.CaughtIDs)
			for _, id := range gained {
				fmt.Printf("  class %s: newly caught %s\n", c, id)
			}
			for _, id := range lost {
				fmt.Printf("  class %s: no longer caught %s\n", c, id)
			}
		}
	}
	if bad > 0 {
		fmt.Println("detecteval FAILED: results differ from", base, "(run with -write-baseline once the change is meant)")
		return 1
	}
	fmt.Println("detecteval OK: same as", base)
	return 0
}

// templates downloads (or reads) the tarball and checks the templates'
// hash.
func templates(tarball string) (map[string][]byte, error) {
	if tarball == "" {
		dir, err := os.MkdirTemp("", "detecteval-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if tarball, err = download(ctx, templatesURL, dir); err != nil {
			return nil, err
		}
	}
	files, err := readTemplates(tarball)
	if err != nil {
		return nil, err
	}
	if h := manifestHash(files); h != wantHash {
		return nil, fmt.Errorf("%w: http templates hash %s, want %s", errHash, h, wantHash)
	}
	return files, nil
}

func explainHost(repo, tarball string) int {
	ev, _, err := newEvaluator(repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "detecteval:", err)
		return 2
	}
	files, err := templates(tarball)
	if err != nil {
		fmt.Printf("detecteval NOT RUN: %v\n", err)
		return 3
	}
	ev.explainHost(files)
	return 0
}

// sortedClasses is the classes of a and b, sorted.
func sortedClasses(a, b map[string]*ClassStat) []string {
	seen := map[string]bool{}
	for c := range a {
		seen[c] = true
	}
	for c := range b {
		seen[c] = true
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// idDiff is the ids of got not in want (gained) and of want not in got
// (lost), each sorted.
func idDiff(got, want []string) (gained, lost []string) {
	in := func(list []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range list {
			m[x] = true
		}
		return m
	}
	g, w := in(got), in(want)
	for x := range g {
		if !w[x] {
			gained = append(gained, x)
		}
	}
	for x := range w {
		if !g[x] {
			lost = append(lost, x)
		}
	}
	sort.Strings(gained)
	sort.Strings(lost)
	return gained, lost
}
