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
// count of ordinary requests or false positives, of templates not
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
	b := baseline{st.NucleiCommit, st.TemplatesHash, st.NotConverted, st.Unclassified, st.RCEUnspecified, st.FalsePositives, st.NormalRequests, st.GradedHash, st}
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
	diff("not_converted", b.NotConverted, want.NotConverted)
	diff("unclassified", b.Unclassified, want.Unclassified)
	diff("rce_unspecified", b.RCEUnspecified, want.RCEUnspecified)
	diff("graded_sha256", b.GradedHash, want.GradedHash)
	if want.Stats == nil {
		diff("host", fmt.Sprintf("%+v", st.Host), "(none)")
	} else {
		diff("host", fmt.Sprintf("%+v", st.Host), fmt.Sprintf("%+v", want.Stats.Host))
	}
	if want.Stats != nil && bad > 0 { // which counts moved, to help read the change
		for c, s := range st.Classes {
			if w := want.Stats.Classes[c]; w == nil || *w != *s {
				fmt.Printf("  class %s: %+v, baseline %+v\n", c, *s, w)
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
