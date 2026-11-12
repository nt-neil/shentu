// Command sitegen builds Shentu's website from the repository: the rule catalog
// from rules/, the route models from rules/routes/, the releases from
// CHANGELOG.md with the rule snapshots in docs/site-src/rules-history/, and the
// bench results kept in docs/site-src/bench/. It reads only files of the
// repository (no network), so the same tree always gives the same site.
//
//	go generate ./cmd/sitegen                     # rebuild docs/site
//	go run ./cmd/sitegen -snapshot 0.2.5          # at a release: keep its rule list
//	go run ./cmd/sitegen -import-bench 0.2.5 -commit <sha> \
//	    -main cves.md -holdout holdout.md -ts cves-ts.md   # keep its bench results
package main

//go:generate go run . -root ../..

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root := flag.String("root", ".", "the repository root")
	out := flag.String("out", "", "output directory (default <root>/docs/site)")
	base := flag.String("base", "https://nt-neil.github.io/shentu/", "the site's address, for the feed and canonical links")
	snapshot := flag.String("snapshot", "", "write the rule snapshot of this release (X.Y.Z) and exit")
	importVer := flag.String("import-bench", "", "keep cvebench results for this release (X.Y.Z) and exit")
	commit := flag.String("commit", "", "with -import-bench: the commit the results were measured at")
	mainRes := flag.String("main", "", "with -import-bench: the main set's result")
	holdout := flag.String("holdout", "", "with -import-bench: the hold-out set's result (only its summary is kept)")
	ts := flag.String("ts", "", "with -import-bench: the TypeScript set's result")
	flag.Parse()
	src := filepath.Join(*root, "docs", "site-src")
	if *out == "" {
		*out = filepath.Join(*root, "docs", "site")
	}
	var err error
	switch {
	case *snapshot != "":
		err = writeSnapshot(src, *snapshot)
	case *importVer != "":
		if *commit == "" {
			err = fmt.Errorf("-import-bench needs -commit")
			break
		}
		err = importBench(src, *importVer, *commit, *mainRes, *holdout, *ts)
	default:
		err = build(*root, src, *out, *base)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sitegen:", err)
		os.Exit(1)
	}
}
