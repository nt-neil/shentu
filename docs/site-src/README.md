# Website sources

`cmd/sitegen` builds the website in `docs/site` from files of this repository only:

- the rules (`rules/`) and route models (`rules/routes/`), as the binary embeds them;
- `CHANGELOG.md`, one section per release;
- `rules-history/X.Y.Z.txt`: the rule ids and route frameworks each release shipped. A
  release's added and removed rules are the difference from the release before it;
  the unreleased version uses the rules of the tree;
- `bench/X.Y.Z/`: cvebench results of a release. The main and TypeScript sets are kept
  whole; of the hold-out set only the summary is kept, so its cases stay unpublished.

At a release:

```sh
go run ./cmd/sitegen -snapshot X.Y.Z
go run ./cmd/sitegen -import-bench X.Y.Z -commit <sha> -main cves.md -holdout holdout.md -ts cves-ts.md
# date the release in CHANGELOG.md, then:
go generate ./cmd/sitegen
```

Commit the result and run the `pages` workflow by hand.
