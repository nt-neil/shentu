package hostenv

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite facts.golden.json from the fixtures")

// TestReplayGolden replays every recorded fixture under testdata/<os>/<case>
// and compares the facts with facts.golden.json beside it. Record a fixture
// with `hostfacts -record DIR` on a real host, then run with -update once.
func TestReplayGolden(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join("testdata", "*", "*", "manifest.json"))
	if len(dirs) == 0 {
		t.Skip("no recorded fixtures yet")
	}
	for _, m := range dirs {
		dir := filepath.Dir(m)
		t.Run(filepath.ToSlash(dir), func(t *testing.T) {
			rp, err := LoadReplay(dir)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(Collect(context.Background(), rp), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := filepath.Join(dir, "facts.golden.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if string(got) != string(want) {
				t.Errorf("facts differ from %s; rerun with -update if the change is intended", golden)
			}
		})
	}
}
