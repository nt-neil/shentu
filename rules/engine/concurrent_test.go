package engine

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// One Engine scans files from several goroutines at once (the audit does), with
// the same findings as one after the other. Run with -race to check it shares
// nothing it writes.
func TestScanConcurrent(t *testing.T) {
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs)
	if err != nil {
		t.Fatal(err)
	}
	ext := map[string]string{"php": ".php", "python": ".py", "js": ".js"}
	type file struct{ name, code string }
	var files []file
	for _, r := range rs {
		for i, s := range r.Samples {
			files = append(files, file{fmt.Sprintf("%s-%d%s", r.ID, i, ext[r.Lang]), s.Code})
		}
	}
	key := func(fs []Finding) []string {
		var out []string
		for _, f := range fs {
			out = append(out, fmt.Sprintf("%s:%d %s", f.Path, f.Line, f.RuleID))
		}
		slices.Sort(out)
		return out
	}
	want := make([][]string, len(files))
	for i, f := range files {
		fs, _ := e.ScanFile(f.name, []byte(f.code))
		want[i] = key(fs)
	}
	got := make([][]string, len(files))
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; i < len(files); i += 8 {
				fs, _ := e.ScanFile(files[i].name, []byte(files[i].code))
				got[i] = key(fs)
			}
		}()
	}
	wg.Wait()
	for i := range files {
		if !slices.Equal(got[i], want[i]) {
			t.Errorf("%s: concurrent %v, alone %v", files[i].name, got[i], want[i])
		}
	}
}
