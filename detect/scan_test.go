package detect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// Review 3, N-5: the signals come out of the read, with where they are.
func TestScanAccessSignals(t *testing.T) {
	src, d := logDir(t)
	lines := []string{
		`203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET /ok HTTP/1.1" 200 1 "-" "-"`,
		`not a line of this format`,
		`203.0.113.8 - x` + strings.Repeat(" [", 200) + ` [15/Nov/2026:10:11:12 +0800] "GET /s HTTP/1.1" 200 1 "-" "-"`,
		`203.0.113.9 - - [15/Nov/2026:10:11:12 +0800] "GET /cut?q=` + strings.Repeat("A", MaxLine),
	}
	write(t, filepath.Join(d, "a.log"), strings.Join(lines, "\n")+"\n", os.O_CREATE)
	ls := hostenv.LogSource{Path: "/logs/a.log", Server: "nginx", Kind: "access", Format: "combined", Spec: ngxCombinedSpec}
	var paths []string
	_, _, sig, err := ScanAccess(src, ls, nil, "/logs/a.log (head_len out of 0..256)", NewBudget(DefaultBudgetBytes, time.Minute), nil, func(r AccessRecord, _ Line) {
		paths = append(paths, r.Path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if sig.Lines != 4 || sig.Unparsed.Count != 1 || sig.Suspicious.Count != 1 || sig.Cut.Count != 1 || sig.Dropped == "" {
		t.Fatalf("signals %+v", sig)
	}
	if s := sig.Unparsed.Samples[0]; s.File != "/logs/a.log" || s.Offset != int64(len(lines[0])+1) {
		t.Errorf("unparsed sample %+v, want offset %d", s, len(lines[0])+1)
	}
	if strings.Join(paths, ",") != "/ok,/s,/cut" {
		t.Errorf("records %v", paths)
	}
	if _, _, _, err := ScanAccess(src, hostenv.LogSource{Path: "/logs/a.log", Server: "nginx", Kind: "access", Spec: `$request`}, nil, "", NewBudget(1, time.Minute), nil, func(AccessRecord, Line) {}); !errors.Is(err, ErrFormatUnrecognized) {
		t.Errorf("unparseable format: %v", err)
	}
}
