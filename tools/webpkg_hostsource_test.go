package tools

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// pkgHost is a Source answering exact argvs and files, recording the argvs.
type pkgHost struct {
	mu    sync.Mutex
	out   map[string]string // argv joined by " " -> stdout
	files map[string]string
	ran   [][]string
}

func (h *pkgHost) Info() hostenv.SourceInfo {
	return hostenv.SourceInfo{GOOS: "linux", GOARCH: "amd64"}
}
func (h *pkgHost) ReadFile(p string) ([]byte, error) {
	if b, ok := h.files[p]; ok {
		return []byte(b), nil
	}
	return nil, fs.ErrNotExist
}
func (h *pkgHost) ReadDir(string) ([]string, error) { return nil, fs.ErrNotExist }
func (h *pkgHost) Readlink(string) (string, error)  { return "", fs.ErrNotExist }
func (h *pkgHost) Run(_ context.Context, argv []string) (hostenv.CmdResult, error) {
	h.mu.Lock()
	h.ran = append(h.ran, argv)
	h.mu.Unlock()
	if o, ok := h.out[strings.Join(argv, " ")]; ok {
		return hostenv.CmdResult{Stdout: []byte(o)}, nil
	}
	return hostenv.CmdResult{ExitCode: 1}, nil
}

// The nginx and Apache checks ask the host source, not the machine running
// them: on a host where nothing can be read they find nothing, whatever is
// installed where the test runs (a CI runner's nginx).
func TestWebPackagesEmptyHost(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"format":"`+hostenv.FixtureFormat+`","info":{"goos":"linux","goarch":"amd64"},"entries":[]}`), 0o600)
	os.Mkdir(filepath.Join(dir, "blobs"), 0o700)
	rp, err := hostenv.LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
	ctx := context.Background()
	if in := nginxVersion(ctx); in.version != "" || in.pkg != "" || in.removed {
		t.Errorf("nginx on an empty host: %+v", in)
	}
	if rs := nginxRisks(ctx); len(rs) != 0 {
		t.Errorf("nginx risks on an empty host: %v", rs)
	}
	if v := apacheVersion(ctx); v != "" {
		t.Errorf("Apache on an empty host: %q", v)
	}
	if log := nginxChangelog(ctx, "nginx", "dpkg") + nginxChangelog(ctx, "nginx", "rpm"); log != "" {
		t.Errorf("a changelog on an empty host: %d bytes", len(log))
	}
}

// Through the host source the versions are still found, and every argv the
// checks run is in the Linux allowlist (the live runner refuses others).
func TestWebPackagesThroughHostSource(t *testing.T) {
	h := &pkgHost{out: map[string]string{
		strings.Join(hostenv.DpkgStatusArgv("nginx-core"), " "): "installed 1.24.0-2ubuntu7",
		strings.Join(hostenv.DpkgVersionArgv("apache2"), " "):   "2.4.58-1ubuntu8",
		strings.Join(hostenv.RPMChangelogArgv("nginx"), " "):    "- fix CVE-2026-123007",
	}, files: map[string]string{}}
	withHost(t, h)
	ctx := context.Background()
	if in := nginxVersion(ctx); in.version != "1.24.0-2ubuntu7" || in.pkg != "nginx-core" || in.dist != "dpkg" {
		t.Errorf("nginx: %+v", in)
	}
	if v := apacheVersion(ctx); v != "2.4.58-1ubuntu8" {
		t.Errorf("Apache: %q", v)
	}
	if log := nginxChangelog(ctx, "nginx", "rpm"); !mentionsCVE(log, "CVE-2026-123007") {
		t.Errorf("rpm changelog: %q", log)
	}
	r, err := hostenv.NewRunner(hostenv.LinuxCollector{}.Allowlist())
	if err != nil {
		t.Fatal(err)
	}
	for _, argv := range h.ran {
		if !r.Allowed(argv) {
			t.Errorf("not in the Linux allowlist: %q", argv)
		}
	}
	if len(h.ran) == 0 {
		t.Error("no command ran")
	}
}

// A package query that exits non-zero is not an answer.
func TestWebPackagesExitCode(t *testing.T) {
	h := &pkgHost{out: map[string]string{}, files: map[string]string{}}
	withHost(t, h)
	if _, err := ngxRun(context.Background(), hostenv.DpkgStatusArgv("nginx")); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("exit 1: %v", err)
	}
}
