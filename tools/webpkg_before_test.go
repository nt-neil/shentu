package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

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
	if rs := nginxH2Risk(ctx); len(rs) != 0 {
		t.Errorf("nginx risks on an empty host: %v", rs)
	}
	if v := apacheVersion(ctx); v != "" {
		t.Errorf("Apache on an empty host: %q", v)
	}
	if log := nginxChangelog(ctx, "nginx", "dpkg") + nginxChangelog(ctx, "nginx", "rpm"); log != "" {
		t.Errorf("a changelog on an empty host: %d bytes", len(log))
	}
}

