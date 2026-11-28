package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// livePkgHost answers as a live host does: Run masked, RunUnmasked as
// written.
type livePkgHost struct{ *pkgHost }

func (h livePkgHost) Run(ctx context.Context, argv []string) (hostenv.CmdResult, error) {
	r, err := h.pkgHost.Run(ctx, argv)
	r.Stdout, r.Stderr = []byte(hostenv.MaskSecrets(string(r.Stdout))), hostenv.MaskSecrets(r.Stderr)
	return r, err
}
func (h livePkgHost) RunUnmasked(ctx context.Context, argv []string) (hostenv.CmdResult, error) {
	return h.pkgHost.Run(ctx, argv)
}

// S-293-3: rpm's changelog is searched for CVE ids as written: an unclosed
// key BEGIN in an entry masked the entries after it, and a backported fix
// read as open. Through the host source, nginx's and an upstream's.
func TestRPMChangelogAsWritten(t *testing.T) {
	cl := "- note -----BEGIN " + "RSA PRIVATE KEY-----\n- fix CVE-2026-123007\n"
	h := livePkgHost{&pkgHost{out: map[string]string{
		strings.Join(hostenv.RPMChangelogArgv("nginx"), " "):   cl,
		strings.Join(hostenv.RPMChangelogArgv("libssh2"), " "): cl,
	}, files: map[string]string{}}}
	withHost(t, h)
	ctx := context.Background()
	if log := nginxChangelog(ctx, "nginx", "rpm"); !mentionsCVE(log, "CVE-2026-123007") {
		t.Errorf("nginx: the backport after a key BEGIN not read: %q", log)
	}
	if log := upstreamChangelog(ctx, "libssh2", "rpm"); !mentionsCVE(log, "CVE-2026-123007") {
		t.Errorf("upstream: the backport after a key BEGIN not read: %q", log)
	}
}
