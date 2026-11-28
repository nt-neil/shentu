package tools

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// anyHost is a "live" host for a recording: the files of a fixture, plus
// overlay, and every other path not there (never "not recorded"), so what
// the recording leaves out shows only in the replay made from it.
type anyHost struct {
	rp      *hostenv.Replay
	overlay map[string]string
	dirs    map[string][]string
}

func notThere(err error) error {
	if errors.Is(err, hostenv.ErrNotRecorded) {
		return fs.ErrNotExist
	}
	return err
}

func (h anyHost) Info() hostenv.SourceInfo { return h.rp.Info() }
func (h anyHost) ReadFile(p string) ([]byte, error) {
	if s, ok := h.overlay[p]; ok {
		return []byte(s), nil
	}
	b, err := h.rp.ReadFile(p)
	return b, notThere(err)
}
func (h anyHost) stat(p string, f func(string) (hostenv.FileStat, error)) (hostenv.FileStat, error) {
	if s, ok := h.overlay[p]; ok {
		return hostenv.FileStat{Mode: 0o644, Size: int64(len(s))}, nil
	}
	if _, ok := h.dirs[p]; ok {
		return hostenv.FileStat{Mode: fs.ModeDir | 0o755}, nil
	}
	st, err := f(p)
	return st, notThere(err)
}
func (h anyHost) Stat(p string) (hostenv.FileStat, error)  { return h.stat(p, h.rp.Stat) }
func (h anyHost) Lstat(p string) (hostenv.FileStat, error) { return h.stat(p, h.rp.Lstat) }
func (h anyHost) ReadDir(p string) ([]string, error) {
	if n, ok := h.dirs[p]; ok {
		return n, nil
	}
	n, err := h.rp.ReadDir(p)
	return n, notThere(err)
}
func (h anyHost) Readlink(p string) (string, error) {
	s, err := h.rp.Readlink(p)
	return s, notThere(err)
}
func (h anyHost) Run(ctx context.Context, argv []string) (hostenv.CmdResult, error) {
	r, err := h.rp.Run(ctx, argv)
	if errors.Is(err, hostenv.ErrNotRecorded) {
		return hostenv.CmdResult{}, fs.ErrNotExist // as a command not installed
	}
	return r, err
}

// S5 (v0.5.8 VM acceptance): every read the survey makes of a host is in
// that host's recording (hostfacts -record): a replay of it answers each
// one, none "not recorded". Fails on the base: cloud-init's configuration
// (the default_user of 90-cloud-init-users) was never recorded, and the
// replay lost sudo:nopasswd:cloud-init.
func TestRecordingCoversSurvey(t *testing.T) {
	base, err := hostenv.LoadReplay("../hostenv/testdata/linux/ubuntu2404-root")
	if err != nil {
		t.Fatal(err)
	}
	live := anyHost{rp: base, overlay: map[string]string{
		"/etc/cloud/cloud.cfg":                "system_info:\n  default_user:\n    name: ubuntu\n",
		"/etc/cloud/cloud.cfg.d/90-users.cfg": "# none\n",
		"/etc/sudoers.d/90-cloud-init-users":  "ubuntu ALL=(ALL) NOPASSWD:ALL\n",
	}, dirs: map[string][]string{"/etc/cloud/cloud.cfg.d": {"90-users.cfg"}}}
	sd, _ := base.ReadDir("/etc/sudoers.d")
	live.dirs["/etc/sudoers.d"] = append(sd, "90-cloud-init-users")
	sort.Strings(live.dirs["/etc/sudoers.d"])
	dir := filepath.Join(t.TempDir(), "fx")
	if _, err := RecordHost(context.Background(), live, dir, func(*hostenv.Facts) *hostenv.Masker { return &hostenv.Masker{} }); err != nil {
		t.Fatal(err)
	}
	rp, err := hostenv.LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(SetHostSourceForTest(rp))
	p := Survey(context.Background(), &Env{})
	seen := map[string]bool{}
	var miss []string
	for _, m := range rp.Missed() {
		if !seen[m] {
			seen[m] = true
			miss = append(miss, m)
		}
	}
	sort.Strings(miss)
	if len(miss) > 0 {
		t.Errorf("the survey read %d things the recording left out:\n%s", len(miss), strings.Join(miss, "\n"))
	}
	found := false
	for _, r := range p.Risks {
		found = found || r.Key == "sudo:nopasswd:cloud-init"
	}
	if !found {
		t.Errorf("the replay lost sudo:nopasswd:cloud-init: %+v", p.Risks)
	}
}

// hostReadsBypass are the reads of the machine in tools and checks that do
// not go through hostSource, so a recording does not hold them (S-305-1),
// counted per file. One more, or one gone, fails TestNoHostReadsBypass: a
// new one is to go through hostSource or be added here with its reason.
var hostReadsBypass = map[string]int{
	"tools/alas.go":      7, // shentu's own cache of Amazon Linux advisories
	"tools/codeaudit.go": 1, // shentu's state directory
	"tools/codecalls.go": 6, // shentu's kept audit results and its own executable
	"tools/files.go":     2, // certbot's certificates (cert_expiry): not recorded (known issue)
	"tools/firewall.go":  3, // nft on this machine: block_ip acts, it does not read the host
	"tools/imagepkgs.go": 6, // Docker's and containerd's image stores: not recorded (known issue)
}

var hostReadRe = regexp.MustCompile(`\bos\.(ReadFile|Open|OpenFile|ReadDir|Stat|Lstat|Readlink)\(|\bexec\.(Command|CommandContext|LookPath)\(|\bfilepath\.(Walk|WalkDir|Glob)\(|\bioutil\.`)

func TestNoHostReadsBypass(t *testing.T) {
	got := map[string]int{}
	for _, dir := range []string{".", "../checks"} {
		names, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(names) == 0 {
			t.Fatal(dir, err)
		}
		for _, n := range names {
			if strings.HasSuffix(n, "_test.go") {
				continue
			}
			b, err := os.ReadFile(n)
			if err != nil {
				t.Fatal(err)
			}
			if c := len(hostReadRe.FindAll(b, -1)); c > 0 {
				got[filepath.ToSlash(filepath.Join("tools", n))] = c
			}
		}
	}
	norm := map[string]int{}
	for k, v := range got {
		norm[strings.Replace(k, "tools/../", "", 1)] = v
	}
	for k, v := range norm {
		if hostReadsBypass[k] != v {
			t.Errorf("%s reads the machine without hostSource %d times, the list says %d: go through hostSource, or list it with its reason", k, v, hostReadsBypass[k])
		}
	}
	for k, v := range hostReadsBypass {
		if _, ok := norm[k]; !ok {
			t.Errorf("%s is listed (%d) but has none: take it off the list", k, v)
		}
	}
}
