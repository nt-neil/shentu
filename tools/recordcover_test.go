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
// line by line ("file: the line", trimmed), each with its reason. A line
// more, or one gone or changed, fails TestNoHostReadsBypass: a new one is
// to go through hostSource or be listed here with its reason. hostenv
// (the host source itself, Live) and detect (the logs it reads, its state)
// are not scanned (a known issue).
var hostReadsBypass = map[string]struct {
	N   int // the times the line is there
	Why string
}{
	"tools/alas.go: if info, err := os.Stat(\"/var/lib/shentu\"); err == nil && info.IsDir() && os.Geteuid() == 0 {":      {1, "shentu's own cache of Amazon Linux advisories"},
	"tools/alas.go: if c, err := os.Open(cached); err == nil {":                                                           {1, "shentu's own cache of Amazon Linux advisories"},
	"tools/alas.go: f, err := os.Open(p)":                                                                                 {1, "shentu's own cache of Amazon Linux advisories"},
	"tools/alas.go: return os.Open(path)":                                                                                 {1, "shentu's own cache of Amazon Linux advisories"},
	"tools/alas.go: old, _ := filepath.Glob(filepath.Join(dir, \"alas-*\"))":                                              {1, "shentu's own cache of Amazon Linux advisories"},
	"tools/alas.go: tmps, _ := filepath.Glob(filepath.Join(dir, \".alas-*\"))":                                            {1, "shentu's own cache of Amazon Linux advisories"},
	"tools/alas.go: if st, err := os.Stat(f); err == nil && time.Since(st.ModTime()) > time.Hour {":                       {1, "shentu's own cache of Amazon Linux advisories"},
	"tools/codeaudit.go: if info, err := os.Stat(\"/var/lib/shentu\"); err == nil && info.IsDir() && os.Geteuid() == 0 {": {1, "shentu's state directory"},
	"tools/codecalls.go: if info, err := os.Stat(exe); err == nil {":                                                      {1, "shentu's kept audit results and its own executable"},
	"tools/codecalls.go: b, err := os.ReadFile(name)":                                                                     {2, "shentu's kept audit results and its own executable"},
	"tools/codecalls.go: names, _ := filepath.Glob(filepath.Join(dir, \"codecalls-*.json\"))":                             {1, "shentu's kept audit results and its own executable"},
	"tools/codecalls.go: if info, err := os.Lstat(n); err == nil && info.Mode().IsRegular() {":                            {1, "shentu's kept audit results and its own executable"},
	"tools/codecalls.go: if _, err := os.Lstat(f); errors.Is(err, fs.ErrNotExist) {":                                      {1, "shentu's kept audit results and its own executable"},
	"tools/files.go: return filepath.EvalSymlinks(root)":                                                                  {1, "a Windows web root resolved on this machine, the host itself (watchRoot)"},
	"tools/files.go: m, _ := filepath.Glob(g)":                                                                            {1, "certbot's certificates (cert_expiry): not recorded (known issue)"},
	"tools/files.go: b, err := os.ReadFile(f)":                                                                            {1, "certbot's certificates (cert_expiry): not recorded (known issue)"},
	"tools/firewall.go: if exec.CommandContext(ctx, \"nft\", \"list\", \"table\", \"inet\", nftTable).Run() == nil {":     {1, "nft on this machine: block_ip acts, it does not read the host"},
	"tools/firewall.go: cmd := exec.CommandContext(ctx, \"nft\", \"-f\", \"-\")":                                          {1, "nft on this machine: block_ip acts, it does not read the host"},
	"tools/firewall.go: if out, err := exec.CommandContext(ctx, \"nft\", args...).CombinedOutput(); err != nil {":         {1, "nft on this machine: block_ip acts, it does not read the host"},
	"tools/imagepkgs.go: if _, err := os.Lstat(dockerDaemonJSON); err == nil {":                                           {1, "Docker's and containerd's image stores: not recorded (known issue)"},
	"tools/imagepkgs.go: _, err := os.Lstat(content)":                                                                     {1, "Docker's and containerd's image stores: not recorded (known issue)"},
	"tools/imagepkgs.go: st, err := os.Lstat(p)":                                                                          {1, "Docker's and containerd's image stores: not recorded (known issue)"},
	"tools/imagepkgs.go: switch _, err := os.Lstat(root); {":                                                              {1, "Docker's and containerd's image stores: not recorded (known issue)"},
	"tools/imagepkgs.go: if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {":                                      {1, "Docker's and containerd's image stores: not recorded (known issue)"},
	"tools/imagepkgs.go: err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {":                     {1, "Docker's and containerd's image stores: not recorded (known issue)"},
	"tools/overlay_linux.go: st, ok := fi.Sys().(*syscall.Stat_t)":                                                        {1, "an overlay layer's whiteout and opaque marks of the image stores: not recorded (known issue)"},
	"tools/overlay_linux.go: if n, err := syscall.Getxattr(p, a, buf); err == nil && n == 1 && buf[0] == 'y' {":           {1, "an overlay layer's whiteout and opaque marks of the image stores: not recorded (known issue)"},
}

var hostReadRe = regexp.MustCompile(`\bos\.(ReadFile|Open|OpenFile|ReadDir|Stat|Lstat|Readlink|DirFS)\(|\bexec\.(Command|CommandContext|LookPath)\(|\bfilepath\.(Walk|WalkDir|Glob|EvalSymlinks)\(|\bioutil\.|\bsyscall\.|\bunix\.`)

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
			name := filepath.ToSlash(n)
			if dir == "." {
				name = "tools/" + name
			} else {
				name = strings.TrimPrefix(name, "../")
			}
			for _, l := range strings.Split(string(b), "\n") {
				if hostReadRe.MatchString(l) {
					got[name+": "+strings.TrimSpace(l)]++
				}
			}
		}
	}
	for k, n := range got {
		if hostReadsBypass[k].N != n {
			t.Errorf("reads the machine without hostSource %d times, listed %d: %s\n(go through hostSource, or list the line with its reason)", n, hostReadsBypass[k].N, k)
		}
	}
	for k, w := range hostReadsBypass {
		if got[k] == 0 {
			t.Errorf("listed (%d) but not there (gone or changed): %s", w.N, k)
		}
	}
}
