package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fakeDocker is Docker's overlay2 image store, made at run time.
type fakeDocker struct {
	t     *testing.T
	root  string
	repos map[string]map[string]string
	n     int
}

func hexOf(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

// withDocker makes an empty store the scan reads, as root.
func withDocker(t *testing.T) *fakeDocker {
	t.Helper()
	d := &fakeDocker{t: t, root: t.TempDir(), repos: map[string]map[string]string{}}
	oldR, oldJ, oldC, oldE, oldW, oldO := dockerRoot, dockerDaemonJSON, containerdRoot, imageEuid, overlayWhiteout, overlayOpaque
	t.Cleanup(func() {
		dockerRoot, dockerDaemonJSON, containerdRoot, imageEuid, overlayWhiteout, overlayOpaque = oldR, oldJ, oldC, oldE, oldW, oldO
	})
	dockerRoot, dockerDaemonJSON, containerdRoot = d.root, filepath.Join(d.root, "no-daemon.json"), filepath.Join(d.root, "no-containerd")
	imageEuid = func() int { return 0 }
	os.MkdirAll(filepath.Join(d.root, "image", "overlay2", "imagedb", "content", "sha256"), 0o700)
	d.save()
	return d
}

func (d *fakeDocker) save() {
	b, _ := json.Marshal(map[string]any{"Repositories": d.repos})
	os.WriteFile(filepath.Join(d.root, "image", "overlay2", "repositories.json"), b, 0o600)
}

// image adds an image of these layers (path → content; a path ending in
// "/" a folder), tagged tags, and gives its ID.
func (d *fakeDocker) image(layers []map[string]string, tags ...string) string {
	d.t.Helper()
	d.n++
	store := filepath.Join(d.root, "image", "overlay2")
	var diffIDs []string
	chain := ""
	for i, l := range layers {
		diff := "sha256:" + hexOf(fmt.Sprintf("image %d layer %d", d.n, i))
		diffIDs = append(diffIDs, diff)
		if chain == "" {
			chain = diff
		} else {
			chain = "sha256:" + hexOf(chain+" "+diff)
		}
		cache := hexOf("cache " + chain)
		ldir := filepath.Join(store, "layerdb", "sha256", strings.TrimPrefix(chain, "sha256:"))
		os.MkdirAll(ldir, 0o700)
		os.WriteFile(filepath.Join(ldir, "cache-id"), []byte(cache), 0o600)
		dir := filepath.Join(d.root, "overlay2", cache, "diff")
		os.MkdirAll(dir, 0o700)
		for p, c := range l {
			full := filepath.Join(dir, filepath.FromSlash(p))
			if strings.HasSuffix(p, "/") {
				os.MkdirAll(full, 0o755)
				continue
			}
			os.MkdirAll(filepath.Dir(full), 0o755)
			os.WriteFile(full, []byte(c), 0o644)
		}
	}
	cfg, _ := json.Marshal(map[string]any{"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}})
	id := hexOf(string(cfg))
	os.WriteFile(filepath.Join(store, "imagedb", "content", "sha256", id), cfg, 0o600)
	for _, tag := range tags {
		repo, _, _ := strings.Cut(tag, ":")
		if d.repos[repo] == nil {
			d.repos[repo] = map[string]string{}
		}
		d.repos[repo][tag] = "sha256:" + id
		d.repos[repo][repo+"@sha256:"+hexOf("digest "+tag)] = "sha256:" + id
	}
	d.save()
	return id
}

// layerOf is where image n's layer i is on disk (the fixture's names).
func (d *fakeDocker) layerOf(n, i int) string {
	chain := ""
	for k := 0; k <= i; k++ {
		diff := "sha256:" + hexOf(fmt.Sprintf("image %d layer %d", n, k))
		if chain == "" {
			chain = diff
		} else {
			chain = "sha256:" + hexOf(chain+" "+diff)
		}
	}
	return filepath.Join(d.root, "overlay2", hexOf("cache "+chain), "diff")
}

const sp312 = "usr/local/lib/python3.12/site-packages/"

func meta(name, version string) string {
	return "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n\n"
}

func imageResults(t *testing.T, f *pypiFeeds) (map[string]any, map[string]AppResult) {
	t.Helper()
	out, err := AppVulns(context.Background(), &http.Client{Transport: f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := out["files"].([]AppResult)
	got := map[string]AppResult{}
	for _, r := range files {
		got[r.Path] = r
	}
	return out, got
}

// An image's packages are its layers stacked: a higher layer's version
// replaces a lower one's, a whiteout (.wh.<name>) deletes a package in its
// own folder only, an opaque folder (.wh..wh..opq, or overlayfs' xattr)
// hides the lower layers' in it. Under usr/lib only pip's are read. Each
// image is checked once under its first tag; the KEV mark comes as for a
// site-packages folder. On integ no image was read.
func TestImagePackages(t *testing.T) {
	noSystemSitePackages(t)
	d := withDocker(t)
	d.image([]map[string]string{
		{
			sp312 + "requests-2.19.1.dist-info/METADATA":                          meta("requests", "2.19.1"),
			sp312 + "LiteLLM-1.30.0.dist-info/METADATA":                           meta("LiteLLM", "1.30.0"),
			sp312 + "gone-1.0.dist-info/METADATA":                                 meta("gone", "1.0"),
			sp312 + "sub/keep-1.0.dist-info/METADATA":                             meta("keep", "1.0"), // not a site-packages folder's own
			"usr/lib/python3/dist-packages/aptpkg-1.0.dist-info/METADATA":         meta("aptpkg", "1.0"),
			"usr/lib/python3/dist-packages/pippkg-1.0.dist-info/METADATA":         meta("pippkg", "1.0"),
			"usr/lib/python3/dist-packages/pippkg-1.0.dist-info/INSTALLER":        "pip\n",
			"opt/venv/lib/python3.12/site-packages/hidden-1.0.dist-info/METADATA": meta("hidden", "1.0"),
			"srv/other/site-packages/.wh.zzz":                                     "",
			"srv/other/site-packages/twin-1.0.dist-info/METADATA":                 meta("twin", "1.0"),
		},
		{
			sp312 + ".wh.requests-2.19.1.dist-info":                            "",
			sp312 + "requests-2.32.5.dist-info/METADATA":                       meta("requests", "2.32.5"),
			sp312 + ".wh.gone-1.0.dist-info":                                   "",
			"srv/elsewhere/.wh.twin-1.0.dist-info":                             "", // another folder: srv/other's stays
			"opt/venv/lib/python3.12/site-packages/.wh..wh..opq":               "",
			"opt/venv/lib/python3.12/site-packages/new-1.0.dist-info/METADATA": meta("new", "1.0"),
			sp312 + "distutils-precedence.pth":                                 "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
			sp312 + "evil.pth":                                                 "import os\n",
		},
	}, "app:1", "app:latest")
	f := &pypiFeeds{
		vulns:   map[string][]string{"litellm@1.30.0": {"GHSA-test-lite"}, "requests@2.19.1": {"PYSEC-old"}},
		aliases: map[string][]string{"GHSA-test-lite": {"CVE-2026-40217"}},
		kev:     []string{"CVE-2026-40217"},
	}
	out, got := imageResults(t, f)
	r := got["docker-image:app:1"]
	if r.Kind != "image" || r.Ecosystem != "PyPI" || len(got) != 1 {
		t.Fatalf("results %+v", got)
	}
	sort.Strings(f.queries)
	if q := strings.Join(f.queries, " "); q != "litellm@1.30.0 new@1.0 pippkg@1.0 requests@2.32.5 twin@1.0" {
		t.Errorf("queried %q", q)
	}
	if len(r.Exploited) != 1 || r.Exploited[0].Package != "litellm" || len(r.Affected) != 1 {
		t.Errorf("affected %+v exploited %+v", r.Affected, r.Exploited)
	}
	pth, _ := out["pth"].([]PthFile)
	want := []PthFile{
		{Path: "docker-image:app:1:/" + sp312 + "distutils-precedence.pth", ImportLines: 1, Unproven: "setuptools"},
		{Path: "docker-image:app:1:/" + sp312 + "evil.pth", ImportLines: 1},
	}
	if fmt.Sprint(pth) != fmt.Sprint(want) {
		t.Errorf("pth %+v", pth)
	}
	if out["docker_images"] != 1 || out["partial"] != nil || out["docker_images_note"] != nil {
		t.Errorf("images %v, partial %v, note %v", out["docker_images"], out["partial"], out["docker_images_note"])
	}
	// overlayfs' own opaque mark, as Docker's overlay2 leaves it
	d2 := withDocker(t)
	d2.image([]map[string]string{
		{sp312 + "old-1.0.dist-info/METADATA": meta("old", "1.0")},
		{sp312: ""},
	}, "op:1")
	opaque := d2.layerOf(1, 1) + "/" + strings.TrimSuffix(sp312, "/")
	overlayOpaque = func(p string) bool { return p == opaque }
	f = &pypiFeeds{}
	imageResults(t, f)
	if len(f.queries) != 0 {
		t.Errorf("opaque by xattr: queried %q", f.queries)
	}
}

// What the scan could not read is said apart from no Docker at all, and
// a store that is there but not read is never "0 images".
func TestImagePackagesNotChecked(t *testing.T) {
	noSystemSitePackages(t)
	partial := func(out map[string]any) string { s, _ := out["partial"].(string); return s }
	feeds := &pypiFeeds{}

	d := withDocker(t)
	dockerRoot = filepath.Join(d.root, "none")
	out, _ := imageResults(t, feeds)
	if n, _ := out["docker_images_note"].(string); !strings.Contains(n, "這台沒有 Docker 映像庫") || partial(out) != "" {
		t.Errorf("no Docker: note %v, partial %q", out["docker_images_note"], partial(out))
	}

	d = withDocker(t)
	d.image([]map[string]string{{sp312 + "a-1.0.dist-info/METADATA": meta("a", "1.0")}}, "a:1")
	imageEuid = func() int { return 1000 }
	if out, _ := imageResults(t, feeds); !strings.Contains(partial(out), "要 root 才能讀") || out["docker_images"] != 0 {
		t.Errorf("not root: %q", partial(out))
	}
	imageEuid = func() int { return 0 }

	os.WriteFile(filepath.Join(d.root, "image", "overlay2", "repositories.json"), []byte("{not json"), 0o600)
	if out, _ := imageResults(t, feeds); !strings.Contains(partial(out), "repositories.json 存在但讀不到") {
		t.Errorf("bad repositories.json: %q", partial(out))
	}

	// ids that are not 64 hex digits never make a path
	d = withDocker(t)
	id := d.image([]map[string]string{{sp312 + "a-1.0.dist-info/METADATA": meta("a", "1.0")}}, "a:1")
	cache := filepath.Join(d.root, "image", "overlay2", "layerdb", "sha256", strings.TrimPrefix("sha256:"+hexOf("image 1 layer 0"), "sha256:"), "cache-id")
	os.WriteFile(cache, []byte("../../../../etc"), 0o600)
	if out, _ := imageResults(t, feeds); !strings.Contains(partial(out), "cache-id 不是 64 個十六進位字元") {
		t.Errorf("cache-id ../: %q", partial(out))
	}
	cfg := filepath.Join(d.root, "image", "overlay2", "imagedb", "content", "sha256", id)
	os.WriteFile(cfg, []byte(`{"rootfs":{"diff_ids":["sha256:../../x"]}}`), 0o600)
	if out, _ := imageResults(t, feeds); !strings.Contains(partial(out), "diff_id 不是 sha256") {
		t.Errorf("diff_id ../: %q", partial(out))
	}
	d.repos["evil"] = map[string]string{"evil:1": "sha256:../../../etc/passwd"}
	d.save()
	if out, _ := imageResults(t, feeds); out["docker_images"] != 1 {
		t.Errorf("an image id not hex was taken: %v", out["docker_images"])
	}

	// a layer folder swapped for a symlink is not followed
	d = withDocker(t)
	d.image([]map[string]string{{sp312 + "a-1.0.dist-info/METADATA": meta("a", "1.0")}}, "a:1")
	diff := d.layerOf(1, 0)
	elsewhere := t.TempDir()
	os.Rename(diff, filepath.Join(elsewhere, "diff"))
	os.Symlink(filepath.Join(elsewhere, "diff"), diff)
	if out, _ := imageResults(t, feeds); !strings.Contains(partial(out), "是 symlink") {
		t.Errorf("symlinked layer: %q", partial(out))
	}

	// the bounds
	d = withDocker(t)
	d.image([]map[string]string{{sp312 + "a-1.0.dist-info/METADATA": meta("a", "1.0"), sp312 + "b-1.0.dist-info/METADATA": meta("b", "1.0")}}, "a:1")
	d.image([]map[string]string{{sp312 + "c-1.0.dist-info/METADATA": meta("c", "1.0")}}, "c:1")
	oldI, oldE := imgMaxImages, imgMaxEntries
	t.Cleanup(func() { imgMaxImages, imgMaxEntries = oldI, oldE })
	imgMaxImages = 1
	if out, _ := imageResults(t, feeds); !strings.Contains(partial(out), "Docker 映像超過 1 個") {
		t.Errorf("image cap: %q", partial(out))
	}
	imgMaxImages, imgMaxEntries = oldI, 3
	if out, _ := imageResults(t, feeds); !strings.Contains(partial(out), "的檔案超過 3 個") {
		t.Errorf("entry cap: %q", partial(out))
	}
	imgMaxEntries = oldE

	// daemon.json's data-root: read there; one not absolute is said
	other := withDocker(t)
	other.image([]map[string]string{{sp312 + "moved-1.0.dist-info/METADATA": meta("moved", "1.0")}}, "m:1")
	dockerRoot = filepath.Join(other.root, "none")
	dockerDaemonJSON = filepath.Join(t.TempDir(), "daemon.json")
	os.WriteFile(dockerDaemonJSON, []byte(`{"data-root": "`+other.root+`"}`), 0o600)
	f := &pypiFeeds{}
	if imageResults(t, f); strings.Join(f.queries, " ") != "moved@1.0" {
		t.Errorf("data-root: %q", f.queries)
	}
	os.WriteFile(dockerDaemonJSON, []byte(`{"data-root": "var/lib/docker"}`), 0o600)
	if out, _ := imageResults(t, feeds); !strings.Contains(partial(out), "data-root 不是絕對路徑") {
		t.Errorf("relative data-root: %q", partial(out))
	}

	// a path asked about leaves the images out (a store there to read)
	dockerRoot, dockerDaemonJSON = other.root, filepath.Join(t.TempDir(), "none.json")
	f = &pypiFeeds{}
	if imageResults(t, f); len(f.queries) != 1 {
		t.Fatalf("the store is not read: %q", f.queries)
	}
	f = &pypiFeeds{}
	if out, _ := appVulnsIn(context.Background(), &http.Client{Transport: f}, []string{t.TempDir()}, false); out["docker_images"] != nil || len(f.queries) != 0 {
		t.Errorf("a path asked about read the images: %v %q", out["docker_images"], f.queries)
	}
}

// Docker's images in containerd's store (the default of new Docker
// releases: /var/lib/docker/image/overlay2 is not there) are said as not
// checked, never as no images; and a host read that is not this machine
// itself (a replay) does not read this machine's store.
func TestImagePackagesContainerdStore(t *testing.T) {
	noSystemSitePackages(t)
	partial := func(out map[string]any) string { s, _ := out["partial"].(string); return s }
	feeds := &pypiFeeds{}

	d := withDocker(t)
	img := filepath.Join(d.root, "image") // Docker's root is there, no overlay2 image store
	os.Rename(img, filepath.Join(t.TempDir(), "image"))
	os.MkdirAll(filepath.Join(containerdRoot, "io.containerd.content.v1.content", "blobs", "sha256"), 0o700)
	out, _ := imageResults(t, feeds)
	if p := partial(out); !strings.Contains(p, "Docker 映像在 containerd 存放區") || !strings.Contains(p, "這版沒有檢查") || out["docker_images_note"] != nil || out["docker_images"] != 0 {
		t.Errorf("containerd content store: partial %q, note %v, images %v", p, out["docker_images_note"], out["docker_images"])
	}

	d = withDocker(t)
	d.image([]map[string]string{{sp312 + "a-1.0.dist-info/METADATA": meta("a", "1.0")}}, "a:1")
	dockerDaemonJSON = filepath.Join(t.TempDir(), "daemon.json")
	os.WriteFile(dockerDaemonJSON, []byte(`{"features": {"containerd-snapshotter": true}}`), 0o600)
	f := &pypiFeeds{}
	out, _ = imageResults(t, f)
	if p := partial(out); !strings.Contains(p, "開了 containerd-snapshotter") || strings.Join(f.queries, " ") != "a@1.0" {
		t.Errorf("snapshotter on: partial %q, queries %q (overlay2's still read)", p, f.queries)
	}

	d = withDocker(t)
	d.image([]map[string]string{{sp312 + "a-1.0.dist-info/METADATA": meta("a", "1.0")}}, "a:1")
	withHost(t, memHost{})
	f = &pypiFeeds{}
	out, _ = imageResults(t, f)
	if p := partial(out); !strings.Contains(p, "這次讀的不是這台機器本身") || len(f.queries) != 0 {
		t.Errorf("replay read this machine's images: partial %q, queries %q", p, f.queries)
	}
}
