package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// The Python packages in Docker images (plan cd58fb installed-pkgs, the
// images' part): read from Docker's overlay2 image store on disk, the
// layers stacked as overlayfs stacks them; no container is started and
// the daemon is not asked. Each tagged image is checked against OSV as
// PyPI, as a site-packages folder is.

// dockerRoot is Docker's data root unless /etc/docker/daemon.json sets
// "data-root"; dockerDaemonJSON is that file (tests replace both).
var (
	dockerRoot       = "/var/lib/docker"
	dockerDaemonJSON = "/etc/docker/daemon.json"
	imageEuid        = os.Geteuid
)

// The scan's bounds: past one, or a file not read, is said in partial.
var (
	imgMaxImages  = 50
	imgMaxLayers  = 200
	imgMaxEntries = 200000 // entries of one image's layers walked
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// imageScan is what the image store gave: an image's packages (as a lock
// file of kind "image"), its .pth files, what was not checked (partial),
// and a note when there is nothing to check (no Docker image store).
type imageScan struct {
	files   []Lockfile
	pth     []PthFile
	partial []string
	none    string
	images  int
}

// dockerDataRoot is where Docker keeps its data: daemon.json's data-root
// when set (an absolute path), else dockerRoot.
func dockerDataRoot() (string, error) {
	b, ok := readHead(dockerDaemonJSON, 1<<20)
	if !ok {
		if _, err := os.Lstat(dockerDaemonJSON); err == nil {
			return "", fmt.Errorf("%s 讀不到", dockerDaemonJSON)
		}
		return dockerRoot, nil
	}
	var c struct {
		DataRoot string `json:"data-root"`
	}
	if json.Unmarshal(b, &c) != nil {
		return "", fmt.Errorf("%s 不是 JSON", dockerDaemonJSON)
	}
	if c.DataRoot == "" {
		return dockerRoot, nil
	}
	if !filepath.IsAbs(c.DataRoot) {
		return "", fmt.Errorf("%s 的 data-root 不是絕對路徑", dockerDaemonJSON)
	}
	return filepath.Clean(c.DataRoot), nil
}

// realDir: p is a folder itself, not a symlink to one.
func realDir(p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return errors.New("是 symlink")
	}
	if !st.IsDir() {
		return errors.New("不是資料夾")
	}
	return nil
}

// scanImages reads the tagged images of Docker's overlay2 image store.
func scanImages() imageScan {
	var s imageScan
	root, err := dockerDataRoot()
	if err != nil {
		s.partial = append(s.partial, "Docker 映像庫沒有檢查："+err.Error())
		return s
	}
	switch _, err := os.Lstat(root); {
	case errors.Is(err, fs.ErrNotExist):
		s.none = "這台沒有 Docker 映像庫（" + root + " 不存在）"
		return s
	case err != nil:
		s.partial = append(s.partial, "Docker 映像庫 "+root+" 存在但讀不到（"+errText(err)+"），裡面的映像沒有檢查")
		return s
	}
	if imageEuid() != 0 {
		s.partial = append(s.partial, "Docker 映像庫 "+root+" 要 root 才能讀，這次不是以 root 執行，裡面的映像沒有檢查")
		return s
	}
	store := filepath.Join(root, "image", "overlay2")
	for _, d := range []string{root, store} {
		if err := realDir(d); errors.Is(err, fs.ErrNotExist) && d == store {
			s.none = "這台的 Docker 映像庫沒有 overlay2 的映像（" + store + " 不存在）"
			return s
		} else if err != nil {
			s.partial = append(s.partial, "Docker 映像庫 "+d+" 存在但讀不到（"+errText(err)+"），裡面的映像沒有檢查")
			return s
		}
	}
	tags, err := imageTags(store)
	if err != nil {
		s.partial = append(s.partial, "Docker 映像庫的 repositories.json 存在但讀不到（"+err.Error()+"），裡面的映像沒有檢查")
		return s
	}
	byID := map[string][]string{}
	var ids []string
	for tag, id := range tags {
		if byID[id] == nil {
			ids = append(ids, id)
		}
		byID[id] = append(byID[id], tag)
	}
	sort.Strings(ids)
	if len(ids) > imgMaxImages {
		s.partial = append(s.partial, fmt.Sprintf("Docker 映像超過 %d 個，其餘 %d 個沒有檢查", imgMaxImages, len(ids)-imgMaxImages))
		ids = ids[:imgMaxImages]
	}
	for _, id := range ids {
		sort.Strings(byID[id])
		name := "docker-image:" + byID[id][0]
		pkgs, pth, notes := readImage(root, store, id, name)
		s.images++
		s.pth = append(s.pth, pth...)
		s.partial = append(s.partial, notes...)
		if len(pkgs) > 0 {
			s.files = append(s.files, Lockfile{Path: name, Ecosystem: "PyPI", pkgs: pkgs, kind: "image"})
		}
	}
	return s
}

// imageTags is repositories.json's tags (repo:tag → image hex), the
// digests (repo@sha256:...) left out; none when the file is not there.
func imageTags(store string) (map[string]string, error) {
	p := filepath.Join(store, "repositories.json")
	b, ok := readHead(p, 16<<20)
	if !ok {
		if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, errors.New("讀不到")
	}
	var r struct {
		Repositories map[string]map[string]string
	}
	if json.Unmarshal(b, &r) != nil {
		return nil, errors.New("不是 JSON")
	}
	out := map[string]string{}
	for _, refs := range r.Repositories {
		for ref, id := range refs {
			h, ok := strings.CutPrefix(id, "sha256:")
			if strings.Contains(ref, "@") || !ok || !hex64.MatchString(h) {
				continue
			}
			out[ref] = h
		}
	}
	return out, nil
}

// imageLayers are the diff folders of image id, bottom first: its config's
// rootfs.diff_ids, chained (chain ID n is sha256 of chain n-1, a space and
// diff ID n) to layerdb's cache-id, which names the overlay2 folder.
// Every id is 64 hex digits before it is put in a path.
func imageLayers(root, store, id string) ([]string, error) {
	b, ok := readHead(filepath.Join(store, "imagedb", "content", "sha256", id), 4<<20)
	if !ok {
		return nil, errors.New("設定檔讀不到")
	}
	var c struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if json.Unmarshal(b, &c) != nil {
		return nil, errors.New("設定檔不是 JSON")
	}
	if len(c.RootFS.DiffIDs) > imgMaxLayers {
		return nil, fmt.Errorf("有 %d 層，超過 %d 層的上限", len(c.RootFS.DiffIDs), imgMaxLayers)
	}
	var dirs []string
	chain := ""
	for _, d := range c.RootFS.DiffIDs {
		h, ok := strings.CutPrefix(d, "sha256:")
		if !ok || !hex64.MatchString(h) {
			return nil, errors.New("diff_id 不是 sha256")
		}
		if chain == "" {
			chain = d
		} else {
			sum := sha256.Sum256([]byte(chain + " " + d))
			chain = "sha256:" + hex.EncodeToString(sum[:])
		}
		ldir := filepath.Join(store, "layerdb", "sha256", strings.TrimPrefix(chain, "sha256:"))
		if err := realDir(ldir); err != nil {
			return nil, fmt.Errorf("layerdb 的一層（%s）", errText(err))
		}
		cb, ok := readHead(filepath.Join(ldir, "cache-id"), 256)
		cache := strings.TrimSpace(string(cb))
		if !ok || !hex64.MatchString(cache) {
			return nil, errors.New("cache-id 不是 64 個十六進位字元")
		}
		diff := filepath.Join(root, "overlay2", cache, "diff")
		for _, p := range []string{filepath.Dir(diff), diff} {
			if err := realDir(p); err != nil {
				return nil, fmt.Errorf("overlay2 的一層（%s）", errText(err))
			}
		}
		dirs = append(dirs, diff)
	}
	return dirs, nil
}

// layerEntry is a path of an image's merged tree: the layer it is from.
type layerEntry struct {
	layer int
	dir   bool
}

// overlayWhiteout and overlayOpaque are overlayfs' marks in a layer's diff
// folder as Docker's overlay2 leaves them: a character device 0:0 for a
// name deleted, the xattr trusted.overlay.opaque "y" for a folder that
// hides the lower layers' (overlay_linux.go; tests replace them).
var (
	overlayWhiteout = overlayWhiteoutFile
	overlayOpaque   = overlayOpaqueDir
)

// mergeLayers stacks the layers' diff folders as overlayfs does: a higher
// layer's file replaces a lower one's; a whiteout (overlayfs' device, or a
// .wh.<name> as a layer tar has it) deletes <name> in its own folder and
// what is under it, in the lower layers; an opaque folder (overlayfs'
// xattr, or .wh..wh..opq in it) hides what the lower layers have in it.
func mergeLayers(dirs []string) (map[string]layerEntry, error) {
	merged := map[string]layerEntry{}
	walked := 0
	for li, d := range dirs {
		adds := map[string]layerEntry{}
		gone := map[string]bool{}   // a whiteout: the path and all under it
		hidden := map[string]bool{} // an opaque folder: all under it
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == d {
				return nil
			}
			if walked++; walked > imgMaxEntries {
				return errWalkCap
			}
			rel, _ := filepath.Rel(d, p)
			rel = filepath.ToSlash(rel)
			parent, name := path.Dir(rel), e.Name()
			switch {
			case name == ".wh..wh..opq":
				hidden[parent] = true
				return nil
			case strings.HasPrefix(name, ".wh."):
				gone[path.Join(parent, strings.TrimPrefix(name, ".wh."))] = true // a name: no /
				return nil
			}
			if e.Type()&fs.ModeCharDevice != 0 {
				if fi, err := e.Info(); err == nil && overlayWhiteout(fi) {
					gone[rel] = true
					return nil
				}
			}
			if e.IsDir() && overlayOpaque(p) {
				hidden[rel] = true
			}
			adds[rel] = layerEntry{li, e.IsDir()} // a symlink is an entry, never followed
			return nil
		})
		if err != nil {
			return nil, err
		}
		for p := range merged {
			for q := p; q != "."; q = path.Dir(q) {
				if gone[q] || hidden[q] && q != p {
					delete(merged, p)
					break
				}
			}
		}
		for p, e := range adds {
			merged[p] = e
		}
	}
	return merged, nil
}

var errWalkCap = errors.New("walk cap")

// readImage reads one image's site-packages from its merged tree.
func readImage(root, store, id, name string) (pkgs []pkg, pth []PthFile, notes []string) {
	dirs, err := imageLayers(root, store, id)
	if err != nil {
		return nil, nil, []string{name + " 沒有檢查：" + err.Error()}
	}
	merged, err := mergeLayers(dirs)
	if errors.Is(err, errWalkCap) {
		return nil, nil, []string{fmt.Sprintf("%s 的檔案超過 %d 個，沒有檢查", name, imgMaxEntries)}
	}
	if err != nil {
		return nil, nil, []string{name + " 的一層讀不到（" + errText(err) + "），沒有檢查"}
	}
	file := func(rel string) (string, bool) { // where rel of the merged tree is on disk
		e, ok := merged[rel]
		if !ok || e.dir {
			return "", false
		}
		return filepath.Join(dirs[e.layer], filepath.FromSlash(rel)), true
	}
	sites := map[string]bool{}
	for p, e := range merged {
		if b := path.Base(p); e.dir && (b == "site-packages" || b == "dist-packages") {
			sites[p] = true
		}
	}
	dists, unread := map[string]int{}, 0
	for p, e := range merged {
		site := path.Dir(p)
		if !sites[site] {
			continue
		}
		n := path.Base(p)
		switch {
		case strings.HasSuffix(n, ".dist-info") || strings.HasSuffix(n, ".egg-info"):
			if dists[site]++; dists[site] > sitePkgDistMax {
				continue
			}
			meta := p
			if e.dir {
				meta = path.Join(p, "METADATA")
				if strings.HasSuffix(n, ".egg-info") {
					meta = path.Join(p, "PKG-INFO")
				}
			}
			if strings.HasPrefix(site, "usr/lib/") || strings.HasPrefix(site, "usr/lib64/") {
				// the image's own package manager's (apt, dnf) unless pip wrote it
				inst, ok := file(path.Join(p, "INSTALLER"))
				b, rok := readHead(inst, 256)
				if !e.dir || !ok || !rok || !pipInstallers[strings.TrimSpace(string(b))] {
					continue
				}
			}
			f, ok := file(meta)
			b, rok := readHead(f, sitePkgHead)
			nm, v := metaNameVersion(b)
			if !ok || !rok || nm == "" || v == "" {
				unread++
				continue
			}
			pkgs = append(pkgs, pkg{pep503(nm), v})
		case strings.HasSuffix(n, ".pth") && !e.dir:
			f, _ := file(p)
			b, ok := readHead(f, sitePkgHead+1)
			if !ok {
				notes = append(notes, name+":/"+p+" 讀不到，沒有檢查它會不會執行程式")
				continue
			}
			if len(b) > sitePkgHead {
				notes = append(notes, fmt.Sprintf("%s:/%s 超過 %d KiB，只檢查了前面的部分", name, p, sitePkgHead>>10))
				b = b[:sitePkgHead]
			}
			if pf, ok := pthTemplate(n, b); ok {
				pf.Path = name + ":/" + p
				pth = append(pth, pf)
			}
		}
	}
	for site, n := range dists {
		if n > sitePkgDistMax {
			notes = append(notes, fmt.Sprintf("%s:/%s 有 %d 個套件超過單一資料夾 %d 個的上限，沒有檢查", name, site, n-sitePkgDistMax, sitePkgDistMax))
		}
	}
	if unread > 0 {
		notes = append(notes, fmt.Sprintf("%s 有 %d 個套件的 METADATA 讀不到或沒有名稱、版本，沒有檢查", name, unread))
	}
	pkgs = uniq(pkgs)
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	sort.Slice(pth, func(i, j int) bool { return pth[i].Path < pth[j].Path })
	return pkgs, pth, notes
}

// pthTemplate is pthImports for a .pth in an image: never Known (whoever
// built the image wrote every file in it, as root); one whose lines are a
// tool's own (in most images: setuptools') is Unproven, as in a folder a
// user can write.
func pthTemplate(name string, b []byte) (PthFile, bool) {
	var f PthFile
	raw := strings.TrimPrefix(string(b), "\ufeff")
	var lines []string
	for _, l := range pthLines(raw) {
		if strings.HasPrefix(l, "import ") || strings.HasPrefix(l, "import\t") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return f, false
	}
	f.ImportLines = len(lines)
	plain := !strings.ContainsAny(raw, "\v\f\x1c\x1d\x1e\u0085\u2028\u2029") && utf8.ValidString(raw)
	for _, k := range knownPth {
		if !k.name.MatchString(name) {
			continue
		}
		all := plain && k.info
		for _, l := range lines {
			one := false
			for _, re := range k.lines {
				m := re.FindStringSubmatch(l)
				one = one || m != nil && (re != editableLine || m[1] == m[2])
			}
			all = all && one
		}
		if all {
			f.Unproven = k.label
		}
		break
	}
	return f, true
}
