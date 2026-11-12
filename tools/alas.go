package tools

// Amazon Linux's security advisories (ALAS): OSV does not carry them, so
// the repository's updateinfo.xml is read, streamed, and each advisory that
// fixes an installed package at a newer version than the one installed
// counts. The repository is public (cdn.amazonlinux.com), outside AWS too.

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

type alasHit struct {
	Package string   `json:"package"`
	Version string   `json:"version"`
	IDs     []string `json:"ids"`
}

var (
	// updateinfoData is repomd's entry for updateinfo: the file's location
	// and the sha256 of the file as served (compressed) are both taken from
	// it, so they cannot come from two entries.
	updateinfoData   = regexp.MustCompile(`(?s)<data type="updateinfo">.*?</data>`)
	updateinfoHref   = regexp.MustCompile(`<location href="([^"]+)"`)
	updateinfoSHA256 = regexp.MustCompile(`<checksum type="sha256">([0-9a-fA-F]{64})</checksum>`)
)

// alasMirrorList is hostenv.ALASMirrorList (and alasExtrasMirrorList the
// extras one), and mirrorPrefixes what a mirror they name may start with;
// tests point them at a fake repository.
var (
	alasMirrorList       = hostenv.ALASMirrorList
	alasExtrasMirrorList = hostenv.ALASExtrasMirrorList
	mirrorPrefixes       = []string{"https://cdn.amazonlinux.com/"}
)

// alasCacheDir keeps downloaded updateinfo between runs: the state
// directory when the service can write it, else the user's cache.
var alasCacheDir = func() string {
	if info, err := os.Stat("/var/lib/shentu"); err == nil && info.IsDir() && os.Geteuid() == 0 {
		return "/var/lib/shentu"
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "shentu")
	}
	return ""
}

// alasAffected returns the installed packages with security fixes pending,
// and the advisories by id. It reads the release's core repository and,
// on Amazon Linux 2, each amazon-linux-extras topic enabled (kernel-5.10,
// php8.2). Every installed version of a name counts (several kernels), and
// a fix counts for the architecture it was built for.
//
// A topic that fails (a 404, a bad checksum) leaves the core and the other
// topics checked: it is named in failed with why, and the answer is
// partial. A core that fails is an error.
func alasAffected(ctx context.Context, hc *http.Client, feed hostenv.PatchFeed, arch string, items []hostenv.Package) (hits []alasHit, advisories map[string]hostenv.Advisory, failed []string, err error) {
	pruneALASTemp()
	mirrors := []string{alasMirrorList(feed.Release, arch)}
	if feed.Release == "2" {
		for _, topic := range feed.Repos {
			if u := alasExtrasMirrorList(topic, arch); u != "" {
				mirrors = append(mirrors, u)
			}
		}
	}
	installed := map[string][]hostenv.Package{}
	names := map[string]bool{}
	for _, p := range items {
		installed[p.Name], names[p.Name] = append(installed[p.Name], p), true
	}
	advs := map[string]hostenv.Advisory{}
	byKey := map[string]*alasHit{} // name and version
	used := map[string]bool{}
	for i, ml := range mirrors {
		r, cached, err := updateinfo(ctx, hc, ml)
		if err != nil {
			if i == 0 {
				return nil, nil, nil, err
			}
			failed = append(failed, extrasTopicOf(ml, feed.Repos)+": "+err.Error())
			continue
		}
		used[cached] = true
		err = hostenv.ScanUpdateInfo(r, names, func(a hostenv.Advisory) {
			for name := range a.Fixed {
				for _, p := range installed[name] {
					fixed, ok := a.FixedArch[hostenv.FixedKey(name, p.Arch)]
					if !ok {
						fixed, ok = a.FixedArch[hostenv.FixedKey(name, "noarch")]
					}
					if !ok && p.Arch == "" {
						fixed, ok = a.Fixed[name], true
					}
					if !ok || hostenv.CompareEVR(p.Version, fixed) >= 0 {
						continue
					}
					advs[a.ID] = a
					k := name + "\x00" + p.Version
					h := byKey[k]
					if h == nil {
						h = &alasHit{Package: name, Version: p.Version}
						byKey[k] = h
					}
					if !slices.Contains(h.IDs, a.ID) {
						h.IDs = append(h.IDs, a.ID)
					}
				}
			}
		})
		r.Close()
		if err != nil && i == 0 {
			return nil, nil, nil, fmt.Errorf("updateinfo: %w", err)
		}
		if err != nil {
			failed = append(failed, extrasTopicOf(ml, feed.Repos)+": updateinfo: "+err.Error())
		}
	}
	pruneALASCache(used)
	var out []alasHit
	for _, h := range byKey {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return hostenv.CompareEVR(out[i].Version, out[j].Version) < 0
	})
	return out, advs, failed, nil
}

// extrasTopicOf names the topic whose mirror list ml is.
func extrasTopicOf(ml string, topics []string) string {
	for _, t := range topics {
		if strings.Contains(ml, "/"+t+"/") {
			return "extras topic " + t
		}
	}
	return "extras " + ml
}

// updateinfo opens a repository's updateinfo (unpacked), from the cache
// when it holds it: a mirror path names the repository's content (a hash),
// so the same path is the same file. cached is the cache file ("" none).
func updateinfo(ctx context.Context, hc *http.Client, mirrorList string) (io.ReadCloser, string, error) {
	base, err := httpFirstLine(ctx, hc, mirrorList)
	if err != nil {
		return nil, "", fmt.Errorf("mirror list: %w", err)
	}
	base = strings.TrimSuffix(base, "/") + "/"
	repomd, err := httpBody(ctx, hc, base+"repodata/repomd.xml", 1<<20)
	if err != nil {
		return nil, "", fmt.Errorf("repomd: %w", err)
	}
	d := updateinfoData.Find(repomd)
	m := updateinfoHref.FindSubmatch(d)
	if m == nil {
		return nil, "", errors.New("the repository lists no updateinfo")
	}
	want := "" // the checksum repomd gives, when it gives one
	if c := updateinfoSHA256.FindSubmatch(d); c != nil {
		want = strings.ToLower(string(c[1]))
	}
	url := base + string(m[1])
	sum := sha256.Sum256([]byte(url))
	cached := ""
	var f io.ReadCloser
	if dir := alasCacheDir(); dir != "" {
		cached = filepath.Join(dir, "alas-"+hex.EncodeToString(sum[:8])+path.Ext(string(m[1])))
		if want != "" && fileSHA256(cached) != want {
			os.Remove(cached) // cut short or damaged: fetched again below
		}
		if c, err := os.Open(cached); err == nil {
			f = c
		}
	}
	if f == nil {
		body, err := httpStream(ctx, hc, url)
		if err != nil {
			return nil, "", err
		}
		f = body
		if cached != "" {
			saved, err := saveCache(cached, body)
			if err != nil {
				return nil, "", err
			}
			if want != "" && fileSHA256(cached) != want {
				saved.Close()
				os.Remove(cached)
				return nil, "", errors.New("updateinfo does not match the checksum repomd gives")
			}
			f = saved
		}
	}
	if !strings.HasSuffix(string(m[1]), ".gz") {
		return f, cached, nil
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, "", err
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(gz, 2<<30), f}, cached, nil
}

// fileSHA256 is the hex sha256 of a file, "" when it cannot be read.
func fileSHA256(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// saveCache writes body (at most 512 MiB) to path through a temporary file
// (mode 0600) and opens the result; body is closed.
func saveCache(path string, body io.ReadCloser) (io.ReadCloser, error) {
	defer body.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".alas-")
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(tmp, io.LimitReader(body, 512<<20+1))
	if err == nil && n > 512<<20 {
		err = errors.New("updateinfo over 512 MiB")
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	return os.Open(path)
}

// pruneALASCache removes cached updateinfo no repository of this host
// names any more (each repository update gives a new file).
func pruneALASCache(used map[string]bool) {
	dir := alasCacheDir()
	if dir == "" {
		return
	}
	old, _ := filepath.Glob(filepath.Join(dir, "alas-*"))
	for _, f := range old {
		if !used[f] {
			os.Remove(f)
		}
	}
}

// pruneALASTemp removes downloads left half way by an earlier run (a
// temporary file older than an hour: none of this run's).
func pruneALASTemp() {
	dir := alasCacheDir()
	if dir == "" {
		return
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, ".alas-*"))
	for _, f := range tmps {
		if st, err := os.Stat(f); err == nil && time.Since(st.ModTime()) > time.Hour {
			os.Remove(f)
		}
	}
}

func httpStream(ctx context.Context, hc *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("updateinfo: HTTP %d", resp.StatusCode)
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, 512<<20), resp.Body}, nil
}

func httpFirstLine(ctx context.Context, hc *http.Client, url string) (string, error) {
	b, err := httpBody(ctx, hc, url, 64<<10)
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	if sc.Scan() {
		for _, p := range mirrorPrefixes {
			if strings.HasPrefix(sc.Text(), p) {
				return strings.TrimSpace(sc.Text()), nil
			}
		}
	}
	return "", errors.New("no https mirror in " + url)
}

func httpBody(ctx context.Context, hc *http.Client, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}
