package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxDownload = 512 << 20

// downloadHosts are the only hosts cvebench downloads from, redirects included.
var downloadHosts = map[string]bool{
	"downloads.wordpress.org": true,
	"codeload.github.com":     true,
	"pypi.org":                true,
	"files.pythonhosted.org":  true,
	"registry.npmjs.org":      true,
}

func newClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return allowedURL(req.URL)
		},
	}
}

func allowedURL(u *url.URL) error {
	if u.Scheme != "https" || !downloadHosts[u.Hostname()] || u.Port() != "" {
		return fmt.Errorf("refusing to download from %s", u.Redacted())
	}
	return nil
}

// fetcher downloads release archives into dir/dl and unpacks each one into its
// own directory under dir/src.
type fetcher struct {
	dir    string
	client *http.Client

	mu    sync.Mutex
	locks map[string]*sync.Mutex // one per release, so two cases never unpack the same one at once
}

func (f *fetcher) lock(key string) func() {
	f.mu.Lock()
	if f.locks == nil {
		f.locks = map[string]*sync.Mutex{}
	}
	l := f.locks[key]
	if l == nil {
		l = &sync.Mutex{}
		f.locks[key] = l
	}
	f.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// release returns the directory holding the unpacked release, downloading and
// unpacking it first if the cache does not have it.
func (f *fetcher) release(c Case, version string) (string, error) {
	pkg := strings.NewReplacer("/", "__", "@", "").Replace(c.Package)
	dest := filepath.Join(f.dir, "src", c.Ecosystem, pkg, version)
	defer f.lock(dest)()
	if _, err := os.Stat(dest); err == nil {
		return dest, nil
	}
	src, err := f.archive(c, version, pkg)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	// Unpack into a new empty directory and move it into place only when
	// complete, so a directory under src is always a whole release.
	tmp, err := os.MkdirTemp(filepath.Dir(dest), ".unpack-")
	if err != nil {
		return "", err
	}
	if err := unpack(src, tmp); err != nil {
		return "", fmt.Errorf("%s: %w (partial files left in %s)", filepath.Base(src), err, tmp)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	return dest, nil
}

// archive returns the cached archive of a release, downloading it if needed.
func (f *fetcher) archive(c Case, version, pkg string) (string, error) {
	loc, err := f.locate(c, version)
	if err != nil {
		return "", err
	}
	name := filepath.Join(f.dir, "dl", c.Ecosystem, pkg, version+loc.ext)
	if _, err := os.Stat(name); err == nil {
		return name, nil
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return "", err
	}
	if err := f.download(loc, name); err != nil {
		return "", err
	}
	return name, nil
}

// location is where a release archive is and, when the registry publishes
// one, the digest it must have.
type location struct {
	url, ext string
	sum      func() hash.Hash
	want     []byte
}

func (f *fetcher) locate(c Case, version string) (location, error) {
	switch c.Ecosystem {
	case "wordpress-plugin":
		return location{url: "https://downloads.wordpress.org/plugin/" + c.Package + "." + version + ".zip", ext: ".zip"}, nil
	case "composer":
		return location{url: "https://codeload.github.com/" + c.Package + "/tar.gz/refs/tags/" + url.PathEscape(version), ext: ".tar.gz"}, nil
	case "pypi":
		b, err := f.get("https://pypi.org/pypi/" + c.Package + "/" + version + "/json")
		if err != nil {
			return location{}, err
		}
		return pypiSdist(b)
	case "npm":
		b, err := f.get("https://registry.npmjs.org/" + strings.Replace(c.Package, "/", "%2F", 1) + "/" + version)
		if err != nil {
			return location{}, err
		}
		return npmTarball(b)
	}
	return location{}, fmt.Errorf("unknown ecosystem %s", c.Ecosystem)
}

// pypiSdist picks the source distribution from a PyPI release's JSON.
func pypiSdist(b []byte) (location, error) {
	var meta struct {
		URLs []struct {
			PackageType string `json:"packagetype"`
			Filename    string `json:"filename"`
			URL         string `json:"url"`
			Digests     struct {
				SHA256 string `json:"sha256"`
			} `json:"digests"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return location{}, err
	}
	for _, u := range meta.URLs {
		if u.PackageType != "sdist" {
			continue
		}
		var ext string
		switch {
		case strings.HasSuffix(u.Filename, ".tar.gz"):
			ext = ".tar.gz"
		case strings.HasSuffix(u.Filename, ".zip"):
			ext = ".zip"
		default:
			return location{}, fmt.Errorf("sdist %s is neither .tar.gz nor .zip", u.Filename)
		}
		want, err := hex.DecodeString(u.Digests.SHA256)
		if err != nil || len(want) != sha256.Size {
			return location{}, fmt.Errorf("sdist %s has no sha256", u.Filename)
		}
		return location{url: u.URL, ext: ext, sum: sha256.New, want: want}, nil
	}
	return location{}, errors.New("release has no sdist")
}

// npmTarball reads the tarball URL and its sha512 from an npm version document.
func npmTarball(b []byte) (location, error) {
	var meta struct {
		Dist struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return location{}, err
	}
	enc, ok := strings.CutPrefix(meta.Dist.Integrity, "sha512-")
	want, err := base64.StdEncoding.DecodeString(enc)
	if !ok || err != nil || len(want) != sha512.Size {
		return location{}, errors.New("version has no sha512 integrity")
	}
	return location{url: meta.Dist.Tarball, ext: ".tar.gz", sum: sha512.New, want: want}, nil
}

func (f *fetcher) get(raw string) ([]byte, error) {
	resp, err := f.open(raw)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

func (f *fetcher) open(raw string) (*http.Response, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := allowedURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "shentu-cvebench")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", u.Redacted(), resp.Status)
	}
	return resp, nil
}

// download saves loc to name, checking the size cap and the digest, and moves
// the file into place only when it is whole.
func (f *fetcher) download(loc location, name string) error {
	resp, err := f.open(loc.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(filepath.Dir(name), ".download-")
	if err != nil {
		return err
	}
	defer tmp.Close()
	var h hash.Hash
	w := io.Writer(tmp)
	if loc.sum != nil {
		h = loc.sum()
		w = io.MultiWriter(tmp, h)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return err
	}
	if n > maxDownload {
		return fmt.Errorf("%s is larger than %d MiB (partial file %s)", loc.url, maxDownload>>20, tmp.Name())
	}
	if h != nil && string(h.Sum(nil)) != string(loc.want) {
		return fmt.Errorf("%s does not match the registry's digest (file kept as %s)", loc.url, tmp.Name())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}
