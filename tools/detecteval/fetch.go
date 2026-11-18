package main

import (
	"archive/tar"
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
	"sort"
	"strings"
	"time"
)

// The nuclei-templates (MIT) the evaluation runs: release v10.5.2. Only
// this commit, and the hash of its http/ templates, are kept here; the
// templates are downloaded when the evaluation runs.
const (
	templatesCommit = "5442582a875f96887bfe403c6de562de460897e7"
	templatesURL    = "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/" + templatesCommit
	// templatesHash is manifestHash of the commit's http/**/*.yaml.
	templatesHash = "259cb2836719cc15521784577b2bdc334d1183a141d7ad7f364dc8e7469edb8c"
)

// wantHash is what templates checks against: templatesHash, which only a
// test replaces (with its own placeholder archive's).
var wantHash = templatesHash

// Limits on what is downloaded and read out of it.
const (
	maxExtracted = 256 << 20 // the http/ templates, together
	maxTemplate  = 16 << 20  // one template (the largest, a WordPress plugin list, is ~5 MB)
	maxTemplates = 50000     // http/**/*.yaml (11835 at the commit)
)

// The limits a test lowers, to reach them without gigabytes.
var (
	maxDownload int64 = 512 << 20 // the tarball
	maxUnpacked int64 = 1 << 30   // the whole archive unpacked, every entry (58 MB at the commit)
	maxEntries        = 100000    // entries in the archive (15526 at the commit)
)

// Why the evaluation did not run: said apart, never a pass.
var (
	errDownload = errors.New("download failed")
	errHash     = errors.New("hash mismatch")
	errArchive  = errors.New("archive refused")
)

// retryBase: the first wait before a retry; each one after waits twice as
// long (2s, 4s, 8s).
var retryBase = 2 * time.Second

// download fetches url into dir, trying 3 more times on failure. The
// compressed tarball is written there (a temporary directory the caller
// removes; a job killed before that leaves it to the runner's cleanup):
// only what is read out of it stays in memory.
func download(ctx context.Context, url, dir string) (string, error) {
	f := filepath.Join(dir, "templates.tar.gz")
	var last error
	for i := 0; i < 4; i++ {
		if i > 0 {
			select {
			case <-time.After(retryBase << (i - 1)):
			case <-ctx.Done():
				return "", fmt.Errorf("%w: %v", errDownload, ctx.Err())
			}
		}
		if last = fetchOnce(ctx, url, f); last == nil {
			return f, nil
		}
	}
	return "", fmt.Errorf("%w: %v", errDownload, last)
}

func fetchOnce(ctx context.Context, url, f string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	out, err := os.OpenFile(f, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, maxDownload+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxDownload {
		err = fmt.Errorf("larger than %d bytes", maxDownload)
	}
	return err
}

// readTemplates reads the http/**/*.yaml files out of a GitHub tarball
// (one top directory), keyed by their path below it (http/...). Nothing
// read out of it is written to disk. A name with "..", an absolute one, or a link or other
// non-regular entry under http/ refuses the archive, as does going past
// the limits (sizes, entries, templates).
func readTemplates(tarball string) (map[string][]byte, error) {
	fh, err := os.Open(tarball)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return readTar(fh)
}

func readTar(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errArchive, err)
	}
	tr := tar.NewReader(&capped{r: gz, left: maxUnpacked})
	out := map[string][]byte{}
	var total int64
	for entries := 1; ; entries++ {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errArchive, err)
		}
		if entries > maxEntries {
			return nil, fmt.Errorf("%w: more than %d entries", errArchive, maxEntries)
		}
		name := h.Name
		if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || slicesContains(strings.Split(name, "/"), "..") {
			return nil, fmt.Errorf("%w: entry name %q", errArchive, name)
		}
		_, rel, ok := strings.Cut(name, "/") // below the top directory
		if !ok || !(rel == "http" || strings.HasPrefix(rel, "http/")) {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default: // a link, a device: not what a template is
			return nil, fmt.Errorf("%w: %s is not a regular file", errArchive, rel)
		}
		if path.Clean(rel) != rel || path.Ext(rel) != ".yaml" {
			continue
		}
		if len(out) >= maxTemplates {
			return nil, fmt.Errorf("%w: more than %d http templates", errArchive, maxTemplates)
		}
		if h.Size > maxTemplate {
			return nil, fmt.Errorf("%w: %s larger than %d bytes", errArchive, rel, maxTemplate)
		}
		if total += h.Size; total > maxExtracted {
			return nil, fmt.Errorf("%w: http/ templates larger than %d bytes", errArchive, maxExtracted)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxTemplate+1))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errArchive, err)
		}
		if int64(len(b)) != h.Size {
			return nil, fmt.Errorf("%w: %s size differs from its header", errArchive, rel)
		}
		out[rel] = b
	}
}

// capped reads r until left bytes are read, then fails: an archive that
// unpacks to more is refused, whatever its entries.
type capped struct {
	r    io.Reader
	left int64
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, fmt.Errorf("unpacks to more than %d bytes", maxUnpacked)
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

func slicesContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// manifestHash is the sha256 of the lines "<path>\x00<sha256 of file>\n",
// sorted by path: the same templates hash the same however the tarball
// around them was packed.
func manifestHash(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		s := sha256.Sum256(files[n])
		fmt.Fprintf(h, "%s\x00%s\n", n, hex.EncodeToString(s[:]))
	}
	return hex.EncodeToString(h.Sum(nil))
}
