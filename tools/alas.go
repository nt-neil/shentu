package tools

// Amazon Linux's security advisories (ALAS): OSV does not carry them, so
// the repository's updateinfo.xml is read, streamed, and each advisory that
// fixes an installed package at a newer version than the one installed
// counts. The repository is public (cdn.amazonlinux.com), outside AWS too.

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

type alasHit struct {
	Package string   `json:"package"`
	Version string   `json:"version"`
	IDs     []string `json:"ids"`
}

var updateinfoHref = regexp.MustCompile(`href="([^"]*updateinfo[^"]*)"`)

// alasMirrorList is hostenv.ALASMirrorList, and mirrorPrefixes what a
// mirror it names may start with; tests point both at a fake repository.
var (
	alasMirrorList = hostenv.ALASMirrorList
	mirrorPrefixes = []string{"https://cdn.amazonlinux.com/"}
)

// alasAffected returns the installed packages with security fixes pending,
// and the advisories by id.
func alasAffected(ctx context.Context, hc *http.Client, release, arch string, pkgs []pkg) ([]alasHit, map[string]hostenv.Advisory, error) {
	base, err := httpFirstLine(ctx, hc, alasMirrorList(release, arch))
	if err != nil {
		return nil, nil, fmt.Errorf("mirror list: %w", err)
	}
	base = strings.TrimSuffix(base, "/") + "/"
	repomd, err := httpBody(ctx, hc, base+"repodata/repomd.xml", 1<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("repomd: %w", err)
	}
	m := updateinfoHref.FindSubmatch(repomd)
	if m == nil {
		return nil, nil, errors.New("the repository lists no updateinfo")
	}
	installed := map[string]string{}
	names := map[string]bool{}
	for _, p := range pkgs {
		installed[p.Name], names[p.Name] = p.Version, true
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+string(m[1]), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("updateinfo: HTTP %d", resp.StatusCode)
	}
	var r io.Reader = io.LimitReader(resp.Body, 512<<20)
	if strings.HasSuffix(string(m[1]), ".gz") {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, err
		}
		r = io.LimitReader(gz, 2<<30)
	}
	advs := map[string]hostenv.Advisory{}
	hits := map[string]*alasHit{}
	err = hostenv.ScanUpdateInfo(r, names, func(a hostenv.Advisory) {
		for name, fixed := range a.Fixed {
			if hostenv.CompareEVR(installed[name], fixed) >= 0 {
				continue
			}
			advs[a.ID] = a
			h := hits[name]
			if h == nil {
				h = &alasHit{Package: name, Version: installed[name]}
				hits[name] = h
			}
			h.IDs = append(h.IDs, a.ID)
		}
	})
	if err != nil {
		return nil, nil, fmt.Errorf("updateinfo: %w", err)
	}
	var out []alasHit
	for _, h := range hits {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out, advs, nil
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
