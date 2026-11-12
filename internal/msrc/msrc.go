// Package msrc checks a Windows Server's OS build against Microsoft's
// monthly security releases (the public MSRC CVRF API, no key) and lists
// the CVEs whose fixes the host does not have yet.
//
// Each monthly CVRF document is about 30 MB; only the fixes for Windows
// Server products are kept, as a small index cached on disk (in the state
// directory, never in the repository). Cumulative updates mean a host
// that has one month's fixed build has every older month's fixes, so the
// check walks back from the newest month and stops at the first month the
// host is current with.
package msrc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultAPI is the public MSRC CVRF v3 endpoint.
const DefaultAPI = "https://api.msrc.microsoft.com/cvrf/v3.0"

// Fix is one CVE's fix for one product.
type Fix struct {
	CVE        string `json:"cve"`
	Title      string `json:"title,omitempty"`
	Severity   string `json:"severity,omitempty"` // Critical, Important, ...
	KB         string `json:"kb,omitempty"`       // "5044281"
	FixedBuild string `json:"fixed_build"`        // "10.0.20348.2762"
	// Hotpatch marks a hotpatch update (SubType SecurityHotpatchUpdate):
	// its build is on a branch of its own, not the cumulative chain.
	Hotpatch bool `json:"hotpatch,omitempty"`
}

// Month is the cached index of one release: product name → fixes, for
// Windows Server products only.
type Month struct {
	ID       string           `json:"id"` // "2026-Oct"
	Fetched  time.Time        `json:"fetched"`
	Products map[string][]Fix `json:"products"`
}

// Server reports whether product is a Windows Server edition MSRC names,
// e.g. "Windows Server 2022 (Server Core installation)".
func Server(product string) bool { return strings.HasPrefix(product, "Windows Server ") }

// cvrfVuln is the part of a CVRF vulnerability the index needs.
type cvrfVuln struct {
	CVE   string
	Title struct{ Value string }
	// Type 3 is severity; Type 2 a vendor fix (KB, FixedBuild).
	Threats []struct {
		Type        int
		Description struct{ Value string }
		ProductID   []string
	}
	Remediations []struct {
		Type        int
		SubType     string
		Description struct{ Value string }
		ProductID   []string
		FixedBuild  string
	}
}

// ParseCVRF reads a CVRF JSON document as a stream (ProductTree must come
// before Vulnerability, as MSRC writes it) and keeps the fixes for the
// products keep accepts.
func ParseCVRF(r io.Reader, keep func(product string) bool) (map[string][]Fix, error) {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("msrc: not a CVRF document: %v", err)
	}
	names := map[string]string{} // ProductID → name, kept products only
	out := map[string][]Fix{}
	seenTree := false
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t {
		case "ProductTree":
			var tree struct {
				FullProductName []struct{ ProductID, Value string }
			}
			if err := dec.Decode(&tree); err != nil {
				return nil, fmt.Errorf("msrc: ProductTree: %w", err)
			}
			for _, p := range tree.FullProductName {
				if keep(p.Value) {
					names[p.ProductID] = p.Value
				}
			}
			seenTree = true
		case "Vulnerability":
			if !seenTree {
				return nil, errors.New("msrc: Vulnerability before ProductTree")
			}
			if t, err := dec.Token(); err != nil || t != json.Delim('[') {
				return nil, fmt.Errorf("msrc: Vulnerability is not a list: %v", err)
			}
			for dec.More() {
				var v cvrfVuln
				if err := dec.Decode(&v); err != nil {
					return nil, fmt.Errorf("msrc: Vulnerability: %w", err)
				}
				addFixes(out, names, &v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}
		}
	}
	if !seenTree {
		return nil, errors.New("msrc: no ProductTree")
	}
	return out, nil
}

func addFixes(out map[string][]Fix, names map[string]string, v *cvrfVuln) {
	sev := map[string]string{}
	for _, t := range v.Threats {
		if t.Type == 3 {
			for _, id := range t.ProductID {
				sev[id] = t.Description.Value
			}
		}
	}
	for _, r := range v.Remediations {
		if r.Type != 2 || r.FixedBuild == "" {
			continue
		}
		for _, id := range r.ProductID {
			name, ok := names[id]
			if !ok {
				continue
			}
			out[name] = append(out[name], Fix{CVE: v.CVE, Title: v.Title.Value, Severity: sev[id],
				KB: strings.TrimPrefix(r.Description.Value, "KB"), FixedBuild: r.FixedBuild,
				Hotpatch: strings.Contains(strings.ToLower(r.SubType), "hotpatch")})
		}
	}
}

// CompareBuild compares dotted build numbers ("10.0.20348.2762").
func CompareBuild(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Missing is a fix the host lacks.
type Missing struct {
	Fix
	Month string `json:"month"`
}

// Result is the outcome of Check.
type Result struct {
	Product   string    `json:"product"`
	HostBuild string    `json:"host_build"`
	Missing   []Missing `json:"missing"`
	Months    []string  `json:"months_checked"`
	// Current is the newest month the host already has; empty when the
	// walk stopped at maxMonths first (the host may be missing more).
	Current string `json:"current_with,omitempty"`
	// CannotTell are CVEs fixed only by a hotpatch in a month with no
	// cumulative update for the product: whether the host has the fix
	// cannot be told from its build.
	CannotTell []Missing `json:"cannot_tell,omitempty"`
}

// Check walks months (newest first, fetched lazily by get) for product
// until it reaches a month whose every CVE the host has a fix for. One CVE
// may list several fixes for a product (the cumulative update and a
// hotpatch, or a monthly rollup and a security-only update): any one of
// them covers it. A fix counts as present when its KB is installed, or
// when the host build is at least its fixed build; a hotpatch's build is
// on a branch of its own, so for a hotpatch only that exact build counts. When no checked month names the
// product at all, the answer is unknown: an error, not "nothing missing".
func Check(product, hostBuild string, installedKB map[string]bool, ids []string, maxMonths int, get func(id string) (Month, error)) (Result, error) {
	res := Result{Product: product, HostBuild: hostBuild}
	named := false
	for _, id := range ids {
		if len(res.Months) >= maxMonths {
			break
		}
		m, err := get(id)
		if err != nil {
			return res, fmt.Errorf("msrc %s: %w", id, err)
		}
		res.Months = append(res.Months, id)
		fixes := m.Products[product]
		if len(fixes) == 0 {
			continue
		}
		named = true
		var order []string
		byCVE := map[string][]Fix{}
		for _, f := range fixes {
			if _, ok := byCVE[f.CVE]; !ok {
				order = append(order, f.CVE)
			}
			byCVE[f.CVE] = append(byCVE[f.CVE], f)
		}
		// The month's cumulative update for the product: the highest
		// non-hotpatch fixed build. It carries every fix of the month.
		monthCU, cuFix := "", Fix{}
		for _, f := range fixes {
			if !f.Hotpatch && (monthCU == "" || CompareBuild(f.FixedBuild, monthCU) > 0) {
				monthCU, cuFix = f.FixedBuild, f
			}
		}
		lacking, unknown := 0, 0
		for _, cve := range order {
			// The fix reported is a cumulative update, never a hotpatch: a
			// host short of the month's cumulative update cannot take that
			// month's hotpatch (it needs the baseline first), and the
			// cumulative update carries the fix too.
			covered, newest, hotOnly := false, byCVE[cve][0], true
			for _, f := range byCVE[cve] {
				if present(f, hostBuild, installedKB) {
					covered = true
				}
				hotOnly = hotOnly && f.Hotpatch
				if newest.Hotpatch && !f.Hotpatch || newest.Hotpatch == f.Hotpatch && CompareBuild(f.FixedBuild, newest.FixedBuild) > 0 {
					newest = f
				}
			}
			if hotOnly && monthCU != "" {
				newest = cuFix
				newest.CVE = cve
			}
			if !covered && hotOnly {
				// Listed with a hotpatch alone: a host on the cumulative chain
				// has it with the month's cumulative update.
				switch {
				case monthCU == "":
					unknown++
					res.CannotTell = append(res.CannotTell, Missing{newest, id})
					continue
				case CompareBuild(hostBuild, monthCU) >= 0:
					covered = true
				}
			}
			if !covered {
				lacking++
				res.Missing = append(res.Missing, Missing{newest, id})
			}
		}
		if lacking == 0 && unknown == 0 {
			res.Current = id
			break
		}
	}
	if !named {
		return res, fmt.Errorf("msrc: none of the %d releases checked names %q", len(res.Months), product)
	}
	return res, nil
}

// present reports whether the host has fix f.
func present(f Fix, hostBuild string, installedKB map[string]bool) bool {
	if installedKB[f.KB] {
		return true
	}
	if f.Hotpatch {
		return CompareBuild(hostBuild, f.FixedBuild) == 0
	}
	return CompareBuild(hostBuild, f.FixedBuild) >= 0
}

// Client fetches the release list and monthly indexes, caching both under
// CacheDir (when set).
type Client struct {
	HTTP     *http.Client
	API      string // DefaultAPI when empty
	CacheDir string
	Now      func() time.Time
}

func (c *Client) api() string {
	if c.API != "" {
		return c.API
	}
	return DefaultAPI
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	return resp.Body, nil
}

// Releases returns the monthly release IDs, newest first.
func (c *Client) Releases(ctx context.Context) ([]string, error) {
	type update struct {
		ID                 string
		InitialReleaseDate time.Time
	}
	var list []update
	if !c.readCache("updates.json", 24*time.Hour, &list) {
		body, err := c.get(ctx, c.api()+"/updates")
		if err != nil {
			return nil, err
		}
		defer body.Close()
		var doc struct{ Value []update }
		if err := json.NewDecoder(body).Decode(&doc); err != nil {
			return nil, fmt.Errorf("msrc updates: %w", err)
		}
		list = doc.Value
		c.writeCache("updates.json", list)
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].InitialReleaseDate.After(list[j].InitialReleaseDate) })
	ids := make([]string, 0, len(list))
	for _, u := range list {
		if u.ID != "" {
			ids = append(ids, u.ID)
		}
	}
	return ids, nil
}

// Month returns the Windows Server index of one release. The two newest
// releases are refreshed weekly (MSRC revises them), older ones monthly.
func (c *Client) Month(ctx context.Context, id string, recent bool) (Month, error) {
	if strings.ContainsAny(id, `/\.`) {
		return Month{}, fmt.Errorf("msrc: bad release id %q", id)
	}
	ttl := 30 * 24 * time.Hour
	if recent {
		ttl = 7 * 24 * time.Hour
	}
	var m Month
	// ".v2": the index gained Fix.Hotpatch; an older one would count a
	// hotpatch build as cumulative.
	if c.readCache(id+".v2.json", ttl, &m) && m.ID == id {
		return m, nil
	}
	body, err := c.get(ctx, c.api()+"/cvrf/"+id)
	if err != nil {
		return Month{}, err
	}
	defer body.Close()
	prods, err := ParseCVRF(body, Server)
	if err != nil {
		return Month{}, err
	}
	m = Month{ID: id, Fetched: c.now().UTC(), Products: prods}
	c.writeCache(id+".v2.json", m)
	return m, nil
}

func (c *Client) cachePath(name string) string { return filepath.Join(c.CacheDir, "msrc", name) }

func (c *Client) readCache(name string, ttl time.Duration, out any) bool {
	if c.CacheDir == "" {
		return false
	}
	p := c.cachePath(name)
	st, err := os.Stat(p)
	if err != nil || c.now().Sub(st.ModTime()) > ttl {
		return false
	}
	b, err := os.ReadFile(p)
	return err == nil && json.Unmarshal(b, out) == nil
}

// writeCache stores out atomically; a failed write only costs a refetch.
func (c *Client) writeCache(name string, out any) {
	if c.CacheDir == "" {
		return
	}
	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	// The cache folder may be created only inside a state directory that
	// already exists (Shentu made it, with its protected permissions on
	// Windows): never the state directory itself, as whoever runs this.
	if _, err := os.Stat(filepath.Dir(c.CacheDir)); err != nil {
		return
	}
	dir := filepath.Dir(c.cachePath(name))
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil || cerr != nil || os.Rename(f.Name(), c.cachePath(name)) != nil {
		os.Remove(f.Name())
	}
}
