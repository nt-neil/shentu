package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/nt-neil/shentu/internal/osutil"
)

var appVulns = Tool{
	Name:        "app_vulns",
	Description: "Finds application dependency lock files (npm package-lock.json, composer.lock, requirements.txt, Pipfile.lock, poetry.lock, go.mod, Gemfile.lock) under the configured app paths and checks them against OSV, marking vulnerabilities that CISA lists as actively exploited. Use it for web apps and services, which package_vulns (OS packages) does not cover.",
	Params: schema(`{"type":"object","properties":{
		"path":{"type":"string","description":"only lock files under this directory (must be inside the app paths)"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			Path string `json:"path"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		roots := env.AppPaths
		if a.Path != "" {
			clean := filepath.Clean(a.Path)
			inside := false
			for _, r := range env.AppPaths {
				if clean == r || strings.HasPrefix(clean, strings.TrimSuffix(r, "/")+"/") {
					inside = true
				}
			}
			if !inside {
				return nil, fmt.Errorf("path is not inside the app paths: %s", strings.Join(env.AppPaths, ", "))
			}
			roots = []string{clean}
		}
		return AppVulns(ctx, env.HTTP, roots)
	},
}

// Lockfile is one dependency manifest and what it pins.
type Lockfile struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
	pkgs      []pkg
}

var lockParsers = map[string]struct {
	eco   string
	parse func([]byte) []pkg
}{
	"package-lock.json": {"npm", parseNpmLock},
	"composer.lock":     {"Packagist", parseComposerLock},
	"requirements.txt":  {"PyPI", parseRequirements},
	"Pipfile.lock":      {"PyPI", parsePipfileLock},
	"poetry.lock":       {"PyPI", parsePoetryLock},
	"go.mod":            {"Go", parseGoMod},
	"Gemfile.lock":      {"RubyGems", parseGemfileLock},
}

var skipDirs = map[string]bool{"node_modules": true, ".git": true, "vendor": true, "venv": true, ".venv": true,
	"__pycache__": true, "site-packages": true, ".cache": true, "proc": true}

// FindLockfiles walks roots (at most 6 levels deep) and returns up to 100 lock files.
func FindLockfiles(roots []string) []Lockfile {
	var out []Lockfile
	for _, root := range roots {
		base := strings.Count(filepath.Clean(root), string(filepath.Separator))
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] || strings.Count(p, string(filepath.Separator))-base > 6 {
					return filepath.SkipDir
				}
				return nil
			}
			lp, ok := lockParsers[d.Name()]
			if !ok || !d.Type().IsRegular() {
				return nil
			}
			seen, err := d.Info() // lstat from the walk
			if err != nil {
				return nil
			}
			b, ok := readSmallRegular(p, 20<<20, seen)
			if !ok {
				return nil
			}
			out = append(out, Lockfile{Path: p, Ecosystem: lp.eco, pkgs: uniq(safeParse(lp.parse, b))})
			if len(out) >= 100 {
				return filepath.SkipAll
			}
			return nil
		})
	}
	return out
}

// readSmallRegular reads a file that app users may control: it does not follow a
// symlink swapped in after the walk, checks the open file itself, and reads at most max.
// When seen is set, the opened file must be the same file the walk saw, so a parent
// folder swapped for a symlink in between cannot redirect the read.
func readSmallRegular(p string, max int64, seen os.FileInfo) ([]byte, bool) {
	f, err := osutil.OpenNoFollow(p, os.O_RDONLY, 0, true)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > max || (seen != nil && !os.SameFile(seen, st)) {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, false
	}
	return b, true
}

// safeParse keeps one malformed lock file from stopping the scan or the patrol.
func safeParse(parse func([]byte) []pkg, b []byte) (out []pkg) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	return parse(b)
}

// AppHit is a vulnerable dependency in a lock file.
type AppHit struct {
	Package string   `json:"package"`
	Version string   `json:"version"`
	IDs     []string `json:"ids"`
}

// AppResult is the scan of one lock file.
type AppResult struct {
	Path      string    `json:"path"`
	Ecosystem string    `json:"ecosystem"`
	Packages  int       `json:"packages"`
	Affected  []AppHit  `json:"affected,omitempty"`
	Exploited []Exploit `json:"actively_exploited,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// AppVulns checks every lock file under roots against OSV and CISA KEV.
func AppVulns(ctx context.Context, hc *http.Client, roots []string) (map[string]any, error) {
	files := FindLockfiles(roots)
	kev, kevErr := loadKEV(ctx, hc)
	var results []AppResult
	total := 0
	for _, f := range files {
		r := AppResult{Path: f.Path, Ecosystem: f.Ecosystem, Packages: len(f.pkgs)}
		ids, err := osvBatch(ctx, hc, f.Ecosystem, f.pkgs)
		if err != nil {
			r.Error = err.Error()
			results = append(results, r)
			continue
		}
		for i, list := range ids {
			if len(list) == 0 {
				continue
			}
			p := f.pkgs[i]
			r.Affected = append(r.Affected, AppHit{p.Name, p.Version, list[:min(5, len(list))]})
			total += len(list)
			if kevErr == nil {
				for _, e := range matchKEV(kev, list, func(id string) []string { return osvCVEs(ctx, hc, id) }) {
					e.Package, e.Version = p.Name, p.Version
					r.Exploited = append(r.Exploited, e)
				}
			}
		}
		sort.Slice(r.Affected, func(i, j int) bool { return len(r.Affected[i].IDs) > len(r.Affected[j].IDs) })
		if len(r.Affected) > 20 {
			r.Affected = r.Affected[:20]
		}
		results = append(results, r)
	}
	out := map[string]any{"searched": roots, "lock_files": len(files), "total_vulns": total, "files": results}
	if len(files) == 0 {
		out["note"] = "no lock files found; set [tools] app_paths to where your apps live"
	}
	if kevErr != nil {
		out["kev"] = "CISA KEV list unavailable: " + kevErr.Error()
	}
	return out, nil
}

// osvBatch returns the vulnerability IDs for each package, in order.
func osvBatch(ctx context.Context, hc *http.Client, eco string, pkgs []pkg) ([][]string, error) {
	out := make([][]string, len(pkgs))
	for start := 0; start < len(pkgs); start += 500 {
		chunk := pkgs[start:min(start+500, len(pkgs))]
		qs := make([]map[string]any, len(chunk))
		for i, p := range chunk {
			qs[i] = map[string]any{"package": map[string]string{"name": p.Name, "ecosystem": eco}, "version": p.Version}
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := postJSON(ctx, hc, osvAPI+"/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
			return nil, fmt.Errorf("OSV query failed: %w", err)
		}
		for i, r := range resp.Results {
			if i >= len(chunk) {
				break
			}
			for _, v := range r.Vulns {
				out[start+i] = append(out[start+i], v.ID)
			}
		}
	}
	return out, nil
}

func parseNpmLock(b []byte) []pkg {
	var l struct {
		Packages     map[string]struct{ Version string } `json:"packages"`
		Dependencies map[string]json.RawMessage          `json:"dependencies"`
	}
	if json.Unmarshal(b, &l) != nil {
		return nil
	}
	var out []pkg
	for k, v := range l.Packages {
		if k == "" || v.Version == "" {
			continue
		}
		i := strings.LastIndex(k, "node_modules/")
		if i < 0 {
			continue // a workspace folder, not an installed package
		}
		out = append(out, pkg{k[i+len("node_modules/"):], v.Version})
	}
	if len(l.Packages) == 0 { // lockfileVersion 1
		var walk func(map[string]json.RawMessage)
		walk = func(deps map[string]json.RawMessage) {
			for name, raw := range deps {
				var d struct {
					Version      string                     `json:"version"`
					Dependencies map[string]json.RawMessage `json:"dependencies"`
				}
				if json.Unmarshal(raw, &d) == nil && d.Version != "" {
					out = append(out, pkg{name, d.Version})
					walk(d.Dependencies)
				}
			}
		}
		walk(l.Dependencies)
	}
	return out
}

func parseComposerLock(b []byte) []pkg {
	var l struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	json.Unmarshal(b, &l)
	var out []pkg
	for _, p := range append(l.Packages, l.PackagesDev...) {
		if p.Name != "" && p.Version != "" {
			out = append(out, pkg{p.Name, strings.TrimPrefix(p.Version, "v")})
		}
	}
	return out
}

var reqLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!_-]+)`)

func parseRequirements(b []byte) []pkg {
	var out []pkg
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if m := reqLine.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
			out = append(out, pkg{strings.ToLower(m[1]), m[2]})
		}
	}
	return out
}

func parsePipfileLock(b []byte) []pkg {
	var l map[string]json.RawMessage
	if json.Unmarshal(b, &l) != nil {
		return nil
	}
	var out []pkg
	for _, section := range []string{"default", "develop"} {
		var deps map[string]struct{ Version string }
		json.Unmarshal(l[section], &deps)
		for name, d := range deps {
			if v := strings.TrimPrefix(d.Version, "=="); v != "" && v != d.Version {
				out = append(out, pkg{strings.ToLower(name), v})
			}
		}
	}
	return out
}

func parsePoetryLock(b []byte) []pkg {
	var l struct {
		Package []struct{ Name, Version string } `toml:"package"`
	}
	if _, err := toml.Decode(string(b), &l); err != nil {
		return nil
	}
	var out []pkg
	for _, p := range l.Package {
		out = append(out, pkg{strings.ToLower(p.Name), p.Version})
	}
	return out
}

var goReq = regexp.MustCompile(`^(?:require\s+)?([a-zA-Z0-9.\-_~/]+\.[a-z]+/[^\s]+)\s+(v[0-9][^\s]*)`)

func parseGoMod(b []byte) []pkg {
	var out []pkg
	for _, l := range strings.Split(string(b), "\n") {
		if m := goReq.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			out = append(out, pkg{m[1], m[2]})
		}
	}
	return out
}

var gemLine = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([^)\s]+)\)$`)

func parseGemfileLock(b []byte) []pkg {
	var out []pkg
	for _, l := range strings.Split(string(b), "\n") {
		if m := gemLine.FindStringSubmatch(strings.TrimRight(l, "\r")); m != nil {
			out = append(out, pkg{m[1], m[2]})
		}
	}
	return out
}
