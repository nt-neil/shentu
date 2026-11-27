package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"

	"github.com/nt-neil/shentu/hostenv"
)

var appVulns = Tool{
	Name:        "app_vulns",
	Description: "Finds application dependency lock files (npm package-lock.json, composer.lock, requirements.txt, Pipfile.lock, poetry.lock, go.mod, Gemfile.lock) under the configured app paths and checks them against OSV, marking vulnerabilities that CISA lists as actively exploited. The Python packages installed in site-packages folders (venvs under the app paths, and the system's when no path is given) are checked the same way, and .pth files there that run code at every Python start are listed (known names the tool whose own file it is; one without it is worth a look). Use it for web apps and services, which package_vulns (OS packages) does not cover.",
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
			if !insideAny(clean, env.AppPaths) {
				return nil, fmt.Errorf("path is not inside the app paths: %s", strings.Join(env.AppPaths, ", "))
			}
			roots = []string{clean}
		}
		return appVulnsIn(ctx, env.HTTP, roots, a.Path == "") // the system's site-packages only when not asked about one path
	},
}

// Lockfile is one dependency manifest and what it pins.
type Lockfile struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
	pkgs      []pkg
	kind      string // "site-packages": a folder of installed packages, not a lock file
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

// FindLockfiles walks roots (at most 6 levels deep) through the host source
// and returns up to 100 lock files.
func FindLockfiles(roots []string) []Lockfile {
	var out []Lockfile
	src := hostSource()
	for _, root := range roots {
		hp := hostPaths() // the host's spelling (S-272-2)
		base := strings.Count(hp.Clean(root), hp.Sep)
		hostenv.Walk(src, root, func(p string, st hostenv.FileStat, err error) error {
			if err != nil {
				return nil
			}
			name := filepath.Base(p)
			if st.Mode.IsDir() {
				if skipDirs[name] || strings.Count(p, hp.Sep)-base > 6 {
					return filepath.SkipDir
				}
				return nil
			}
			lp, ok := lockParsers[name]
			if !ok || !st.Mode.IsRegular() {
				return nil
			}
			b, ok := readAt(src, p, 20<<20, st) // the file the walk's lstat saw
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

// readAt reads, through src, the regular file at p a walk's Lstat saw (st):
// not past a link, only if it is still that file, at most max bytes; as
// v0.2.5 readSmallRegular did on the machine.
func readAt(src hostenv.Source, p string, max int64, st hostenv.FileStat) ([]byte, bool) {
	if !st.Mode.IsRegular() || st.Size > max {
		return nil, false
	}
	b, err := hostenv.ReadFileIfSameMax(src, p, st, max)
	return b, err == nil
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
	// Kind is "site-packages" for a folder of installed packages
	// (Path is the folder), empty for a lock file.
	Kind string `json:"kind,omitempty"`
	// cves: the CVEs each advisory id stands for, as OSV answered the KEV
	// check (a GHSA and a PYSEC id of one vulnerability name the same CVE);
	// for detect (SurfaceApps), not the model.
	cves map[string][]string
}

// AppVulns checks every lock file under roots against OSV and CISA KEV, and
// the Python packages installed in site-packages folders under roots and
// the system's.
func AppVulns(ctx context.Context, hc *http.Client, roots []string) (map[string]any, error) {
	return appVulnsIn(ctx, hc, roots, true)
}

func appVulnsIn(ctx context.Context, hc *http.Client, roots []string, system bool) (map[string]any, error) {
	files := FindLockfiles(roots)
	nLock := len(files)
	siteDirs, partial := findSitePackages(roots, system)
	walked := len(partial) == 0 // every site-packages folder found
	var pth []PthFile
	for _, d := range siteDirs {
		sd := readSitePackages(d)
		partial = append(partial, sd.notes...)
		pth = append(pth, sd.pth...)
		if len(sd.pkgs) > 0 {
			files = append(files, Lockfile{Path: d, Ecosystem: "PyPI", pkgs: sd.pkgs, kind: "site-packages"})
		}
	}
	var img imageScan
	if system { // the host's Docker images: the whole host's check, not a path asked about
		img = scanImages(ctx, hostSource())
		files = append(files, img.files...)
		pth = append(pth, img.pth...)
	}
	if unverifiedDistutilsHack(siteDirs, walked) {
		for i := range pth {
			if strings.HasSuffix(pth[i].Path, "distutils-precedence.pth") {
				pth[i].Known, pth[i].Unproven = "", "" // its module may be another's: one to look at
			}
		}
	}
	kev, kevErr := loadKEV(ctx, hc)
	var results []AppResult
	total, kevUnchecked := 0, 0
	for _, f := range files {
		r := AppResult{Path: f.Path, Ecosystem: f.Ecosystem, Packages: len(f.pkgs), Kind: f.kind, cves: map[string][]string{}}
		var cmu sync.Mutex
		lookup := func(id string) ([]string, bool) { // matchKEV asks concurrently
			list, ok := osvCVEs(ctx, hc, id)
			if ok {
				cmu.Lock()
				r.cves[id] = list
				cmu.Unlock()
			}
			return list, ok
		}
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
				matched, n := matchKEV(kev, list, lookup)
				kevUnchecked += n
				for _, e := range matched {
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
	out := map[string]any{"searched": roots, "lock_files": nLock, "site_packages": len(siteDirs), "total_vulns": total, "files": results}
	if system {
		out["docker_images"] = img.images
		if img.none != "" {
			out["docker_images_note"] = img.none // nothing to check: not a part left out
		}
	}
	if len(pth) > 0 {
		out["pth"] = pth // .pth files that run code at every Python start; Known: a tool's own
	}
	if img.containerd != "" {
		out["docker_images_containerd"] = img.containerd
	}
	if len(img.partial) > 0 {
		out["docker_images_partial"] = img.partial // one line each in the daily report, never cut with the rest
	}
	// partial says all of it: what was found in part, containerd's store,
	// then the images'.
	if img.containerd != "" {
		partial = append(partial, img.containerd)
	}
	if partial = append(partial, img.partial...); len(partial) > 0 {
		out["partial"] = strings.Join(partial, "；")
	}
	if len(files) == 0 {
		out["note"] = "no lock files found; set [tools] app_paths to where your apps live"
	}
	if kevErr != nil {
		out["kev"] = "CISA KEV list unavailable: " + kevErr.Error()
	} else if kevUnchecked > 0 {
		out["kev_unchecked"] = kevUnchecked
		out["kev"] = fmt.Sprintf("%d vulnerabilities could not be checked against the CISA KEV list: exploited ones among them are not marked", kevUnchecked)
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
