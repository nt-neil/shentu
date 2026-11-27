package tools

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nt-neil/shentu/hostenv"
)

// Installed Python packages (plan cd58fb installed-pkgs-and-pth): a venv or
// site-packages holds what pip installed, which no lock file may list (a
// LiteLLM installed by hand). Each site-packages folder is checked against
// OSV as PyPI, as a lock file is, and its .pth files that run code at every
// Python start are listed.

// systemSitePackages are the interpreter's own folders. Under /usr/lib the
// system's package manager installs too: only what pip (or a tool like it)
// wrote INSTALLER for is read there; the rest is the OS package check's.
var systemSitePackages = []string{
	"/usr/local/lib/python3*/site-packages", "/usr/local/lib/python3*/dist-packages",
	"/usr/lib/python3*/site-packages", "/usr/lib/python3*/dist-packages",
	"/usr/lib64/python3*/site-packages",
}

// osManagedPrefixes: under these, a package needs a pip-family INSTALLER.
var osManagedPrefixes = []string{"/usr/lib/", "/usr/lib64/"}

var pipInstallers = map[string]bool{"pip": true, "uv": true, "poetry": true, "pdm": true, "pipenv": true, "hatch": true}

// The scan's bounds: a walk past them, or a file not read, is said, never
// taken as "nothing installed".
var (
	sitePkgDepth   = 8      // folders below a root
	sitePkgVisits  = 200000 // entries walked over all roots
	sitePkgDirsMax = 100    // site-packages folders
	sitePkgDistMax = 5000   // packages in one folder
)

const sitePkgHead = 64 << 10 // METADATA and .pth: the first 64 KiB

var sitePkgSkip = map[string]bool{"node_modules": true, ".git": true, "__pycache__": true, ".cache": true, "proc": true}

// PthFile is a .pth file with lines Python runs at every start ("import"
// lines). Its content is not kept: it may hold a host's secrets.
type PthFile struct {
	Path        string `json:"path"`
	ImportLines int    `json:"import_lines"`
	// Known names the tool whose own file it is, proven: its lines the
	// tool's to the letter, the tool's own record of it, and the folder,
	// every folder above it and those files root's alone (no one else could
	// have written them). Empty is one to look at.
	Known string `json:"known,omitempty"`
	// Unproven names the tool it looks like (setuptools' distutils hook,
	// virtualenv, an editable install: in most venvs), its record there
	// too, in a folder a user can write: whoever can write the .pth can
	// write the record, so it is said (info), not proven.
	Unproven string `json:"unproven,omitempty"`
}

// sitePkgDir is one site-packages folder read.
type sitePkgDir struct {
	Path  string
	pkgs  []pkg
	pth   []PthFile
	notes []string
}

// findSitePackages returns the site-packages folders under roots (and the
// system's, with system set), and what the walk could not cover.
func findSitePackages(roots []string, system bool) (dirs []string, notes []string) {
	hp := hostPaths() // the host's path spelling (S-272-2)
	seen := map[string]bool{}
	add := func(p string) bool {
		if seen[p] {
			return true
		}
		if len(dirs) >= sitePkgDirsMax {
			return false
		}
		seen[p] = true
		dirs = append(dirs, p)
		return true
	}
	full := false
	src := hostSource()
	if system {
		for _, g := range systemSitePackages {
			for _, m := range hostenv.Glob(src, g) {
				if st, err := hostenv.Lstat(src, m); err == nil && st.Mode.IsDir() && !add(m) {
					full = true
				}
			}
		}
	}
	visits, unread, deep := 0, 0, 0
	for _, root := range roots {
		if full {
			break
		}
		base := strings.Count(hp.Clean(root), hp.Sep)
		hostenv.Walk(src, root, func(p string, st hostenv.FileStat, err error) error {
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					unread++
				}
				return nil
			}
			if visits++; visits > sitePkgVisits {
				return filepath.SkipAll
			}
			if !st.Mode.IsDir() {
				return nil
			}
			if n := hp.Base(p); n == "site-packages" || n == "dist-packages" {
				if !add(p) {
					full = true
					return filepath.SkipAll
				}
				return filepath.SkipDir
			}
			if sitePkgSkip[hp.Base(p)] {
				return filepath.SkipDir
			}
			if strings.Count(p, hp.Sep)-base >= sitePkgDepth {
				deep++ // its folders not looked into: said (N-239-2)
				return filepath.SkipDir
			}
			return nil
		})
	}
	if visits > sitePkgVisits {
		notes = append(notes, fmt.Sprintf("找 site-packages 時走到 %d 個項目的上限就停了，其餘資料夾沒有檢查", sitePkgVisits))
	}
	if full {
		notes = append(notes, fmt.Sprintf("site-packages 資料夾超過 %d 個，其餘沒有檢查", sitePkgDirsMax))
	}
	if unread > 0 {
		notes = append(notes, fmt.Sprintf("找 site-packages 時有 %d 個資料夾讀不到，裡面沒有檢查", unread))
	}
	if deep > 0 {
		notes = append(notes, fmt.Sprintf("找 site-packages 時有 %d 個資料夾超過 %d 層，裡面沒有檢查", deep, sitePkgDepth))
	}
	return dirs, notes
}

// readSitePackages reads the packages one folder holds and its .pth files.
func readSitePackages(dir string) sitePkgDir {
	hp := hostPaths() // the host's path spelling (S-272-2)
	r := sitePkgDir{Path: dir}
	src := hostSource()
	ents, err := lsDir(src, dir)
	if err != nil {
		r.notes = append(r.notes, dir+" 讀不到（"+errText(err)+"）")
		return r
	}
	osManaged := false
	for _, p := range osManagedPrefixes {
		osManaged = osManaged || strings.HasPrefix(dir, p)
	}
	dists, unread, cut := 0, 0, 0
	for _, e := range ents {
		n, p := e.name, hp.Join(dir, e.name)
		switch {
		case strings.HasSuffix(n, ".dist-info") || strings.HasSuffix(n, ".egg-info"):
			if dists++; dists > sitePkgDistMax {
				cut++
				continue
			}
			meta := p // an .egg-info file is the PKG-INFO itself
			if e.isDir() {
				meta = hp.Join(p, "METADATA")
				if strings.HasSuffix(n, ".egg-info") {
					meta = hp.Join(p, "PKG-INFO")
				}
			} else if !e.isRegular() {
				unread++
				continue
			}
			if osManaged {
				if !e.isDir() {
					continue // a distutils .egg-info file: the system's packages
				}
				b, ok := readHead(src, hp.Join(p, "INSTALLER"), 256)
				if !ok || !pipInstallers[strings.TrimSpace(string(b))] {
					continue
				}
			}
			b, ok := readHead(src, meta, sitePkgHead)
			name, version := metaNameVersion(b)
			if !ok || name == "" || version == "" {
				unread++
				continue
			}
			r.pkgs = append(r.pkgs, pkg{pep503(name), version})
		case strings.HasSuffix(n, ".pth") && !e.isRegular():
			r.notes = append(r.notes, p+" 不是一般檔案（symlink 之類），沒有檢查它會不會執行程式")
		case strings.HasSuffix(n, ".pth"):
			b, ok := readHead(src, p, sitePkgHead+1)
			if !ok {
				r.notes = append(r.notes, p+" 讀不到，沒有檢查它會不會執行程式")
				continue
			}
			if len(b) > sitePkgHead {
				r.notes = append(r.notes, fmt.Sprintf("%s 超過 %d KiB，只檢查了前面的部分", p, sitePkgHead>>10))
				b = b[:sitePkgHead]
			}
			if f, ok := pthImports(dir, n, b); ok {
				f.Path = p
				r.pth = append(r.pth, f)
			}
		}
	}
	if cut > 0 {
		r.notes = append(r.notes, fmt.Sprintf("%s 有 %d 個套件超過單一資料夾 %d 個的上限，沒有檢查", dir, cut, sitePkgDistMax))
	}
	if unread > 0 {
		r.notes = append(r.notes, fmt.Sprintf("%s 有 %d 個套件的 METADATA 讀不到或沒有名稱、版本，沒有檢查", dir, unread))
	}
	r.pkgs = uniq(r.pkgs)
	sort.Slice(r.pkgs, func(i, j int) bool { return r.pkgs[i].Name < r.pkgs[j].Name })
	return r
}

// errText is err without the path it names, for a text that says the path
// itself: a PathError's own error, a replay's "not in fixture".
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	if errors.Is(err, hostenv.ErrNotRecorded) {
		return hostenv.ErrNotRecorded.Error()
	}
	return err.Error()
}

// readHead reads at most max bytes of a regular file, not through a
// symlink, through the host source.
func readHead(src hostenv.Source, p string, max int64) ([]byte, bool) {
	b, err := hostenv.ReadFileNoFollowMax(src, p, max)
	return b, err == nil || errors.Is(err, hostenv.ErrTruncated)
}

// dirEnt is one entry of a folder read through the host source: its
// Lstat, or the error that gave (not a regular file, nor a folder, then).
type dirEnt struct {
	name string
	st   hostenv.FileStat
	err  error
}

func (e dirEnt) isDir() bool     { return e.err == nil && e.st.Mode.IsDir() }
func (e dirEnt) isRegular() bool { return e.err == nil && e.st.Mode.IsRegular() }
func (e dirEnt) isLink() bool    { return e.err == nil && e.st.Mode&fs.ModeSymlink != 0 }

// lsDir is os.ReadDir through src: sorted names, each with its Lstat.
func lsDir(src hostenv.Source, dir string) ([]dirEnt, error) {
	hp := hostPaths() // the host's path spelling (S-272-2)
	names, err := src.ReadDir(dir)
	out := make([]dirEnt, 0, len(names))
	for _, n := range names {
		st, lerr := hostenv.Lstat(src, hp.Join(dir, n))
		out = append(out, dirEnt{n, st, lerr})
	}
	return out, err
}

// metaNameVersion reads Name and Version from the headers of a METADATA or
// PKG-INFO (RFC 822 style, up to the first blank line).
func metaNameVersion(b []byte) (name, version string) {
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 0, 4096), sitePkgHead)
	for s.Scan() {
		l := s.Text()
		if strings.TrimSpace(l) == "" {
			break
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "name":
			if name == "" {
				name = strings.TrimSpace(v)
			}
		case "version":
			if version == "" {
				version = strings.TrimSpace(v)
			}
		}
	}
	return name, version
}

var pep503Sep = regexp.MustCompile(`[-_.]+`)

// pep503 is a PyPI name as PEP 503 normalizes it, as OSV keys it.
func pep503(n string) string { return strings.ToLower(pep503Sep.ReplaceAllString(n, "-")) }

// knownPth are .pth files tools write themselves: a file named so, all of
// whose import lines are the tool's own, to the letter, plain UTF-8, and
// for which the tool's own record says so (record: its files, nil when
// there is none). Only with the folder, every folder above it, the .pth
// and those files root's alone is that proof (Known); in a folder a user
// can write, whoever wrote the .pth could have written the record too.
// Then a tool whose file is in most venvs (info) is said as Unproven, and
// the others are ones to look at: nspkg and easy-install lines run code or
// put folders first on sys.path. A module changed after it was installed
// is out of reach here, as is any installed module changed.
var knownPth = []struct {
	name   *regexp.Regexp
	label  string
	lines  []*regexp.Regexp
	info   bool
	record func(dir, name string, lines []string, b []byte) []string
}{
	{regexp.MustCompile(`^distutils-precedence\.pth$`), "setuptools", []*regexp.Regexp{
		regexp.MustCompile(`^import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '(?:local|stdlib)'\) == 'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\); ?$`)}, true,
		func(dir, name string, _ []string, _ []byte) []string { // the module and the .pth setuptools installed, as its RECORD has them
			mod := hostPaths().Join(dir, "_distutils_hack", "__init__.py")
			if rec, ok := recordHas(hostSource(), dir, "setuptools-*.dist-info", "_distutils_hack/__init__.py"); ok && sameRecordHas(dir, rec, name) {
				return []string{rec, mod}
			}
			if managedDir(dir) { // the system's setuptools (Debian keeps no RECORD)
				return []string{mod}
			}
			return nil
		}},
	{regexp.MustCompile(`^_virtualenv\.pth$`), "virtualenv", []*regexp.Regexp{regexp.MustCompile(`^import _virtualenv$`)}, true,
		func(dir, _ string, _ []string, _ []byte) []string { // a venv virtualenv made says so in its pyvenv.cfg
			cfg := hostPaths().Join(dir, "..", "..", "..", "pyvenv.cfg")
			b, ok := readHead(hostSource(), cfg, sitePkgHead)
			if !ok || !virtualenvKey.Match(b) {
				return nil
			}
			return []string{hostPaths().Clean(cfg), hostPaths().Join(dir, "_virtualenv.py")}
		}},
	{regexp.MustCompile(`^__editable__\.[A-Za-z0-9_.+-]+\.pth$`), "editable install", []*regexp.Regexp{editableLine}, true,
		func(dir, name string, lines []string, _ []byte) []string { // the finder and the .pth the package's RECORD lists
			m := editableLine.FindStringSubmatch(lines[0])
			dist := strings.TrimSuffix(strings.TrimPrefix(name, "__editable__."), ".pth")
			if rec, ok := recordHas(hostSource(), dir, dist+".dist-info", m[1]+".py"); ok && len(lines) == 1 && sameRecordHas(dir, rec, name) {
				return []string{rec, hostPaths().Join(dir, m[1]+".py")}
			}
			return nil
		}},
	{regexp.MustCompile(`^easy-install\.pth$`), "setuptools", []*regexp.Regexp{
		regexp.MustCompile(`^import sys; sys\.__plen = len\(sys\.path\)$`),
		regexp.MustCompile(`^import sys; new = sys\.path\[sys\.__plen:\]; del sys\.path\[sys\.__plen:\]; p = getattr\(sys, '__egginsert', 0\); sys\.path\[p:p\] = new; sys\.__egginsert = p \+ len\(new\)$`)}, false,
		func(dir, name string, _ []string, b []byte) []string {
			// Its lines put the folders between them first on sys.path:
			// with any folder there it is one to look at.
			if len(pthPathLines(dir, b)) > 0 {
				return nil
			}
			return pthRecord(dir, name)
		}},
	{regexp.MustCompile(`^[A-Za-z0-9_.+-]+-nspkg\.pth$`), "setuptools namespace package", []*regexp.Regexp{nspkgLine()}, false,
		func(dir, name string, _ []string, _ []byte) []string { return pthRecord(dir, name) }},
}

var virtualenvKey = regexp.MustCompile(`(?m)^virtualenv\s*=`)

// sameRecordHas: the RECORD rec (of a dist-info in dir) lists the .pth
// name too, with its hash: a .pth written next to a real install, which
// no RECORD lists, is not that install's (S-239r-1).
func sameRecordHas(dir, rec, name string) bool {
	hp := hostPaths() // the host's path spelling (S-272-2)
	_, ok := recordHas(hostSource(), dir, hp.Base(hp.Dir(rec)), name)
	return ok
}

// pthRecord is the RECORD that lists dir's .pth name with its hash, or,
// in the system package manager's folders (no RECORD there), none needed.
func pthRecord(dir, name string) []string {
	if rec, ok := recordHas(hostSource(), dir, "*.dist-info", name); ok {
		return []string{rec}
	}
	if managedDir(dir) {
		return []string{}
	}
	return nil
}

// managedDir: dir is under the system package manager's prefixes.
func managedDir(dir string) bool {
	for _, p := range osManagedPrefixes {
		if strings.HasPrefix(dir, p) {
			return true
		}
	}
	return false
}

// rootChain: dir and every folder above it are root's alone (rootOnly), so
// nothing in it was written by another user.
func rootChain(dir string) bool {
	hp := hostPaths() // the host's path spelling (S-272-2)
	for p := hp.Clean(dir); ; p = hp.Dir(p) {
		if !rootOnly(p, true) {
			return false
		}
		if hp.Dir(p) == p {
			return true
		}
	}
}

// unverifiedDistutilsHack: some folder Python may search holds a
// _distutils_hack that is not setuptools' by its RECORD nor the system's:
// before the real one on sys.path it is what distutils-precedence.pth
// imports, so no such .pth is known then. The folders are dirs and those
// their .pth path lines add; whole only when the walk was (complete).
// Anything importable by that name counts: the package folder (a real one,
// verified) or a module of any suffix (.py, .pyc, .so, .cpython-*.so ...).
func unverifiedDistutilsHack(dirs []string, complete bool) bool {
	if !complete {
		return true
	}
	seen := map[string]bool{}
	var all []string
	src := hostSource()
	for _, d := range dirs {
		if !seen[d] {
			seen[d] = true
			all = append(all, d)
		}
		added, whole := pthPaths(src, d)
		if !whole {
			return true // a .pth not read whole: a folder it adds is not known
		}
		for _, p := range added {
			if !seen[p] {
				if len(all) >= 4*sitePkgDirsMax {
					return true
				}
				seen[p] = true
				all = append(all, p)
			}
		}
	}
	for _, d := range all {
		ents, err := lsDir(src, d)
		if errors.Is(err, fs.ErrNotExist) {
			continue // not there: nothing to import from it (a file there, a zip, can be imported from)
		}
		if err != nil {
			return true
		}
		for _, e := range ents {
			n := e.name
			if n == "_distutils_hack" {
				if _, rec := recordHas(src, d, "setuptools-*.dist-info", "_distutils_hack/__init__.py"); !e.isDir() || !(rec || systemModule(d, "_distutils_hack/__init__.py")) {
					return true
				}
			} else if strings.HasPrefix(n, "_distutils_hack.") {
				return true
			}
		}
	}
	return false
}

func allRootOnly(files []string) bool {
	for _, f := range files {
		if !rootOnly(f, false) {
			return false
		}
	}
	return true
}

// pySpace is what Python's str.isspace() takes as white space.
func pySpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

// pthPaths are the folders the path lines of dir's .pth files add to
// sys.path, read as site.py reads them (a line starting "#" or "import"
// as written is not one; trailing white space dropped; relative ones taken
// from dir); whole is false when a .pth there was not read whole.
func pthPaths(src hostenv.Source, dir string) (out []string, whole bool) {
	hp := hostPaths() // the host's path spelling (S-272-2)
	ents, err := lsDir(src, dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.name, ".pth") {
			continue
		}
		if !e.isRegular() {
			return nil, false
		}
		b, ok := readHead(src, hp.Join(dir, e.name), sitePkgHead+1)
		if !ok || len(b) > sitePkgHead {
			return nil, false
		}
		out = append(out, pthPathLines(dir, b)...)
	}
	return out, true
}

// rootOnly is rootOnlyFile; tests stand in for root.
var rootOnly = rootOnlyFile

// systemOwned: in a folder of the system's package manager (under
// osManagedPrefixes), the folder, the .pth and the module are root's and
// no one else can write them, as the package manager installed them.
func systemOwned(dir, name, rel string) bool {
	hp := hostPaths() // the host's path spelling (S-272-2)
	return systemModule(dir, rel) && rootOnly(hp.Join(dir, name), false)
}

// systemModule: rel in dir is the system package manager's: under its
// prefixes, the folders up to / and the file root's alone.
func systemModule(dir, rel string) bool {
	hp := hostPaths() // the host's path spelling (S-272-2)
	return managedDir(dir) && rootChain(dir) && rootOnly(hp.Join(dir, hp.FromSlash(rel)), false)
}

// recordHas: a dist-info matching glob in dir lists rel in its RECORD, and
// the file there now has the sha256 RECORD gives; rec is that RECORD.
// recordRow is a RECORD line: a file's path and its sha256 ("" if none).
type recordRow struct{ path, sha256 string }

// recordRows reads a RECORD as the CSV it is (PEP 376): a path with a
// comma or a quote is quoted (S-272-5: a split at ",sha256=" kept the
// quotes, and such a file was never matched). Read up to a line it cannot
// parse (a RECORD cut at its size cap): those before it stand.
func recordRows(b []byte) []recordRow {
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	var out []recordRow
	for {
		f, err := r.Read()
		if err != nil {
			return out
		}
		if len(f) < 2 {
			continue
		}
		h, _ := strings.CutPrefix(f[1], "sha256=")
		if h == f[1] {
			h = "" // another algorithm, or none: not verified
		}
		out = append(out, recordRow{f[0], h})
	}
}

func recordHas(src hostenv.Source, dir, glob, rel string) (rec string, ok bool) {
	// glob is one name (a dist-info folder): matched against dir's entries,
	// so the host's path form does not matter (hostenv.Glob is POSIX-only:
	// on a Windows host no RECORD was found, and a setuptools .pth was
	// listed as one to look at).
	// On Windows, whose file names are matched without case, the name and
	// RECORD's path are too, and RECORD's \ (an old pip's) is read as /.
	win := src.Info().GOOS == "windows"
	fold := func(s string) string {
		if win {
			return strings.ToLower(s)
		}
		return s
	}
	names, _ := src.ReadDir(dir)
	for _, n := range names {
		if m, _ := path.Match(fold(glob), fold(n)); !m {
			continue
		}
		recp := hostJoin(src, dir, n, "RECORD")
		b, ok := readHead(src, recp, 4<<20)
		if !ok {
			continue
		}
		for _, row := range recordRows(b) {
			p, want := row.path, row.sha256
			if win {
				p = strings.ReplaceAll(p, `\`, "/")
			}
			if want == "" || fold(p) != fold(rel) {
				continue
			}
			b, ok := readHead(src, hostJoin(src, dir, rel), 4<<20)
			sum := sha256.Sum256(b)
			if ok && want != "" && base64.RawURLEncoding.EncodeToString(sum[:]) == want {
				return recp, true
			}
		}
	}
	return "", false
}

// hostJoin joins dir and the slash-separated names after it as the host
// source writes paths: with \ on Windows, / elsewhere, whichever OS runs
// the check.
func hostJoin(src hostenv.Source, dir string, names ...string) string {
	rel := path.Join(names...)
	if src.Info().GOOS != "windows" {
		return path.Join(dir, rel)
	}
	return strings.TrimRight(dir, `\`) + `\` + strings.ReplaceAll(rel, "/", `\`)
}

// editableLine is setuptools' editable-install finder line; the module it
// imports must be the one it installs (checked in pthImports: RE2 has no
// back-references).
var editableLine = regexp.MustCompile(`^import (__editable___[A-Za-z0-9_]+_finder); (__editable___[A-Za-z0-9_]+_finder)\.install\(\)$`)

// nspkgLine is setuptools' namespace-package line (install_lib's
// _nspkg_tmpl), for one package name, nested or not.
func nspkgLine() *regexp.Regexp {
	pk := `'[A-Za-z0-9_.]+'`
	parts := []string{
		`import sys, types, os`,
		`has_mfs = sys\.version_info > \(3, 5\)`,
		`p = os\.path\.join\(sys\._getframe\(1\)\.f_locals\['sitedir'\], \*\((?:` + pk + `, ?)+\)\)`,
		`importlib = has_mfs and __import__\('importlib\.util'\)`,
		`has_mfs and __import__\('importlib\.machinery'\)`,
		`m = has_mfs and sys\.modules\.setdefault\(` + pk + `, importlib\.util\.module_from_spec\(importlib\.machinery\.PathFinder\.find_spec\(` + pk + `, \[os\.path\.dirname\(p\)\]\)\)\)`,
		`m = m or sys\.modules\.setdefault\(` + pk + `, types\.ModuleType\(` + pk + `\)\)`,
		`mp = \(m or \[\]\) and m\.__dict__\.setdefault\('__path__',\[\]\)`,
		`\(p not in mp\) and mp\.append\(p\)`,
	}
	return regexp.MustCompile(`^` + strings.Join(parts, `;`) + `(?:;m and setattr\(sys\.modules\[` + pk + `\], ` + pk + `, m\))?$`)
}

// pthLineEnd splits a .pth as every Python reads one: up to 3.12 its lines
// end at \n, \r\n or \r; from 3.13 site.py takes str.splitlines() of the
// text (also \v \f \x1c-\x1e U+0085 U+2028 U+2029), decoded as UTF-8 or,
// failing that, in the locale's encoding, where the byte 0x85 can be U+0085.
// Ending a line at any of them finds every line one of them starts.
var pthLineEnd = strings.NewReplacer("\r\n", "\n", "\r", "\n", "\v", "\n", "\f", "\n", "\x1c", "\n", "\x1d", "\n", "\x1e", "\n",
	"\u0085", "\n", "\u2028", "\n", "\u2029", "\n")

// pthLines are a .pth's lines as pthLineEnd ends them; the byte 0x85 too
// only when the text is not UTF-8 (in UTF-8 it is part of a character: Å
// is C3 85), as Python then reads it in the locale's encoding (S-239-1).
func pthLines(raw string) []string {
	s := pthLineEnd.Replace(raw)
	if !utf8.ValidString(raw) {
		s = strings.ReplaceAll(s, "\x85", "\n")
	}
	return strings.Split(s, "\n")
}

// pthPathLines are the folders b's path lines add (pthPaths, one file).
func pthPathLines(dir string, b []byte) []string {
	hp := hostPaths() // the host's path spelling (S-272-2)
	var out []string
	for _, l := range pthLines(strings.TrimPrefix(string(b), "\ufeff")) {
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "import ") || strings.HasPrefix(l, "import\t") {
			continue
		}
		if l = strings.TrimRightFunc(l, pySpace); l == "" {
			continue
		}
		if !hp.IsAbs(l) {
			l = hp.Join(dir, l)
		}
		out = append(out, hp.Clean(l))
	}
	return out
}

// pthImports counts the lines Python's site module runs (those starting
// "import " or "import\t", a UTF-8 BOM dropped, lines split as pthLineEnd
// says); ok is false when there are none.
func pthImports(dir, name string, b []byte) (PthFile, bool) {
	hp := hostPaths() // the host's path spelling (S-272-2)
	var f PthFile
	var lines []string
	raw := strings.TrimPrefix(string(b), "\ufeff")
	// A tool's own file is plain UTF-8 lines: one Pythons would split
	// differently (a byte not UTF-8, another line break) is never known.
	plain := utf8.ValidString(raw) && !strings.ContainsAny(raw, "\v\f\x1c\x1d\x1e\u0085\u2028\u2029")
	for _, l := range pthLines(raw) {
		if strings.HasPrefix(l, "import ") || strings.HasPrefix(l, "import\t") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return f, false
	}
	f.ImportLines = len(lines)
	for _, k := range knownPth {
		if !k.name.MatchString(name) {
			continue
		}
		all := true
		for _, l := range lines {
			one := false
			for _, re := range k.lines {
				m := re.FindStringSubmatch(l)
				one = one || m != nil && (re != editableLine || m[1] == m[2])
			}
			all = all && one
		}
		if !all || !plain {
			break
		}
		files := k.record(dir, name, lines, b)
		switch {
		case files == nil:
		case rootChain(dir) && rootOnly(hp.Join(dir, name), false) && allRootOnly(files):
			f.Known = k.label
		case k.info:
			f.Unproven = k.label
		}
		break
	}
	return f, true
}

// hostPaths are the path operations of the host read: a Linux host's paths
// keep "/" read on any machine (S-272-2).
func hostPaths() hostenv.PathOps { return hostenv.PathFor(hostSource()) }
