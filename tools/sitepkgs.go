package tools

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nt-neil/shentu/internal/osutil"
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
	// Known names the tool whose own .pth this is, to the letter (setuptools,
	// virtualenv, an editable install); empty is one to look at.
	Known string `json:"known,omitempty"`
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
	if system {
		for _, g := range systemSitePackages {
			ms, _ := filepath.Glob(g)
			for _, m := range ms {
				if st, err := os.Lstat(m); err == nil && st.IsDir() && !add(m) {
					full = true
				}
			}
		}
	}
	visits, unread := 0, 0
	for _, root := range roots {
		if full {
			break
		}
		base := strings.Count(filepath.Clean(root), string(filepath.Separator))
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					unread++
				}
				return nil
			}
			if visits++; visits > sitePkgVisits {
				return filepath.SkipAll
			}
			if !d.IsDir() {
				return nil
			}
			if n := d.Name(); n == "site-packages" || n == "dist-packages" {
				if !add(p) {
					full = true
					return filepath.SkipAll
				}
				return filepath.SkipDir
			}
			if sitePkgSkip[d.Name()] || strings.Count(p, string(filepath.Separator))-base >= sitePkgDepth {
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
	return dirs, notes
}

// readSitePackages reads the packages one folder holds and its .pth files.
func readSitePackages(dir string) sitePkgDir {
	r := sitePkgDir{Path: dir}
	ents, err := os.ReadDir(dir)
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
		n, p := e.Name(), filepath.Join(dir, e.Name())
		switch {
		case strings.HasSuffix(n, ".dist-info") || strings.HasSuffix(n, ".egg-info"):
			if dists++; dists > sitePkgDistMax {
				cut++
				continue
			}
			meta := p // an .egg-info file is the PKG-INFO itself
			if e.IsDir() {
				meta = filepath.Join(p, "METADATA")
				if strings.HasSuffix(n, ".egg-info") {
					meta = filepath.Join(p, "PKG-INFO")
				}
			} else if !e.Type().IsRegular() {
				unread++
				continue
			}
			if osManaged {
				if !e.IsDir() {
					continue // a distutils .egg-info file: the system's packages
				}
				b, ok := readHead(filepath.Join(p, "INSTALLER"), 256)
				if !ok || !pipInstallers[strings.TrimSpace(string(b))] {
					continue
				}
			}
			b, ok := readHead(meta, sitePkgHead)
			name, version := metaNameVersion(b)
			if !ok || name == "" || version == "" {
				unread++
				continue
			}
			r.pkgs = append(r.pkgs, pkg{pep503(name), version})
		case strings.HasSuffix(n, ".pth") && !e.Type().IsRegular():
			r.notes = append(r.notes, p+" 不是一般檔案（symlink 之類），沒有檢查它會不會執行程式")
		case strings.HasSuffix(n, ".pth"):
			b, ok := readHead(p, sitePkgHead+1)
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

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// readHead reads at most max bytes of a regular file, not through a symlink.
func readHead(p string, max int64) ([]byte, bool) {
	f, err := osutil.OpenNoFollow(p, os.O_RDONLY, 0, true)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, max))
	return b, err == nil
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
// whose import lines are the tool's own, to the letter, and whose module
// (verify) is the tool's. A file of that name with any other line, or whose
// module is not the one the tool installed, is one to look at. A module
// changed after it was installed is out of reach here, as is any installed
// module changed.
var knownPth = []struct {
	name   *regexp.Regexp
	label  string
	lines  []*regexp.Regexp
	verify func(dir, name string, lines []string) bool
}{
	{regexp.MustCompile(`^distutils-precedence\.pth$`), "setuptools", []*regexp.Regexp{
		regexp.MustCompile(`^import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '(?:local|stdlib)'\) == 'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\); ?$`)},
		func(dir, _ string, _ []string) bool { // the module setuptools installed, as its RECORD has it
			return recordHas(dir, "setuptools-*.dist-info", "_distutils_hack/__init__.py")
		}},
	{regexp.MustCompile(`^_virtualenv\.pth$`), "virtualenv", []*regexp.Regexp{regexp.MustCompile(`^import _virtualenv$`)},
		func(dir, _ string, _ []string) bool { // virtualenv writes it into the venvs it makes
			_, err := os.Lstat(filepath.Join(dir, "..", "..", "..", "pyvenv.cfg"))
			return err == nil
		}},
	{regexp.MustCompile(`^__editable__\.[A-Za-z0-9_.+-]+\.pth$`), "editable install", []*regexp.Regexp{editableLine},
		func(dir, name string, lines []string) bool { // the finder the package's RECORD lists
			m := editableLine.FindStringSubmatch(lines[0])
			dist := strings.TrimSuffix(strings.TrimPrefix(name, "__editable__."), ".pth")
			return len(lines) == 1 && recordHas(dir, dist+".dist-info", m[1]+".py")
		}},
	{regexp.MustCompile(`^easy-install\.pth$`), "setuptools", []*regexp.Regexp{
		regexp.MustCompile(`^import sys; sys\.__plen = len\(sys\.path\)$`),
		regexp.MustCompile(`^import sys; new = sys\.path\[sys\.__plen:\]; del sys\.path\[sys\.__plen:\]; p = getattr\(sys, '__egginsert', 0\); sys\.path\[p:p\] = new; sys\.__egginsert = p \+ len\(new\)$`)}, nil},
	{regexp.MustCompile(`^[A-Za-z0-9_.+-]+-nspkg\.pth$`), "setuptools namespace package", []*regexp.Regexp{nspkgLine()}, nil},
}

// recordHas: a dist-info matching glob in dir lists rel in its RECORD, and
// the file there now has the sha256 RECORD gives.
func recordHas(dir, glob, rel string) bool {
	ms, _ := filepath.Glob(filepath.Join(dir, glob))
	for _, m := range ms {
		rec, ok := readHead(filepath.Join(m, "RECORD"), 4<<20)
		if !ok {
			continue
		}
		for _, l := range strings.Split(string(rec), "\n") {
			want, ok := strings.CutPrefix(strings.TrimRight(l, "\r"), rel+",sha256=")
			if !ok {
				continue
			}
			want, _, _ = strings.Cut(want, ",")
			b, ok := readHead(filepath.Join(dir, filepath.FromSlash(rel)), 4<<20)
			sum := sha256.Sum256(b)
			if ok && want != "" && base64.RawURLEncoding.EncodeToString(sum[:]) == want {
				return true
			}
		}
	}
	return false
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
	"\u2028", "\n", "\u2029", "\n", "\x85", "\n")

// pthImports counts the lines Python's site module runs (those starting
// "import " or "import\t", a UTF-8 BOM dropped, lines split as pthLineEnd
// says); ok is false when there are none.
func pthImports(dir, name string, b []byte) (PthFile, bool) {
	var f PthFile
	var lines []string
	s := pthLineEnd.Replace(strings.TrimPrefix(string(b), "\ufeff"))
	for _, l := range strings.Split(s, "\n") {
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
		if all && (k.verify == nil || k.verify(dir, name, lines)) {
			f.Known = k.label
		}
		break
	}
	return f, true
}
