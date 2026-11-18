package tools

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/hostenv"
)

// WordPress plugins (plan 0743f0, P5): the version of each plugin of each
// WordPress installation under the web roots, read from its main file's
// header as WordPress itself reads it (get_plugin_data: the first 8KB, a
// "Plugin Name:" line, then "Version:"). There is no advisory list for
// plugins here: a signature written for one matches by its slug and
// version range (detect.InstalledPackage).

// Bounds on reading the plugins.
const (
	wpHeaderBytes   = 8 << 10 // as WordPress reads a header
	wpMaxPlugins    = 1000    // per installation
	wpMaxFilesEach  = 50      // .php files looked at in one plugin's directory
	wpMaxVersionLen = 64
)

// WPPlugin is one installed plugin.
type WPPlugin struct {
	Root    string `json:"root"` // the WordPress installation (the directory holding wp-content)
	Slug    string `json:"slug"` // its directory's name (a one-file plugin: its file's, without .php)
	Name    string `json:"name"`
	Version string `json:"version"` // "" when the header has none
}

var (
	wpName    = regexp.MustCompile(`(?mi)^[ \t/*#@]*Plugin Name:[ \t]*(.+)$`)
	wpVersion = regexp.MustCompile(`(?mi)^[ \t/*#@]*Version:[ \t]*(.+)$`)
)

// WordPressPlugins lists the plugins of the WordPress installations at or
// under roots (each root, and the directories one and two levels under
// it: site/public_html), and what could not be read, each with why: a
// plugin missing from the surface is said, never quietly left out. Links
// are not followed (said when one leads to a WordPress).
func WordPressPlugins(roots []string) ([]WPPlugin, []string) {
	var out []WPPlugin
	var unread []string
	seen := map[string]bool{}
	for _, r := range roots {
		cands := []string{r}
		level := []string{r}
		for depth := 0; depth < wpDepth; depth++ {
			var next []string
			for _, d := range level {
				ents, err := readDirMax(d, wpMaxDirEntries)
				if errors.Is(err, errTooMany) {
					unread = append(unread, d+" (more than "+strconv.Itoa(wpMaxDirEntries)+" entries: the rest not looked at)")
				} else if err != nil {
					if depth == 0 {
						unread = append(unread, d+" ("+err.Error()+")")
					}
					continue
				}
				for _, e := range ents {
					p := filepath.Join(d, e.Name())
					switch {
					case e.Type()&os.ModeSymlink != 0:
						if st, err := os.Stat(filepath.Join(p, "wp-content")); err == nil && st.IsDir() {
							unread = append(unread, p+" (a link to a WordPress, not followed)")
						}
					case e.IsDir():
						if len(cands)+len(next) >= wpMaxCandidates {
							continue
						}
						next = append(next, p)
					}
				}
			}
			if len(cands)+len(next) >= wpMaxCandidates {
				unread = append(unread, r+" (more than "+strconv.Itoa(wpMaxCandidates)+" directories under it: the rest not looked at for WordPress)")
			}
			cands, level = append(cands, next...), next
		}
		for _, root := range cands {
			dir := filepath.Join(root, "wp-content", "plugins")
			st, err := os.Lstat(dir)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil:
				unread = append(unread, dir+" ("+err.Error()+")")
				continue
			case st.Mode()&os.ModeSymlink != 0:
				unread = append(unread, dir+" (a link, not followed)")
				continue
			case !st.IsDir() || seen[dir]:
				continue
			}
			seen[dir] = true
			ps, un := pluginsIn(root, dir)
			out = append(out, ps...)
			unread = append(unread, un...)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Root != out[j].Root {
			return out[i].Root < out[j].Root
		}
		return out[i].Slug < out[j].Slug
	})
	return out, unread
}

// Bounds on the search: the entries read of any one directory, the
// levels under a web root looked at (site/public_html/blog), and the
// directories looked at for a wp-content under one root in all.
const (
	wpMaxDirEntries = 4096
	wpDepth         = 3
	wpMaxCandidates = 8192
)

var errTooMany = errors.New("more entries than are read")

// readDirMax reads at most n entries of dir, sorted by name (errTooMany
// when there are more: those read are given).
func readDirMax(dir string, n int) ([]os.DirEntry, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ents, err := f.ReadDir(n + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var more error
	if len(ents) > n {
		ents, more = ents[:n], errTooMany
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	return ents, more
}

func pluginsIn(root, dir string) ([]WPPlugin, []string) {
	ents, err := readDirMax(dir, wpMaxDirEntries)
	tooMany := errors.Is(err, errTooMany)
	if tooMany {
		err = nil // the entries read are looked at, the rest said below
	}
	if err != nil {
		return nil, []string{dir + " (" + err.Error() + ")"}
	}
	var out []WPPlugin
	var unread []string
	for _, e := range ents {
		if len(out) >= wpMaxPlugins {
			unread = append(unread, dir+" (more than "+strconv.Itoa(wpMaxPlugins)+" plugins)")
			break
		}
		p := filepath.Join(dir, e.Name())
		switch {
		case e.Type()&os.ModeSymlink != 0:
			unread = append(unread, p+" (a link, not followed)")
		case e.IsDir():
			files, err := readDirMax(p, wpMaxDirEntries)
			if err != nil && !errors.Is(err, errTooMany) {
				unread = append(unread, p+" ("+err.Error()+")")
				continue
			}
			n, found := 0, false
			var failed []string
			for _, f := range files {
				if !strings.HasSuffix(strings.ToLower(f.Name()), ".php") {
					continue
				}
				if f.Type()&os.ModeSymlink != 0 {
					failed = append(failed, f.Name()+": a link, not followed")
					continue
				}
				if !f.Type().IsRegular() {
					continue
				}
				if n++; n > wpMaxFilesEach {
					failed = append(failed, "more than "+strconv.Itoa(wpMaxFilesEach)+" .php files: the rest not read")
					break
				}
				pl, ok, err := pluginHeader(filepath.Join(p, f.Name()))
				if err != nil {
					failed = append(failed, f.Name()+": "+err.Error())
				}
				if ok {
					pl.Root, pl.Slug = root, e.Name()
					out = append(out, pl)
					found = true
					break
				}
			}
			switch {
			case !found && len(failed) > 0:
				unread = append(unread, p+" (no header read; "+strings.Join(failed, "; ")+")")
			case !found && n > 0:
				unread = append(unread, p+" (.php files but no plugin header found)")
			}
		case e.Type().IsRegular() && strings.HasSuffix(strings.ToLower(e.Name()), ".php"):
			pl, ok, err := pluginHeader(p)
			if err != nil {
				unread = append(unread, p+" ("+err.Error()+")")
			}
			if ok {
				pl.Root, pl.Slug = root, strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
				out = append(out, pl)
			}
		}
	}
	if tooMany {
		unread = append(unread, dir+" (more than "+strconv.Itoa(wpMaxDirEntries)+" entries: the rest not read)")
	}
	return out, unread
}

// pluginHeader reads a plugin's main file header: ok when it has a
// "Plugin Name:" line in its first wpHeaderBytes; err when the file could
// not be read. The directory is the web account's to write: the file is
// opened without following a link, without blocking (a FIFO left there
// cannot hold the patrol), and read only when what was opened is a
// regular file.
func pluginHeader(p string) (WPPlugin, bool, error) {
	f, err := (&hostenv.Live{}).OpenLogNoFollow(p)
	if err != nil {
		return WPPlugin{}, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, wpHeaderBytes))
	if err != nil {
		return WPPlugin{}, false, err
	}
	s := strings.ReplaceAll(string(b), "\r", "\n")
	m := wpName.FindStringSubmatch(s)
	if m == nil {
		return WPPlugin{}, false, nil
	}
	pl := WPPlugin{Name: cleanHeader(m[1], 200)}
	if v := wpVersion.FindStringSubmatch(s); v != nil {
		pl.Version = cleanHeader(v[1], wpMaxVersionLen)
	}
	return pl, true, nil
}

// cleanHeader is a header value: the comment's end taken off, trimmed,
// printable, cut to n bytes.
func cleanHeader(v string, n int) string {
	v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "*/"))
	return Cut(detect.Printable(v), n)
}

// SurfacePlugins is the plugins as installed packages of the surface.
func SurfacePlugins(ps []WPPlugin) []detect.InstalledPackage {
	var out []detect.InstalledPackage
	for _, p := range ps {
		out = append(out, detect.InstalledPackage{Source: p.Root, Ecosystem: "WordPress", Package: p.Slug, Version: p.Version})
	}
	return out
}
