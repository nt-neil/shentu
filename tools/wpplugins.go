package tools

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/detect"
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
// under roots (each root and its direct subdirectories are looked at),
// and the paths that could not be read. Links are not followed.
func WordPressPlugins(roots []string) ([]WPPlugin, []string) {
	var out []WPPlugin
	var unread []string
	seen := map[string]bool{}
	for _, r := range roots {
		cands := []string{r}
		if ents, err := os.ReadDir(r); err == nil {
			for _, e := range ents {
				if e.IsDir() {
					cands = append(cands, filepath.Join(r, e.Name()))
				}
			}
		}
		for _, root := range cands {
			dir := filepath.Join(root, "wp-content", "plugins")
			if st, err := os.Lstat(dir); err != nil || !st.IsDir() || seen[dir] {
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

func pluginsIn(root, dir string) ([]WPPlugin, []string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{dir}
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
			continue
		case e.IsDir():
			files, err := os.ReadDir(p)
			if err != nil {
				unread = append(unread, p)
				continue
			}
			n := 0
			for _, f := range files {
				if !f.Type().IsRegular() || !strings.HasSuffix(strings.ToLower(f.Name()), ".php") {
					continue
				}
				if n++; n > wpMaxFilesEach {
					break
				}
				if pl, ok := pluginHeader(filepath.Join(p, f.Name())); ok {
					pl.Root, pl.Slug = root, e.Name()
					out = append(out, pl)
					break
				}
			}
		case e.Type().IsRegular() && strings.HasSuffix(strings.ToLower(e.Name()), ".php"):
			if pl, ok := pluginHeader(p); ok {
				pl.Root, pl.Slug = root, strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
				out = append(out, pl)
			}
		}
	}
	return out, unread
}

// pluginHeader reads a plugin's main file header: ok when it has a
// "Plugin Name:" line in its first wpHeaderBytes.
func pluginHeader(p string) (WPPlugin, bool) {
	f, err := os.Open(p)
	if err != nil {
		return WPPlugin{}, false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, wpHeaderBytes))
	s := strings.ReplaceAll(string(b), "\r", "\n")
	m := wpName.FindStringSubmatch(s)
	if m == nil {
		return WPPlugin{}, false
	}
	pl := WPPlugin{Name: cleanHeader(m[1], 200)}
	if v := wpVersion.FindStringSubmatch(s); v != nil {
		pl.Version = cleanHeader(v[1], wpMaxVersionLen)
	}
	return pl, true
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
