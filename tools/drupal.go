package tools

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// Drupal core (v0.5.9 item 1, plan t19): each Drupal installation at or
// under the web roots, found by its core/lib/Drupal.php, and its version as
// that file declares it (const VERSION). A Composer install is checked by
// app_vulns too (drupal/core in composer.lock, through OSV); this reads the
// files, so a tarball install is found as well.

// DrupalCore is one installation's core.
type DrupalCore struct {
	Root    string `json:"root"`    // the directory holding core/
	Version string `json:"version"` // "" when Drupal.php declares none read here
}

const drupalPHPBytes = 256 << 10 // Drupal.php is some 30 KB

var drupalVersion = regexp.MustCompile(`(?m)^\s*const\s+VERSION\s*=\s*'([^'\n]{1,64})'\s*;`)

// DrupalSites lists the Drupal installations at or under roots (each root
// and the directories one and two levels under it: site/web,
// site/public_html), and what could not be read, each with why. Links are
// not followed (said when one leads to a Drupal).
func DrupalSites(roots []string) ([]DrupalCore, []string) {
	var out []DrupalCore
	var unread []string
	seen := map[string]bool{}
	src := hostSource()
	ops := hostPaths()
	for _, r := range roots {
		cands := []string{r}
		level := []string{r}
		for depth := 0; depth < wpDepth-1; depth++ {
			var next []string
			for _, d := range level {
				ents, err := readDirMax(src, d, wpMaxDirEntries)
				if errors.Is(err, errTooMany) {
					unread = append(unread, d+" (more than "+strconv.Itoa(wpMaxDirEntries)+" entries: the rest not looked at for Drupal)")
				} else if err != nil {
					if depth == 0 && !errors.Is(err, fs.ErrNotExist) {
						unread = append(unread, d+" ("+err.Error()+")")
					}
					continue
				}
				for _, e := range ents {
					p := ops.Join(d, e.name)
					switch {
					case e.isLink():
						if _, err := hostenv.Stat(src, ops.Join(p, "core", "lib", "Drupal.php")); err == nil {
							unread = append(unread, p+" (a link to a Drupal, not followed)")
						}
					case e.isDir() && len(cands)+len(next) < wpMaxCandidates:
						next = append(next, p)
					}
				}
			}
			cands, level = append(cands, next...), next
		}
		for _, root := range cands {
			f := ops.Join(root, "core", "lib", "Drupal.php")
			st, err := hostenv.Lstat(src, f)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil:
				unread = append(unread, f+" ("+err.Error()+")")
				continue
			case st.Mode&fs.ModeSymlink != 0:
				unread = append(unread, f+" (a link, not followed)")
				continue
			case !st.Mode.IsRegular() || seen[root]:
				continue
			}
			seen[root] = true
			b, err := hostenv.ReadFileMax(src, f, drupalPHPBytes)
			if err != nil {
				unread = append(unread, f+" ("+err.Error()+")")
				continue
			}
			c := DrupalCore{Root: root}
			if m := drupalVersion.FindSubmatch(b); m != nil {
				c.Version = string(m[1])
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Root < out[j].Root })
	return out, unread
}

// drupalSA is a Drupal core advisory: the versions it covers, as ranges
// [from, to) (from "" for "every one before to").
type drupalSA struct {
	id, cve, what string
	exploited     bool
	ranges        [][2]string
	fixed         string
}

// drupalSAs are the core advisories checked (SA-CORE-2026-017, -019: the
// installer, exploited on live sites).
var drupalSAs = []drupalSA{
	{"SA-CORE-2026-017", "CVE-2026-132165", "remote code execution through the installer (install.php)", true,
		[][2]string{{"", "10.6.22"}, {"11.0.0", "11.3.22"}, {"11.4.0", "11.4.13"}}, "10.6.22, 11.3.22 or 11.4.13"},
	{"SA-CORE-2026-019", "CVE-2026-136716", "site takeover through the installer of a site left in an incomplete install state", true,
		[][2]string{{"", "10.6.23"}, {"11.0.0", "11.3.23"}, {"11.4.0", "11.4.14"}}, "10.6.23, 11.3.23 or 11.4.14, then run update.php"},
}

// drupalNumbers parses a release version (10.6.21, 11.4.0): false for one
// that is not (11.x-dev, 10.6.21-rc1).
func drupalNumbers(v string) ([3]int, bool) {
	var n [3]int
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return n, false
	}
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil || x < 0 {
			return n, false
		}
		n[i] = x
	}
	return n, true
}

func drupalLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// drupalAffected reports whether version is in sa's ranges; known is false
// when the version cannot be compared.
func drupalAffected(sa drupalSA, version string) (affected, known bool) {
	v, ok := drupalNumbers(version)
	if !ok {
		return false, false
	}
	for _, r := range sa.ranges {
		to, _ := drupalNumbers(r[1])
		if r[0] != "" {
			if from, _ := drupalNumbers(r[0]); drupalLess(v, from) {
				continue
			}
		}
		if drupalLess(v, to) {
			return true, true
		}
	}
	return false, true
}

// drupalRisks are the advisories each installation's version is in, and a
// note for a version that cannot be compared (never taken for a fixed one).
func drupalRisks(sites []DrupalCore, unread []string) []Risk {
	var out []Risk
	for _, s := range sites {
		var hit []string
		known := true
		for _, sa := range drupalSAs {
			a, k := drupalAffected(sa, s.Version)
			known = known && k
			if a {
				hit = append(hit, fmt.Sprintf("%s (%s, %s%s): upgrade to %s", sa.id, sa.cve, sa.what, exploitedSuffix(sa.exploited), sa.fixed))
			}
		}
		switch {
		case len(hit) > 0:
			out = append(out, Risk{"drupal:core:" + s.Root, "critical", "Drupal core " + s.Version + " at " + s.Root + " is in the affected range of " + strings.Join(hit, "; ")})
		case !known:
			v := s.Version
			if v == "" {
				v = "(no version read)"
			}
			out = append(out, Risk{uncheckedPrefix + "drupal:" + s.Root, "info", "cannot tell whether Drupal core " + v + " at " + s.Root + " is affected by " + drupalSAIDs() + ": its version is not a release version"})
		}
	}
	if len(unread) > 0 {
		out = append(out, Risk{uncheckedPrefix + "drupal", "info", "Drupal installations not looked for in full: " + Cut(strings.Join(unread, "; "), 400)})
	}
	return out
}

func exploitedSuffix(e bool) string {
	if e {
		return ", exploited on live sites"
	}
	return ""
}

func drupalSAIDs() string {
	var ids []string
	for _, sa := range drupalSAs {
		ids = append(ids, sa.id)
	}
	return strings.Join(ids, " and ")
}
