package detect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/hostenv"
)

// cve4577Surface is a host whose PHP the host check found affected by
// CVE-2024-4577, as KEV lists it.
func cve4577Surface(kev bool) Surface {
	return Build(nil, []PackageVuln{{Source: "os", Ecosystem: "Windows", Package: "php", Version: "8.3.7", ID: "CVE-2024-4577", CVE: "CVE-2024-4577", KEV: kev}})
}

// TestCVE20244577Signature: php-cgi's options sent in a query string are
// L2 on a host with the vulnerability, noise on one without; ordinary
// queries and other routes are neither.
func TestCVE20244577Signature(t *testing.T) {
	ss, err := sig.Load()
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(ss)
	for _, c := range []struct {
		name, path, query string
		hit               bool
	}{
		{"soft hyphen %AD, -d", "/index.php", "%ADd+allow_url_include%3d1", true},
		{"soft hyphen %AD, -s", "/index.php", "%ADs", true},
		{"soft hyphen in UTF-8 %C2%AD", "/index.php", "%C2%ADs", true},
		{"upper-case %ad and path", "/Index.PHP", "%adS", true},
		{"a hyphen (CVE-2012-1823's form)", "/info.php", "-s", true},
		{"php-cgi itself", "/php-cgi/php-cgi.exe", "%ADd+allow_url_include%3d1", true},
		{"soft hyphen, the value right after the option", "/index.php", "%ADdx", true},
		{"PATH_INFO after the .php file", "/index.php/x", "%ADs", true},
		{"the index page, logged as /", "/", "%ADs", true},
		{"a byte that is not UTF-8 reads as U+FFFD too (known false hit)", "/a.php", "%E9a", true},
		{"a hyphen with the value right after the option (control)", "/index.php", "-dx", false},
		{"a parameter (control)", "/index.php", "s=1", false},
		{"a hyphen in a value (control)", "/index.php", "q=-d+x", false},
		{"a word starting with a hyphen (control)", "/index.php", "-debug", false},
		{"no PHP route (control)", "/img/a.png", "%ADs", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := m.Match(Normalize(AccessRecord{Method: "GET", Path: c.path, Query: c.query}))
			g := NewJudge(cve4577Surface(true), ss).Judge(r)
			got := len(g.Candidates) == 1 && g.Candidates[0].Level == LevelPayload && hasSig(g.Candidates[0].Hits, "cve-2024-4577-php-cgi-options")
			if got != c.hit {
				t.Errorf("%s?%s: %+v, want a hit %v", c.path, c.query, g, c.hit)
			}
			if !c.hit {
				return
			}
			n := NewJudge(Build(nil, nil), ss).Judge(r)
			if len(n.Candidates) != 0 || !hasSig(n.Noise, "cve-2024-4577-php-cgi-options") {
				t.Errorf("no vulnerability on the host: %+v, want noise only", n)
			}
		})
	}
}

func hasSig(hs []Hit, id string) bool {
	for _, h := range hs {
		if h.Signature == id {
			return true
		}
	}
	return false
}

// TestCVE20244577Pass: through a round of the real entry, an access log
// line read and judged. On a host whose surface has the CVE, as KEV lists
// it, the attack is due and its alert says KEV; on one without, nothing is
// due.
func TestCVE20244577Pass(t *testing.T) {
	for _, c := range []struct {
		name    string
		surface Surface
		due     bool
	}{
		{"surface has CVE-2024-4577 (KEV)", cve4577Surface(true), true},
		{"no such vulnerability", Build(nil, nil), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src, d := logDir(t)
			rootUID = os.Getuid()
			line := accessLine("198.51.100.9", t0.Add(time.Minute), "/index.php?%ADd+allow_url_include%3d1", 200, 1200)
			write(t, filepath.Join(d, "access.log"), line, os.O_CREATE)
			st, _ := hostenv.Stat(src, "/logs/access.log")
			srcs := fakeSources{logs: []hostenv.LogSource{{Path: "/logs/access.log", Server: "nginx", Kind: "access", Format: "combined", Spec: combined, Verified: true, FileID: st.ID}}}
			ss, err := sig.Load()
			if err != nil {
				t.Fatal(err)
			}
			p, err := RunPass(context.Background(), PassInput{Src: src, Sources: srcs, StateDir: t.TempDir(), Surface: c.surface, Sigs: ss,
				Now: t0.Add(2 * time.Minute), Budget: NewBudget(DefaultBudgetBytes, time.Minute), Loc: time.UTC})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			due := p.Due()
			if !c.due {
				if len(due) != 0 {
					t.Errorf("due %+v, want none", due)
				}
				return
			}
			if len(due) != 1 || due[0].CVE != "CVE-2024-4577" || !due[0].KEV || strings.Join(due[0].IPs, ",") != "198.51.100.9" {
				t.Fatalf("due %+v (sources %+v), want one KEV attack of CVE-2024-4577", due, p.Sources)
			}
			if text := AlertText(due[0], &c.surface); !strings.Contains(text, "CISA KEV") {
				t.Errorf("alert lacks the KEV mark: %q", text)
			}
		})
	}
}
