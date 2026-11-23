package tools

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

// #200 review 1.

// realWinFiles writes files whose names are Windows paths into a fresh
// folder and makes it the working directory, so the real readers
// (phpReadApache, phpStatWin, phpReadLimited) open them: on macOS and Linux
// C:\x\y.conf is one file name in the current folder.
func realWinFiles(t *testing.T, files map[string]string) {
	d := t.TempDir()
	t.Chdir(d)
	for p, c := range files {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	win := phpWindows
	t.Cleanup(func() { phpWindows = win })
	phpWindows = true
}

// N-1: the configuration is read through phpReadLimited with the file cap
// and what is left of the total, and what was read counts. On 5cba7db
// each file was read whole (up to 64 MiB) and only files kept counted.
func TestPHPReview200ConfReadCaps(t *testing.T) {
	max := phpApacheMax
	t.Cleanup(func() { phpApacheMax = max })
	phpApacheMax = 1 << 20
	pad := strings.Repeat("# padding padding padding padding padding padding padding\n", 700<<10/58)
	realWinFiles(t, map[string]string{
		`C:\Apache24\conf\httpd.conf`:     "ServerRoot \"C:/Apache24\"\nLoadModule cgi_module modules/mod_cgi.so\nInclude conf/extra/a.conf\nInclude conf/extra/b.conf\n",
		`C:\Apache24\conf\extra\a.conf`:   pad,
		`C:\Apache24\conf\extra\b.conf`:   pad + "ScriptAlias /php/ \"C:/php/\"\n",
		`C:\php\php-cgi.exe`:              "MZ\x00stub\x00",
		`C:\Apache24\conf\extra\big.conf`: "",
	})
	exes, un, _ := phpApacheCGI(`C:\Apache24\conf\httpd.conf`)
	if len(exes) != 0 || len(un) != 1 || !strings.Contains(un[0], `b.conf (not read: past the include limit)`) {
		t.Errorf("b.conf past the total: %q %q", exes, un)
	}
	phpApacheMax = max
	if exes, un, _ := phpApacheCGI(`C:\Apache24\conf\httpd.conf`); len(exes) != 1 || len(un) != 0 {
		t.Errorf("under the total: %q %q", exes, un)
	}

	// Rejected reads count too: two files over phpConfMax use up the
	// total, and the third, under phpConfMax, is past it.
	conf := phpConfMax
	t.Cleanup(func() { phpConfMax = conf })
	phpConfMax, phpApacheMax = 400<<10, 1<<20
	over := strings.Repeat("# padding padding padding padding padding padding padding\n", 500<<10/58)
	realWinFiles(t, map[string]string{
		`C:\Apache24\conf\httpd.conf`:   "ServerRoot \"C:/Apache24\"\nLoadModule cgi_module modules/mod_cgi.so\nInclude conf/extra/a.conf\nInclude conf/extra/b.conf\nInclude conf/extra/c.conf\n",
		`C:\Apache24\conf\extra\a.conf`: over,
		`C:\Apache24\conf\extra\b.conf`: over,
		`C:\Apache24\conf\extra\c.conf`: pad[:300<<10] + "\nScriptAlias /php/ \"C:/php/\"\n",
		`C:\php\php-cgi.exe`:            "MZ\x00stub\x00",
	})
	exes, un, _ = phpApacheCGI(`C:\Apache24\conf\httpd.conf`)
	if len(exes) != 0 || len(un) != 3 || !strings.Contains(un[2], `c.conf (not read: past the include limit)`) {
		t.Errorf("rejected reads not counted: %q %q", exes, un)
	}
	phpConfMax, phpApacheMax = conf, max

	// One file over phpConfMax: no more than the cap is read.
	big := `C:\Apache24\conf\extra\big.conf`
	if err := os.WriteFile(big, []byte(strings.Repeat("#", int(phpConfMax)+4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := phpReadApache(big, phpConfMax); !errors.Is(err, errTooLarge) || int64(len(b)) > phpConfMax {
		t.Errorf("big file: %d bytes, %v", len(b), err)
	}
	if err := phpStatWin(`C:\php\php-cgi.exe`); err != nil {
		t.Errorf("stat: %v", err)
	}
	if err := phpStatWin(`C:\php\none.exe`); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stat of none: %v", err)
	}
}

// N-1 (minor): past the limit, one line and a count, not a line a file.
func TestPHPReview200LimitOneLine(t *testing.T) {
	h := newPHPWinHost(t)
	conf := "ServerRoot \"C:/Apache24\"\n"
	for i := 0; i < 300; i++ {
		f := `C:\Apache24\conf\extra\` + string(rune('a'+i%26)) + strings.Repeat("x", i/26) + ".conf"
		h.file(f, "# empty\n")
		conf += "Include \"" + strings.ReplaceAll(f, `\`, "/") + "\"\n"
	}
	h.file(`C:\Apache24\conf\httpd.conf`, conf)
	_, un, _ := phpApacheCGI(`C:\Apache24\conf\httpd.conf`)
	if len(un) != 2 || !strings.Contains(un[1], "44 more Apache configuration files") {
		t.Errorf("past the limit: %d lines, last %q", len(un), un[len(un)-1])
	}
}

// N-2: two Apache php-cgi programs of one branch, a key each; one program
// two configurations run, one risk naming both.
func TestPHPReview200Keys(t *testing.T) {
	h := newPHPWinHost(t)
	h.acp = "950"
	for _, c := range []struct{ conf, dir string }{{`C:\a\conf\httpd.conf`, `C:\php835`}, {`C:\b\conf\httpd.conf`, `C:\php837`}, {`C:\c\conf\httpd.conf`, `C:\php837`}} {
		h.file(c.conf, "LoadModule cgi_module modules/mod_cgi.so\nScriptAlias /php/ \""+strings.ReplaceAll(c.dir, `\`, "/")+"/\"\n")
		h.confs = append(h.confs, c.conf)
	}
	h.phpCGI(`C:\php835`, "8.3.5")
	h.phpCGI(`C:\php837`, "8.3.7")
	r := phpRisks(context.Background())
	seen := map[string]int{}
	for _, x := range r {
		seen[x.Key]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("key %s %d times", k, n)
		}
	}
	a, b := phpFind(r, `php8.3@C:\php835\php-cgi.exe:CVE-2024-4577`), phpFind(r, `php8.3@C:\php837\php-cgi.exe:CVE-2024-4577`)
	if a == nil || b == nil {
		t.Fatalf("keys: %v", phpKeys(r))
	}
	if !strings.Contains(b.Summary, `C:\b\conf\httpd.conf, C:\c\conf\httpd.conf`) || strings.Contains(a.Summary, `C:\b\`) {
		t.Errorf("confs: %s | %s", a.Summary, b.Summary)
	}
	if s, _ := phpWinSurface(context.Background(), nil); len(s) != 2 {
		t.Errorf("surface: %+v", s)
	}
}

// S-1: IIS and Apache with the same version are two groups: IIS's line
// says IIS (and why 4577 is not reported for it), Apache's says Apache.
func TestPHPReview200IISApacheApart(t *testing.T) {
	h := newPHPWinHost(t)
	h.acp = "950"
	h.iis = []string{`C:\iisphp\php-cgi.exe`}
	h.phpCGI(`C:\iisphp`, "8.3.7")
	h.xampp("8.3.7")
	r := phpRisks(context.Background())
	var iis, apache int
	for _, x := range r {
		if !strings.Contains(x.Key, "CVE-2026-129538") {
			continue
		}
		hasIIS, hasApache := strings.Contains(x.Summary, `C:\iisphp`), strings.Contains(x.Summary, `C:\xampp\php`)
		switch {
		case hasIIS && hasApache:
			t.Errorf("one line for both: %s", x.Summary)
		case hasIIS:
			iis++
		case hasApache:
			apache++
		}
	}
	if iis != 1 || apache != 1 {
		t.Errorf("129538 lines: IIS %d, Apache %d: %v", iis, apache, phpKeys(r))
	}
	for _, x := range r {
		if strings.Contains(x.Summary, "are not reported for it") && strings.Contains(x.Summary, `C:\xampp\php`) {
			t.Errorf("the IIS note on Apache's line: %s", x.Summary)
		}
	}
	if phpFind(r, `php8.3@C:\xampp\php\php-cgi.exe:CVE-2024-4577`) == nil && phpFind(r, "php8.3:CVE-2024-4577") == nil {
		t.Errorf("Apache's 4577: %v", phpKeys(r))
	}
}

// S-2: no LoadModule cgi_module read: reported, as a warning that says why.
func TestPHPReview200CGIModule(t *testing.T) {
	h := newPHPWinHost(t)
	h.acp = "950"
	h.xampp("8.3.7")
	f := `c:\xampp\apache\conf\httpd.conf`
	h.files[f] = strings.Replace(h.files[f], "LoadModule cgi_module", "#LoadModule cgi_module", 1)
	r := phpRisks(context.Background())
	a := phpFind(r, "php8.3:CVE-2024-4577")
	if a == nil || a.Severity != "warning" || !strings.Contains(a.Summary, "cgi_module") {
		t.Fatalf("no cgi_module: %v", r)
	}
	if s, _ := phpWinSurface(context.Background(), nil); len(s) != 1 || s[0].Severity != "medium" {
		t.Errorf("surface: %+v", s)
	}
	h.files[f] = strings.Replace(h.files[f], "#LoadModule cgi_module", "LoadModule cgid_module", 1)
	if a := phpFind(phpRisks(context.Background()), "php8.3:CVE-2024-4577"); a == nil || a.Severity != "critical" {
		t.Errorf("cgid_module: %v", a)
	}
}

// The real readers, kept before any test host replaces them.
var defaultReadApache, defaultStatWin, defaultReadDir, defaultReadBin = phpReadApache, phpStatWin, phpReadDir, phpReadBin

type fakeInfo struct{ mode fs.FileMode }

func (f fakeInfo) Name() string       { return "" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

// S-3: a link on the way to a file is followed only to a local path, and
// nothing remote is looked at, not even with Lstat.
func TestPHPWinLocal(t *testing.T) {
	lstat, readlink := phpLstat, phpReadlink
	t.Cleanup(func() { phpLstat, phpReadlink = lstat, readlink })
	links := map[string]string{
		`C:\Apache24\conf\extra`: `\\files.example\share\extra`,
		`C:\Apache24\conf\local`: `D:\conf`,
		`C:\Apache24\conf\rel`:   `..\shared`,
		`C:\Apache24\conf\root`:  `\shared`,
		`C:\Apache24\conf\dev`:   `\\?\C:\x`,
		`C:\Apache24\conf\loop`:  `C:\Apache24\conf\loop`,
		`D:\conf\back`:           `\\files.example\share`,
		`C:\Apache24\conf\dedup`: "",
		`C:\Apache24\conf\slash`: `//files.example/share`,
	}
	var looked []string
	phpLstat = func(p string) (os.FileInfo, error) {
		looked = append(looked, p)
		if _, ok := links[p]; ok {
			if p == `C:\Apache24\conf\dedup` {
				return fakeInfo{os.ModeIrregular}, nil
			}
			return fakeInfo{os.ModeSymlink}, nil
		}
		return fakeInfo{0}, nil
	}
	phpReadlink = func(p string) (string, error) {
		if t := links[p]; t != "" {
			return t, nil
		}
		return "", errors.New("not a link")
	}
	for in, want := range map[string]string{
		`C:\Apache24\conf\httpd.conf`:          `C:\Apache24\conf\httpd.conf`,
		`C:\Apache24\conf\extra\php.conf`:      "not a local absolute path",
		`C:\Apache24\conf\local\php.conf`:      `D:\conf\php.conf`,
		`C:\Apache24\conf\rel\php.conf`:        `C:\Apache24\shared\php.conf`,
		`C:\Apache24\conf/extra/php.conf`:      "not a local absolute path",
		`C:\Apache24\conf\x\..\extra\php.conf`: "not a local absolute path",
		`C:\Apache24\conf\.\\extra\php.conf`:   "not a local absolute path",
		`C:\Apache24\conf\slash\php.conf`:      "not a local absolute path",
		`C:\..\..\Apache24\conf\httpd.conf`:    `C:\Apache24\conf\httpd.conf`,
		`C:\Apache24\conf\root\php.conf`:       `C:\shared\php.conf`,
		`C:\Apache24\conf\dev\php.conf`:        "not a local absolute path",
		`C:\Apache24\conf\loop\php.conf`:       "too many links",
		`C:\Apache24\conf\local\back\x.conf`:   "not a local absolute path",
		`C:\Apache24\conf\dedup\php.conf`:      "not followed",
		`\\files.example\share\php.conf`:       "not a local absolute path",
	} {
		looked = nil
		got, err := phpWinLocal(in)
		if err != nil {
			got = err.Error()
		}
		if !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
		for _, p := range looked {
			if !phpLocalWinPath(p) || strings.Contains(p, "/") || winClean(p) != p {
				t.Errorf("%s: looked at %s", in, p)
			}
		}
	}
	// The readers refuse through a link too.
	newPHPWinHost(t)
	phpReadApache, phpStatWin, phpReadDir, phpReadBin = defaultReadApache, defaultStatWin, defaultReadDir, defaultReadBin
	if _, err := phpReadApache(`C:\Apache24\conf\extra\php.conf`, 10); !errors.Is(err, errNotLocal) {
		t.Errorf("phpReadApache through a remote link: %v", err)
	}
	if err := phpStatWin(`C:\Apache24\conf\extra\php.conf`); !errors.Is(err, errNotLocal) {
		t.Errorf("phpStatWin through a remote link: %v", err)
	}
	if _, err := phpReadDir(`C:\Apache24\conf\extra`); !errors.Is(err, errNotLocal) {
		t.Errorf("phpReadDir through a remote link: %v", err)
	}
	phpWindows = true
	if _, err := phpReadBin(`C:\Apache24\conf\extra\php8ts.dll`); !errors.Is(err, errNotLocal) {
		t.Errorf("phpReadBin through a remote link: %v", err)
	}
}
