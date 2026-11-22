package tools

import (
	"context"
	"errors"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/hostenv"
)

// phpWinHost is a hand-written Windows host: files (Apache's configuration,
// PHP's binaries), the system code page and the KEV catalog.
type phpWinHost struct {
	files map[string]string
	confs []string
	acp   string
	acpOK bool
	iis   []string
	kev   map[string]kevEntry
	kevOK bool
	reads []string // every path read, to see none is a network one
}

func newPHPWinHost(t *testing.T) *phpWinHost {
	h := &phpWinHost{files: map[string]string{}, acp: "1252", acpOK: true, kev: map[string]kevEntry{}, kevOK: true}
	win, fcgi, read, dir, confs, acp, kev := phpWindows, phpWinFastCGI, phpReadBin, phpReadDir, phpWinApacheConfs, phpWinACP, phpLoadKEV
	t.Cleanup(func() {
		phpWindows, phpWinFastCGI, phpReadBin, phpReadDir, phpWinApacheConfs, phpWinACP, phpLoadKEV = win, fcgi, read, dir, confs, acp, kev
	})
	phpWindows = true
	phpWinFastCGI = func() ([]string, error) { return h.iis, nil }
	phpReadBin = func(p string) ([]byte, error) {
		h.reads = append(h.reads, p)
		if s, ok := h.files[strings.ToLower(p)]; ok {
			if s == "\x00denied" {
				return nil, os.ErrPermission
			}
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	phpReadDir = func(d string) ([]string, error) {
		var out []string
		pre := strings.ToLower(strings.TrimRight(d, `\`)) + `\`
		for p := range h.files {
			if rest, ok := strings.CutPrefix(p, pre); ok && !strings.Contains(rest, `\`) {
				out = append(out, rest)
			}
		}
		if out == nil {
			return nil, os.ErrNotExist
		}
		sort.Strings(out)
		return out, nil
	}
	phpWinApacheConfs = func() ([]string, []string) { return h.confs, nil }
	phpWinACP = func() (string, error) {
		if !h.acpOK {
			return "", errors.New("access denied")
		}
		return h.acp, nil
	}
	phpLoadKEV = func(context.Context, *http.Client) (map[string]kevEntry, error) {
		if !h.kevOK {
			return nil, errors.New("offline")
		}
		return h.kev, nil
	}
	return h
}

func (h *phpWinHost) file(p, content string) { h.files[strings.ToLower(p)] = content }

// phpCGI puts a php-cgi.exe of version in dir, its version in php8ts.dll.
func (h *phpWinHost) phpCGI(dir, version string) {
	h.file(dir+`\php-cgi.exe`, "MZ\x00stub\x00")
	h.file(dir+`\php8ts.dll`, "MZ\x00X-Powered-By: PHP/"+version+"\x00")
}

// xampp is XAMPP's layout: httpd.conf includes httpd-xampp.conf, which
// maps /php-cgi/ onto the PHP folder.
func (h *phpWinHost) xampp(version string) {
	h.file(`C:\xampp\apache\conf\httpd.conf`, "Define SRVROOT \"C:/xampp/apache\"\nServerRoot \"${SRVROOT}\"\nListen 80\n"+
		"LoadModule cgi_module modules/mod_cgi.so\nInclude \"conf/extra/httpd-xampp.conf\"\n")
	h.file(`C:\xampp\apache\conf\extra\httpd-xampp.conf`, "<IfModule mime_module>\n  AddType text/html .php .phps\n</IfModule>\n"+
		"ScriptAlias /php-cgi/ \"C:/xampp/php/\"\n<Directory \"C:/xampp/php\">\n  AllowOverride None\n  Require all denied\n"+
		"  <Files \"php-cgi.exe\">\n    Require all granted\n  </Files>\n</Directory>\n")
	h.phpCGI(`C:\xampp\php`, version)
	h.confs = []string{`C:\xampp\apache\conf\httpd.conf`}
}

func TestPHPApacheCGI(t *testing.T) {
	cgi := func(h *phpWinHost) ([]string, []string) { return phpApacheCGI(h.confs[0], phpReadBin, phpReadDir) }
	h := newPHPWinHost(t)
	h.xampp("8.3.7")
	if got, un := cgi(h); !slices.Equal(got, []string{`C:\xampp\php\php-cgi.exe`}) || len(un) != 0 {
		t.Errorf("XAMPP ScriptAlias: %q %q", got, un)
	}
	// Apache Lounge: Action through a ScriptAlias, files included by a glob.
	h = newPHPWinHost(t)
	h.file(`C:\Apache24\conf\httpd.conf`, "Define SRVROOT \"c:/Apache24\"\nServerRoot \"${SRVROOT}\"\nIncludeOptional conf/extra/*.conf\n")
	h.file(`C:\Apache24\conf\extra\php.conf`, "ScriptAlias /php/ \"D:/php83/\"\nAddHandler application/x-httpd-php .php\n"+
		"Action application/x-httpd-php \"/php/php-cgi.exe\"\n")
	h.file(`C:\Apache24\conf\extra\other.conf`, "# Action application/x-httpd-php \"/x/php-cgi.exe\"\n")
	h.phpCGI(`D:\php83`, "8.3.7")
	h.confs = []string{`C:\Apache24\conf\httpd.conf`}
	if got, _ := cgi(h); !slices.Equal(got, []string{`D:\php83\php-cgi.exe`}) {
		t.Errorf("Action via ScriptAlias: %q", got)
	}
	// The Action's file in a folder under the alias: only the Action finds it.
	h = newPHPWinHost(t)
	h.file(`C:\Apache24\conf\httpd.conf`, "ServerRoot \"C:/Apache24\"\nScriptAlias /php/ \"D:/php/\"\n"+
		"Action application/x-httpd-php \"/php/v83/php-cgi.exe\"\n")
	h.phpCGI(`D:\php\v83`, "8.3.7")
	h.confs = []string{`C:\Apache24\conf\httpd.conf`}
	if got, _ := cgi(h); !slices.Equal(got, []string{`D:\php\v83\php-cgi.exe`}) {
		t.Errorf("Action under the alias: %q", got)
	}
	// AddHandler cgi-script .exe in the PHP folder's Directory.
	h = newPHPWinHost(t)
	h.file(`C:\Apache24\conf\httpd.conf`, "ServerRoot \"C:/Apache24\"\nAlias /php/ \"C:/php/\"\n<Directory \"C:/php\">\n"+
		"  Options +ExecCGI\n  AddHandler cgi-script .exe\n</Directory>\n")
	h.phpCGI(`C:\php`, "8.2.19")
	h.confs = []string{`C:\Apache24\conf\httpd.conf`}
	if got, _ := cgi(h); !slices.Equal(got, []string{`C:\php\php-cgi.exe`}) {
		t.Errorf("AddHandler cgi-script: %q", got)
	}
	// Not CGI: mod_php, a commented ScriptAlias, a ScriptAlias with no php-cgi.exe.
	h = newPHPWinHost(t)
	h.file(`C:\Apache24\conf\httpd.conf`, "ServerRoot \"C:/Apache24\"\nLoadModule php_module \"C:/php/php8apache2_4.dll\"\n"+
		"#ScriptAlias /php-cgi/ \"C:/php/\"\nScriptAlias /cgi-bin/ \"C:/Apache24/cgi-bin/\"\n<Directory \"C:/Apache24/cgi-bin\">\n  AddHandler cgi-script .exe\n</Directory>\n")
	h.phpCGI(`C:\php`, "8.3.7")
	h.confs = []string{`C:\Apache24\conf\httpd.conf`}
	if got, un := cgi(h); len(got) != 0 || len(un) != 0 {
		t.Errorf("mod_php: %q %q", got, un)
	}
	// An included file that cannot be read is named.
	h = newPHPWinHost(t)
	h.file(`C:\Apache24\conf\httpd.conf`, "ServerRoot \"C:/Apache24\"\nInclude conf/extra/php.conf\n")
	h.file(`C:\Apache24\conf\extra\php.conf`, "\x00denied")
	h.confs = []string{`C:\Apache24\conf\httpd.conf`}
	if got, un := cgi(h); len(got) != 0 || len(un) != 1 || !strings.Contains(un[0], "php.conf") {
		t.Errorf("unreadable include: %q %q", got, un)
	}
}

// CVE-2024-4577: 8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8; CVE-2024-8926:
// 8.1 < 8.1.30, 8.2 < 8.2.24, 8.3 < 8.3.12 (NVD, GHSA-3qgc-jrrr-25jv,
// GHSA-p99j-rfp4-xqvq). Branches before 8.1 are not listed and not fixed.
func TestPHPArgInjAffected(t *testing.T) {
	for v, want := range map[string][2]string{
		"8.1.28": {"yes", "yes"}, "8.1.29": {"", "yes"}, "8.1.30": {"", ""},
		"8.2.19": {"yes", "yes"}, "8.2.20": {"", "yes"}, "8.2.23": {"", "yes"}, "8.2.24": {"", ""},
		"8.3.7": {"yes", "yes"}, "8.3.8": {"", "yes"}, "8.3.11": {"", "yes"}, "8.3.12": {"", ""},
		"8.4.0": {"", ""}, "8.5.1": {"", ""}, "9.0.0": {"", ""},
		"8.0.30": {"eol", "eol"}, "7.4.33": {"eol", "eol"}, "5.6.40": {"eol", "eol"}, "": {"", ""}, "8.3.x": {"", ""},
	} {
		rel, _ := phpRelease(v)
		for i, c := range phpArgInjCVEs {
			got := ""
			if aff, eol := phpArgInjAffected(rel, c); eol {
				got = "eol"
			} else if aff {
				got = "yes"
			}
			if got != want[i] {
				t.Errorf("%s %s: %q, want %q", v, c.id, got, want[i])
			}
		}
	}
}

// 4577: the Best-Fit code pages 932, 936, 950 (GHSA). 8926: the ANSI code
// page pointed at an OEM one, not a standard ANSI code page (GHSA: 437).
func TestPHPArgInjCodePages(t *testing.T) {
	c4577, c8926 := phpArgInjCVEs[0], phpArgInjCVEs[1]
	for acp, want := range map[string][2]bool{
		"932": {true, false}, "936": {true, false}, "950": {true, false}, "1252": {false, false}, "949": {false, false},
		"65001": {false, false}, "437": {false, true}, "850": {false, true}, "37": {false, true}, " 950 ": {true, false},
	} {
		if got := [2]bool{c4577.codePage(acp), c8926.codePage(acp)}; got != want {
			t.Errorf("ACP %q: %v, want %v", acp, got, want)
		}
	}
}

func TestPHPRisksWindowsApache(t *testing.T) {
	h := newPHPWinHost(t)
	h.xampp("8.3.7")
	h.acp = "950"
	r := phpRisks(context.Background())
	a := phpFind(r, "php8.3:CVE-2024-4577")
	if a == nil || a.Severity != "critical" || Unchecked(*a) {
		t.Fatalf("Apache php-cgi, code page 950: %v", phpKeys(r))
	}
	for _, s := range []string{"Apache", "950", "8.3.8", `C:\xampp\php\php-cgi.exe`, "httpd.conf"} {
		if !strings.Contains(a.Summary, s) {
			t.Errorf("4577 summary lacks %q: %s", s, a.Summary)
		}
	}
	if phpFind(r, "php8.3:CVE-2024-8926") != nil {
		t.Errorf("8926 needs an OEM code page, not 950: %v", phpKeys(r))
	}
	// Apache runs it as CGI: #195's php-cgi advisory too.
	if c := phpFind(r, "php8.3:CVE-2026-129538"); c == nil || !strings.Contains(c.Summary, "Apache") {
		t.Errorf("129538 under Apache: %v", phpKeys(r))
	}
	// A code page without Best-Fit: neither.
	h.acp = "1252"
	if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2024-4577") != nil || phpFind(r, "php8.3:CVE-2024-8926") != nil {
		t.Errorf("code page 1252: %v", phpKeys(r))
	}
	// An OEM code page as the ANSI one: 8926.
	h.acp = "437"
	if r := phpRisks(context.Background()); phpFind(r, "php8.3:CVE-2024-8926") == nil || phpFind(r, "php8.3:CVE-2024-4577") != nil {
		t.Errorf("code page 437: %v", phpKeys(r))
	}
	// The code page cannot be read: reported, not confirmed.
	h.acpOK = false
	r = phpRisks(context.Background())
	for _, k := range []string{"php8.3:CVE-2024-4577", "php8.3:CVE-2024-8926"} {
		if x := phpFind(r, k); x == nil || x.Severity != "warning" || !strings.Contains(x.Summary, "code page unconfirmed") {
			t.Errorf("code page unread, %s: %v", k, r)
		}
	}
	// Fixed versions.
	h = newPHPWinHost(t)
	h.xampp("8.3.12")
	h.acp = "950"
	for _, x := range phpRisks(context.Background()) {
		if strings.Contains(x.Key, "CVE-2024-") {
			t.Errorf("8.3.12: %s", x.Key)
		}
	}
	// A branch php.net no longer fixes: warning, the advisory does not list it.
	h = newPHPWinHost(t)
	h.xampp("8.0.30")
	h.acp = "932"
	r = phpRisks(context.Background())
	if x := phpFind(r, "php8.0:CVE-2024-4577"); x == nil || x.Severity != "warning" || !strings.Contains(x.Summary, "not listed") {
		t.Errorf("8.0 eol: %v", r)
	}
	// No Apache: IIS's php-cgi is not reported for them, the version line says why.
	h = newPHPWinHost(t)
	h.phpCGI(`C:\PHP`, "8.3.7")
	h.iis = []string{`C:\PHP\php-cgi.exe`}
	h.acp = "950"
	r = phpRisks(context.Background())
	if phpFind(r, "php8.3:CVE-2024-4577") != nil {
		t.Errorf("IIS reported for 4577: %v", phpKeys(r))
	}
	if v := phpFind(r, "php8.3:CVE-2026-129496"); v == nil || !strings.Contains(v.Summary, "CVE-2024-4577") || !strings.Contains(v.Summary, "Apache only") {
		t.Errorf("IIS version line: %v", r)
	}
}

func TestPHPWinSurface(t *testing.T) {
	h := newPHPWinHost(t)
	h.xampp("8.3.7")
	h.acp = "950"
	h.kev["CVE-2024-4577"] = kevEntry{Name: "Example name from the catalog", Added: "2024-06-12"}
	s, note := phpWinSurface(context.Background(), nil)
	if len(s) != 1 || note != "" {
		t.Fatalf("surface: %+v %q", s, note)
	}
	want := detect.PackageVuln{Source: "os", Ecosystem: "PHP", Package: "php-cgi", Version: "8.3.7", ID: "CVE-2024-4577", CVE: "CVE-2024-4577",
		Severity: "critical", Fixed: "8.3.8", KEV: true, KEVSince: "2024-06-12", KEVCVE: "CVE-2024-4577"}
	if !slices.EqualFunc(s, []detect.PackageVuln{want}, func(a, b detect.PackageVuln) bool {
		return a.ID == b.ID && a.Fixed == b.Fixed && a.KEV == b.KEV &&
			a.KEVSince == b.KEVSince && a.Severity == b.Severity && a.Package == b.Package && a.Version == b.Version && a.Ecosystem == b.Ecosystem
	}) {
		t.Errorf("entry: %+v", s[0])
	}
	// KEV comes from the catalog: a CVE not in it is not marked.
	h.acp = "437"
	if s, _ := phpWinSurface(context.Background(), nil); len(s) != 1 || s[0].ID != "CVE-2024-8926" || s[0].KEV || s[0].Fixed != "8.3.12" {
		t.Errorf("8926 not in KEV: %+v", s)
	}
	// The catalog unavailable: entries kept, not marked, said so.
	h.kevOK = false
	if s, note := phpWinSurface(context.Background(), nil); len(s) != 1 || s[0].KEV || !strings.Contains(note, "KEV") {
		t.Errorf("KEV offline: %+v %q", s, note)
	}
	// Code page unconfirmed and a branch php.net no longer fixes: kept, not rated as confirmed.
	h.kevOK, h.acpOK = true, false
	if s, _ := phpWinSurface(context.Background(), nil); len(s) != 2 || s[0].Severity != "medium" || s[1].Severity != "medium" {
		t.Errorf("code page unread: %+v", s)
	}
	h = newPHPWinHost(t)
	h.xampp("7.4.33")
	h.acp = "936"
	h.kev["CVE-2024-4577"] = kevEntry{Name: "x", Added: "2024-06-12"}
	if s, _ := phpWinSurface(context.Background(), nil); len(s) != 1 || s[0].Severity != "medium" || !s[0].KEV || s[0].Fixed != "" {
		t.Errorf("7.4 eol: %+v", s)
	}
	// IIS's php-cgi only: nothing.
	h = newPHPWinHost(t)
	h.phpCGI(`C:\PHP`, "8.3.7")
	h.iis = []string{`C:\PHP\php-cgi.exe`}
	h.acp = "950"
	if s, _ := phpWinSurface(context.Background(), nil); len(s) != 0 {
		t.Errorf("IIS: %+v", s)
	}
}

// The security review of 2132c62: Apache's configuration names paths; a
// network or device path is never read (reading \\host\share makes Windows
// authenticate to that host), a fixed place anyone may create is read only
// when kept to administrators, and what is read is capped.
func TestPHPApacheCGINotLocal(t *testing.T) {
	win, read, dir := phpWindows, phpReadBin, phpReadDir // the default readers, before any host replaces them
	for _, conf := range []string{
		"ServerRoot \"C:/Apache24\"\nInclude \"//files.example/share/php.conf\"\n",
		"ServerRoot \"C:/Apache24\"\nIncludeOptional \\\\files.example\\share\\*.conf\n",
		"ServerRoot \"//files.example/apache\"\nInclude conf/extra/php.conf\n",
		"ServerRoot \"C:/Apache24\"\nScriptAlias /php/ \"//files.example/php/\"\n",
		"ServerRoot \"C:/Apache24\"\nScriptAlias /php/ \"//?/C:/php/\"\n",
		"ServerRoot \"C:/Apache24\"\n<Directory \"//./pipe/php\">\n  AddHandler cgi-script .exe\n</Directory>\n",
	} {
		h := newPHPWinHost(t)
		h.file(`C:\Apache24\conf\httpd.conf`, conf)
		h.confs = []string{`C:\Apache24\conf\httpd.conf`}
		exes, un := phpApacheCGI(h.confs[0], phpReadBin, phpReadDir)
		for _, p := range h.reads {
			if !phpLocalWinPath(p) {
				t.Errorf("%q: read %s", conf, p)
			}
		}
		if len(exes) != 0 || len(un) == 0 || !strings.Contains(strings.Join(un, " "), "not a local absolute path") {
			t.Errorf("%q: %q %q", conf, exes, un)
		}
	}
	// The default readers refuse one too.
	defer func() { phpWindows, phpReadBin, phpReadDir = win, read, dir }()
	newPHPWinHost(t)
	phpWindows, phpReadBin, phpReadDir = true, read, dir
	if _, err := phpReadBin(`\\files.example\share\php8ts.dll`); err != errNotLocal {
		t.Errorf("phpReadBin: %v", err)
	}
	if _, err := phpReadDir(`\\files.example\share`); err != errNotLocal {
		t.Errorf("phpReadDir: %v", err)
	}
}

func TestPHPApacheCGIReadCap(t *testing.T) {
	max := phpApacheMax
	defer func() { phpApacheMax = max }()
	h := newPHPWinHost(t)
	h.file(`C:\Apache24\conf\httpd.conf`, "ServerRoot \"C:/Apache24\"\n"+strings.Repeat("# padding\n", 20)+"Include conf/extra/php.conf\n")
	h.file(`C:\Apache24\conf\extra\php.conf`, "ScriptAlias /php/ \"C:/php/\"\n")
	h.phpCGI(`C:\php`, "8.3.7")
	phpApacheMax = 50
	if exes, un := phpApacheCGI(`C:\Apache24\conf\httpd.conf`, phpReadBin, phpReadDir); len(exes) != 0 || len(un) != 1 || !strings.Contains(un[0], "limit") {
		t.Errorf("past the cap: %q %q", exes, un)
	}
	phpApacheMax = max
	if exes, _ := phpApacheCGI(`C:\Apache24\conf\httpd.conf`, phpReadBin, phpReadDir); len(exes) != 1 {
		t.Errorf("under the cap: %q", exes)
	}
}

func TestPHPWinApacheConfs(t *testing.T) {
	h := newPHPWinHost(t)
	confs, svc, sec := phpWinApacheConfs, phpWinServiceBins, winFileSecurity
	defer func() { phpWinApacheConfs, phpWinServiceBins, winFileSecurity = confs, svc, sec }()
	phpWinApacheConfs = winApacheConfs
	acl := map[string]hostenv.WinFileSecurity{}
	winFileSecurity = func(p string) (hostenv.WinFileSecurity, error) {
		if s, ok := acl[strings.ToLower(p)]; ok {
			return s, nil
		}
		return hostenv.WinFileSecurity{}, errors.New("access denied")
	}
	admins := hostenv.WinFileSecurity{Owner: "S-1-5-18", Writers: []string{"S-1-5-18", "S-1-5-32-544"}}
	users := hostenv.WinFileSecurity{Owner: "S-1-5-32-544", Writers: []string{"S-1-5-32-544", "S-1-5-32-545"}}
	h.file(`C:\xampp\apache\conf\httpd.conf`, "ServerRoot \"C:/xampp/apache\"\n")
	h.file(`D:\web\Apache24\conf\httpd.conf`, "ServerRoot \"D:/web/Apache24\"\n")
	// A service's Apache is read wherever it is; XAMPP's place only when kept to administrators.
	phpWinServiceBins = func() []string {
		return []string{`"D:\web\Apache24\bin\httpd.exe" -k runservice`, `C:\Windows\System32\svchost.exe -k netsvcs`}
	}
	acl[`c:\xampp\apache\conf\httpd.conf`] = admins
	got, un := winApacheConfs()
	if !slices.Equal(got, []string{`C:\xampp\apache\conf\httpd.conf`, `D:\web\Apache24\conf\httpd.conf`}) || len(un) != 0 {
		t.Errorf("admins only: %q %q", got, un)
	}
	acl[`c:\xampp\apache\conf\httpd.conf`] = users
	got, un = winApacheConfs()
	if !slices.Equal(got, []string{`D:\web\Apache24\conf\httpd.conf`}) || len(un) != 1 || !strings.Contains(un[0], "S-1-5-32-545") {
		t.Errorf("writable by Users: %q %q", got, un)
	}
	delete(acl, `c:\xampp\apache\conf\httpd.conf`)
	if got, un = winApacheConfs(); len(got) != 1 || len(un) != 1 || !strings.Contains(un[0], "could not be read") {
		t.Errorf("ACL unknown: %q %q", got, un)
	}
	// A service whose httpd.exe is on a network share: its conf is not read.
	phpWinServiceBins = func() []string { return []string{`\\files.example\apache\bin\httpd.exe`} }
	acl[`c:\xampp\apache\conf\httpd.conf`] = admins
	h.reads = nil
	if got, _ = winApacheConfs(); !slices.Equal(got, []string{`C:\xampp\apache\conf\httpd.conf`}) {
		t.Errorf("network service: %q", got)
	}
	for _, p := range h.reads {
		if !phpLocalWinPath(p) {
			t.Errorf("read %s", p)
		}
	}
}
