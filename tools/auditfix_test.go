package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// isNote: a summary of the audit itself, which comes before the findings.
func isNote(f CodeFinding) bool { return f.Kind == "audit" || f.Kind == "injection" && f.Rule == "" }

// When the caller's time runs out the findings scanned so far stay, and the
// result says the audit is unfinished (the review of cff48b1, B4).
func TestAppCodeAuditKeepsFindingsWhenCtxEnds(t *testing.T) {
	isolateAudit(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	for i := range 40 {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("a%02d.php", i)), []byte("<?php\nsystem($_GET['a']);\n"), 0o644)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scan := engineScan
	defer func() { engineScan = scan }()
	var once sync.Once
	engineScan = func(e *engine.Engine, lang, p string, b []byte) ([]engine.Finding, bool, error) {
		found, timed, err := scan(e, lang, p, b)
		once.Do(cancel) // the tool's time ends after the first file
		return found, timed, err
	}
	res := AppCodeAudit(ctx, []string{dir}, nil)
	if res.Injection == 0 || findingFor(res, "injection", "a00.php").Rule == "" && res.Injection == 0 {
		t.Fatalf("the findings scanned before the end were dropped: %+v", res)
	}
	if !res.Unfinished || len(res.Findings) == 0 || res.Findings[0].Kind != "audit" || !strings.Contains(res.Findings[0].Detail, "unfinished") {
		t.Fatalf("the result does not say it is unfinished: %+v", res.Findings[:min(3, len(res.Findings))])
	}
	if !strings.Contains(res.Findings[0].Detail, "had not reached") {
		t.Errorf("the summary does not say what was not checked: %s", res.Findings[0].Detail)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Detail, "every file was checked on its own") {
			t.Errorf("claims every file was checked: %s", f.Detail)
		}
	}
}

// A walk the caller's time cuts short lists its root as not walked to the end.
func TestAppCodeAuditWalkCut(t *testing.T) {
	isolateAudit(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(dir, "a.php"), []byte("<?php\necho 1;\n"), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := AppCodeAudit(ctx, []string{dir}, nil)
	// A cancelled context may lose the race for the slot too: both say unfinished.
	if !res.Unfinished || res.Findings[0].Kind != "audit" || len(res.Findings[0].Files) != 1 || res.Findings[0].Files[0].Path != dir {
		t.Errorf("got %+v", res.Findings)
	}
}

// The injection rules stop before the caller's time, leaving time to wrap up:
// the files they had no time for are "time" in the summary, the result is
// complete, and it is back before the caller's time is up.
func TestAppCodeAuditStopsBeforeCtx(t *testing.T) {
	isolateAudit(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	for i := range 100 {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("a%02d.php", i)), []byte("<?php\nsystem($_GET['a']);\n"), 0o644)
	}
	scan := engineScan
	defer func() { engineScan = scan }()
	engineScan = func(e *engine.Engine, lang, p string, b []byte) ([]engine.Finding, bool, error) {
		time.Sleep(100 * time.Millisecond)
		return scan(e, lang, p, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	res := AppCodeAudit(ctx, []string{dir}, nil)
	if ctx.Err() != nil {
		t.Error("the audit ran past the caller's time")
	}
	if res.Injection == 0 || res.Unfinished {
		t.Fatalf("injection %d, unfinished %v", res.Injection, res.Unfinished)
	}
	if f := res.Findings[0]; f.Kind != "injection" || !strings.Contains(f.Detail, "after the audit's time limit") {
		t.Errorf("first: %+v", f)
	}
}

// Findings are capped per rule and file and in all; the summaries come first
// and are never left out (S8, S10).
func TestAppCodeAuditCaps(t *testing.T) {
	isolateAudit(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	awsKey := "AKIA" + strings.Repeat("Q7", 8)
	line := "k = '" + awsKey + "'\n"
	n := auditMaxFindings/auditMaxPerFile + 10
	for i := range n {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("k%03d.yml", i)), []byte(strings.Repeat(line, auditMaxPerFile+5)), 0o644)
	}
	os.MkdirAll(filepath.Join(dir, "public"), 0o755)
	os.WriteFile(filepath.Join(dir, "public", ".env"), []byte("APP_KEY=x\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "open.php"), []byte("<?php\n$a = 'never closed\n"), 0o644)
	res := AppCodeAudit(context.Background(), []string{dir}, nil)
	listed, perFile := 0, map[string]int{}
	notes := true
	for _, f := range res.Findings {
		if isNote(f) {
			if !notes {
				t.Errorf("a summary after the findings: %+v", f)
			}
			continue
		}
		notes = false
		listed++
		perFile[f.Path]++
	}
	if listed != auditMaxFindings || !res.Truncated {
		t.Errorf("listed %d, truncated %v", listed, res.Truncated)
	}
	for p, c := range perFile {
		if c > auditMaxPerFile {
			t.Errorf("%s: %d findings", p, c)
		}
	}
	// The critical .env comes after the list is full of warnings, and is listed.
	if f := findingFor(res, "exposed", ".env"); f.Severity != "critical" {
		t.Error("a critical finding was left out for warnings")
	}
	if f := res.Findings[0]; f.Kind != "audit" || !strings.Contains(f.Detail, "more finding(s) are not listed") {
		t.Errorf("first: %+v", f)
	}
	var partial bool
	for _, f := range res.Findings {
		partial = partial || isNote(f) && strings.Contains(f.Detail, "only in part")
	}
	if !partial {
		t.Error("the summary of unfinished files was left out")
	}
}

// Severity sorts critical, warning, then the rest, then by path and line.
func TestAppCodeAuditOrder(t *testing.T) {
	isolateAudit(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	awsKey := "AKIA" + strings.Repeat("Q7", 8)
	os.MkdirAll(filepath.Join(dir, "public"), 0o755)
	os.WriteFile(filepath.Join(dir, "public", ".env"), []byte("APP_KEY=x\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "public", "a.zip"), []byte("PK"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte("x\nk: "+awsKey+"\nk: "+awsKey+"\n"), 0o644)
	res := AppCodeAudit(context.Background(), []string{dir}, nil)
	var got []string
	for _, f := range res.Findings {
		if !isNote(f) {
			got = append(got, fmt.Sprintf("%s %s %d", f.Severity, filepath.Base(f.Path), f.Line))
		}
	}
	want := "critical .env 0|warning b.yml 2|warning b.yml 3|warning a.zip 0" // by path: dir/b.yml before dir/public/a.zip
	if strings.Join(got, "|") != want {
		t.Errorf("order %q, want %q", strings.Join(got, "|"), want)
	}
}

// One audit runs at a time; a second one waits, in this process and for the
// lock file of another (S11).
func TestAppCodeAuditOneAtATime(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(dir, "a.php"), []byte("<?php\nsystem($_GET['a']);\n"), 0o644)
	state := t.TempDir()
	idx := codeIndexFile
	defer func() { codeIndexFile = idx }()
	codeIndexFile = func() string { return filepath.Join(state, "codeindex.json") }

	run := func(ctx context.Context) <-chan CodeAudit {
		c := make(chan CodeAudit, 1)
		go func() { c <- AppCodeAudit(ctx, []string{dir}, nil) }()
		return c
	}
	// Another audit in this process.
	unlock, err := lockAudit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := run(context.Background())
	select {
	case <-c:
		t.Fatal("ran while another audit held the turn")
	case <-time.After(300 * time.Millisecond):
	}
	unlock()
	if res := <-c; res.Injection == 0 || res.Unfinished {
		t.Errorf("after waiting: %+v", res)
	}
	// Another process: its lock on the file.
	f, err := os.OpenFile(filepath.Join(state, "audit.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	c = run(context.Background())
	select {
	case <-c:
		t.Fatal("ran while another process held the lock")
	case <-time.After(300 * time.Millisecond):
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if res := <-c; res.Injection == 0 {
		t.Errorf("after the other process: %+v", res)
	}
	// Waiting longer than the caller's time: unfinished, nothing checked.
	syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	res := <-run(ctx)
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if !res.Unfinished || len(res.Findings) != 1 || res.Findings[0].Files[0].Reason != "wait" {
		t.Errorf("timed out waiting: %+v", res)
	}
}

// The kept results of at most callStateMax sets of roots stay, the most
// recently written ones (S13).
func TestPruneCallStates(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i := range 20 {
		n := filepath.Join(dir, fmt.Sprintf("codecalls-%02d.json", i))
		os.WriteFile(n, []byte("{}"), 0o600)
		at := now.Add(time.Duration(i) * time.Minute)
		os.Chtimes(n, at, at)
	}
	os.WriteFile(filepath.Join(dir, "codeindex.json"), []byte("{}"), 0o600)
	pruneCallStates(dir, 16)
	for i := range 20 {
		_, err := os.Stat(filepath.Join(dir, fmt.Sprintf("codecalls-%02d.json", i)))
		if gone := err != nil; gone != (i < 4) {
			t.Errorf("codecalls-%02d.json: gone %v", i, gone)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "codeindex.json")); err != nil {
		t.Error("the code index was removed")
	}
}

// Only folders uploads land in count as upload folders: a folder named like
// one inside a library's code is not (the VM run on WordPress, where
// wp-includes/php-ai-client/src/Files/ holds PHP classes).
func TestUploadFolder(t *testing.T) {
	for p, want := range map[string]bool{
		"/srv/wordpress/wp-includes/php-ai-client/src/Files/DTO/File.php": false,
		"/srv/wordpress/wp-content/uploads/x.php":                         true,
		"/srv/wordpress/wp-content/uploads/2026/11/x.php":                 true,
		"/srv/wordpress/wp-content/plugins/p/files/x.php":                 false,
		"/srv/wordpress/wp-content/plugins/p/vendor/a/uploads/x.php":      false,
		"/srv/shop/public/uploads/cat.php":                                true,
		"/srv/shop/public/files/a.php":                                    true,
		"/var/www/shop/upload/a.php":                                      true,
		"/srv/shop/storage/app/public/a.php":                              true,
		"/srv/shop/vendor/x/files/a.php":                                  false,
		"/srv/shop/src/Media/Images.php":                                  false,
		"/srv/shop/app/Files/Upload.php":                                  false,
		"/srv/shop/lib/images/resize.php":                                 false,
		"/srv/wordpress/wp-content/uploads/src/vendor/x.php":              true,
		"/srv/wordpress/wp-content/Uploads/x.php":                         true,
		"/srv/shop/public/Uploads/a.php":                                  true,
		"/srv/shop/storage/app/public/src/a.php":                          true,
		// The review of 3df48d5 (N7): only the path below the site's root counts.
		"/usr/src/app/wp-content/uploads/x.php":          true,
		"/home/u/src/site/wp-content/uploads/2024/x.php": true,
		"/var/www/drupal/sites/default/files/x.php":      true,
		"/var/www/magento/pub/media/x.php":               true,
		"/var/www/files/index.php":                       false, // a site named files
		"/var/www/files/lib/a.php":                       false,
		"/var/www/files/uploads/a.php":                   true,
	} {
		if got := uploadFolder(p, nil); got != want {
			t.Errorf("uploadFolder(%q) = %v, want %v", p, got, want)
		}
	}
	// With the web server's configuration, the folder is right under a web root.
	roots := []string{"/srv/app/web", "/var/www/files"}
	if !uploadFolder("/srv/app/web/media/x.php", roots) || uploadFolder("/srv/app/web/lib/media/x.php", roots) {
		t.Error("web roots")
	}
	if uploadFolder("/var/www/files/index.php", roots) || uploadFolder("/var/www/files/x/y.php", roots) {
		t.Error("a web root named files is not an upload folder")
	}
	// An app path outside every web root still has the folders it is known by.
	if !uploadFolder("/srv/other/public/uploads/x.php", roots) || !uploadFolder("/opt/wp/wp-content/uploads/x.php", roots) {
		t.Error("app paths outside the web roots")
	}
}

// isolateAudit keeps an audit's code index, kept results and lock in a
// folder of the test, never /var/lib/shentu or the user's cache.
func isolateAudit(t *testing.T) string {
	t.Helper()
	state := t.TempDir()
	idx := codeIndexFile
	t.Cleanup(func() { codeIndexFile = idx })
	codeIndexFile = func() string { return filepath.Join(state, "codeindex.json") }
	return state
}

// A file with a finding on every line is capped where the findings come
// from: the heap and the kept results stay bounded, the counts take them all
// (the review of 3df48d5, R1).
func TestAppCodeAuditFindingsBoundedAtTheSource(t *testing.T) {
	if testing.Short() {
		t.Skip("scans 4MB")
	}
	state := isolateAudit(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	line := "system($_GET['a']);\n"
	body := "<?php\n" + strings.Repeat(line, 100<<10/len(line)) // 100KB, under the engine's limits
	const n = 40                                                // 4MB in all
	for i := range n {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%02d.php", i)), []byte(body), 0o644)
	}
	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	max := injectionMaxTime
	defer func() { injectionMaxTime = max }()
	injectionMaxTime = 10 * time.Minute
	res := AppCodeAudit(context.Background(), []string{dir}, nil)
	close(done)
	listed := 0
	for _, f := range res.Findings {
		if f.Kind == "injection" && f.Rule != "" && f.Rule != "-" {
			listed++
		}
	}
	var stateSize int64
	files, _ := filepath.Glob(filepath.Join(state, "codecalls-*.json"))
	for _, f := range files {
		if info, err := os.Stat(f); err == nil {
			stateSize += info.Size()
		}
	}
	t.Logf("injection %d, listed %d, peak heap %dMB, kept results %dKB", res.Injection, listed, peak.Load()>>20, stateSize>>10)
	if listed > n*auditMaxPerFile*2 || !res.Truncated {
		t.Errorf("listed %d, truncated %v", listed, res.Truncated)
	}
	if res.Injection < n*auditMaxPerFile*10 {
		t.Errorf("the counts lost the findings left out: %d", res.Injection)
	}
	if stateSize > 1<<20 {
		t.Errorf("kept results %d bytes", stateSize)
	}
	if peak.Load() > 300<<20 {
		t.Errorf("peak heap %dMB", peak.Load()>>20)
	}
}

// A file left for the rules' time limit means not every file was checked on
// its own: the cross-file summary does not say it was (N8).
func TestAppCodeAuditLateNotAllChecked(t *testing.T) {
	isolateAudit(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(dir, "a.php"), []byte("<?php\necho 1;\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.py"), []byte("print(1)\n"), 0o644)
	scan := engineScan
	max := injectionMaxTime
	defer func() { engineScan, injectionMaxTime = scan, max; SetAuditLimits(0, 0) }()
	injectionMaxTime = 300 * time.Millisecond
	SetAuditLimits(0, 1)
	engineScan = func(e *engine.Engine, lang, p string, b []byte) ([]engine.Finding, bool, error) {
		time.Sleep(400 * time.Millisecond)
		return scan(e, lang, p, b)
	}
	var cross string
	for _, f := range AppCodeAudit(context.Background(), []string{dir}, nil).Findings {
		if strings.Contains(f.Detail, "calls across files") {
			cross = f.Detail
		}
	}
	if cross == "" || strings.Contains(cross, "every file was checked on its own") {
		t.Errorf("cross-file summary: %q", cross)
	}
}

// A walk cut short does not take the files it did not reach as gone: their
// kept results stay for the next audit (N9).
func TestDropStaleWalkCut(t *testing.T) {
	newState := func() *callState {
		return &callState{Files: map[string]*fileState{
			"/a.php": {Hash: "1", Calls: &passResult{}, Deps: []string{"/b.php"}},
			"/b.php": {Hash: "2", Calls: &passResult{}},
		}}
	}
	st := newState()
	if bad := st.dropStale(map[string]string{"/a.php": "1"}, false); len(bad) != 0 || st.Files["/a.php"].Calls == nil {
		t.Errorf("walk cut: dropped %v", bad)
	}
	st = newState()
	if bad := st.dropStale(map[string]string{"/a.php": "1"}, true); !bad["/b.php"] || !bad["/a.php"] {
		t.Errorf("walk done: dropped %v, want b and its caller a", bad)
	}
}

// The files a file's calls reach are replaced when all its rules were
// followed again: a callee no longer called does not keep it stale (S9).
func TestSetDepsReplaces(t *testing.T) {
	fs := &fileState{Deps: []string{"/gone.php", "/kept.php"}}
	fs.setDeps([]string{"/new.php", "/kept.php"})
	if strings.Join(fs.Deps, ",") != "/kept.php,/new.php" {
		t.Errorf("deps %v", fs.Deps)
	}
	st := &callState{Files: map[string]*fileState{"/a.php": {Hash: "1", Calls: &passResult{}, Deps: fs.Deps},
		"/kept.php": {Hash: "2"}, "/new.php": {Hash: "3"}}}
	if bad := st.dropStale(map[string]string{"/a.php": "1", "/kept.php": "2", "/new.php": "3"}, true); len(bad) != 0 {
		t.Errorf("stale %v", bad)
	}
}

// When the list is full, alerts outrank info-tier injection findings (and
// those in test or generated code) whatever their severity (N10).
func TestListRank(t *testing.T) {
	alertCrit := CodeFinding{Kind: "injection", Severity: "critical", Tier: "alert", Rule: "r"}
	infoCrit := CodeFinding{Kind: "injection", Severity: "critical", Tier: "info", Rule: "r"}
	testCrit := CodeFinding{Kind: "injection", Severity: "critical", Tier: "alert", Rule: "r", TestPath: true}
	minCrit := CodeFinding{Kind: "injection", Severity: "critical", Tier: "alert", Rule: "r", Generated: true}
	secret := CodeFinding{Kind: "secret", Severity: "warning"}
	exposed := CodeFinding{Kind: "exposed", Severity: "critical"}
	if !(listRank(exposed) == listRank(alertCrit) && listRank(alertCrit) < listRank(secret) && listRank(secret) < listRank(infoCrit) &&
		listRank(infoCrit) == listRank(testCrit) && listRank(testCrit) == listRank(minCrit)) {
		t.Errorf("ranks: alert %d, exposed %d, secret %d, info %d, test %d, minified %d", listRank(alertCrit), listRank(exposed),
			listRank(secret), listRank(infoCrit), listRank(testCrit), listRank(minCrit))
	}
}
