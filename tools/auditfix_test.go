package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	} {
		if got := uploadFolder(p, nil); got != want {
			t.Errorf("uploadFolder(%q) = %v, want %v", p, got, want)
		}
	}
	// With the web server's configuration, the folder is right under a web root.
	if !uploadFolder("/srv/app/web/media/x.php", []string{"/srv/app/web"}) || uploadFolder("/srv/app/lib/media/x.php", []string{"/srv/app/web"}) {
		t.Error("web roots")
	}
}
