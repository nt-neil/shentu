package detect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/rules/engine"
)

// P5 part 1: a round read and judged. Neutral markers, real files.

const combined = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

type fakeSources struct {
	logs  []hostenv.LogSource
	units []hostenv.AppUnit
}

func (f fakeSources) WebLogs(hostenv.Source) hostenv.Obs[[]hostenv.LogSource] {
	return hostenv.OK(f.logs)
}
func (f fakeSources) AppUnits(hostenv.Source) hostenv.Obs[[]hostenv.AppUnit] {
	return hostenv.OK(f.units)
}
func (f fakeSources) WebAccounts(hostenv.Source) hostenv.WebAccounts { return hostenv.WebAccounts{} }

func accessLine(ip string, at time.Time, path string, status int, bytes int) string {
	return fmt.Sprintf("%s - - [%s] \"GET %s HTTP/1.1\" %d %d \"-\" \"marker-agent\"\n", ip, at.Format("02/Jan/2006:15:04:05 -0700"), path, status, bytes)
}

func passSetup(t *testing.T) (*hostenv.Live, string, PassInput) {
	t.Helper()
	src, d := logDir(t)
	rootUID = os.Getuid()
	state := t.TempDir()
	var acc strings.Builder
	for i := 0; i < 30; i++ { // ordinary responses of the route, from 30 sources
		acc.WriteString(accessLine(fmt.Sprintf("192.0.2.%d", i+1), t0.Add(time.Duration(i)*time.Second), "/marker/5", 200, 1000+i%5*10))
	}
	acc.WriteString(accessLine("198.51.100.7", t0.Add(time.Minute), "/marker/5?q=marker-one", 200, 9000))
	write(t, filepath.Join(d, "access.log"), acc.String(), os.O_CREATE)
	write(t, filepath.Join(d, "php.log"), "["+t0.Add(time.Minute+5*time.Second).Format("02-Jan-2006 15:04:05")+" UTC] PHP Warning:  marker in /srv/www/app/x.php on line 12\n", os.O_CREATE)
	ast, _ := hostenv.Stat(src, "/logs/access.log")
	pst, _ := hostenv.Stat(src, "/logs/php.log")
	srcs := fakeSources{logs: []hostenv.LogSource{
		{Path: "/logs/access.log", Server: "nginx", Kind: "access", Format: "combined", Spec: combined, Verified: true, FileID: ast.ID},
		{Path: "/logs/php.log", Server: "php-fpm", Kind: "php_error", Verified: true, FileID: pst.ID},
	}}
	surface := Build([]CodeSink{{Rule: "php-sqli", CWE: "CWE-89", Severity: "warning", Path: "app/x.php", Line: 12,
		Routes: []engine.RouteRef{{Model: "m", Framework: "laravel", Method: "get", Pattern: "/marker/{id}", File: "routes/web.php", Line: 3}}}}, nil)
	return src, d, PassInput{Src: src, Sources: srcs, StateDir: state, Surface: surface, Sigs: loadSigs(t, markerSigs),
		Now: t0.Add(2 * time.Minute), Budget: NewBudget(DefaultBudgetBytes, time.Minute), Loc: time.UTC}
}

func TestRunPass(t *testing.T) {
	_, d, in := passSetup(t)
	p, err := RunPass(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	due := p.Due()
	if len(due) != 1 || due[0].Level != LevelSuccess || due[0].Unverified || due[0].Severity != "high" || strings.Join(due[0].IPs, ",") != "198.51.100.7" {
		t.Fatalf("due %+v", due)
	}
	if !strings.Contains(due[0].Success, "回應大小") || !strings.Contains(due[0].Success, "錯誤記錄") {
		t.Errorf("L3 evidence: %q", due[0].Success)
	}
	if len(p.Sources) != 2 || p.Sources[0].Kind != "php_error" || p.Sources[1].Read.Lines != 31 {
		t.Errorf("sources %+v", p.Sources)
	}
	p.Notified(due[0])
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	p.Close()
	// The next round: nothing new read, nothing due; the state kept.
	in.Now = in.Now.Add(time.Hour)
	q, err := RunPass(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if len(q.Due()) != 0 || q.Sources[1].Read.Lines != 0 || len(q.Attacks().Groups) == 0 {
		t.Errorf("second round: due %d, lines %d, groups %d", len(q.Due()), q.Sources[1].Read.Lines, len(q.Attacks().Groups))
	}
	_ = d
}

// Notices: a log much of which does not parse, an invalid cursor, a
// stuck one.
func TestRunPassNotices(t *testing.T) {
	_, d, in := passSetup(t)
	var junk strings.Builder
	for i := 0; i < 30; i++ {
		junk.WriteString("marker not a request line\n")
	}
	write(t, filepath.Join(d, "access.log"), junk.String(), os.O_APPEND)
	if err := os.WriteFile(filepath.Join(in.StateDir, CursorFileName), []byte(`{"version":1,"sources":{"/logs/access.log":{"offset":-5}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := RunPass(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	txt := p.NoticeText()
	for _, want := range []string{"30 / 61 行無法依格式解析", "讀取進度無效，已從頭讀"} {
		if !strings.Contains(txt, want) {
			t.Errorf("notices lack %q:\n%s", want, txt)
		}
	}
	p.NoticesSent()
	if p.NoticeText() != "" {
		t.Errorf("notices after they were sent: %q", p.NoticeText())
	}
}

// A pending group past the TTL is not dropped quietly: merged into its
// overflow group, counted.
func TestPruneTTLPending(t *testing.T) {
	a := newAttacks()
	a.Add(att("192.0.2.1", "e1", LevelPayload, t0), t0)
	a.prune(t0.Add(AttackTTL + time.Hour))
	if len(a.Groups) != 0 || a.DroppedPending != 1 || len(a.Overflow) != 1 {
		t.Fatalf("groups %d, dropped %d, overflow %d", len(a.Groups), a.DroppedPending, len(a.Overflow))
	}
	for _, o := range a.Overflow {
		if o.Since != 1 || len(a.Due(t0.Add(AttackTTL+time.Hour))) != 1 {
			t.Errorf("overflow %+v", o)
		}
	}
}

// Set-aside copies of a state file are kept, the latest five.
func TestKeepBadFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 7; i++ {
		os.WriteFile(filepath.Join(dir, AttacksFile+fmt.Sprintf(".bad-%d", 1000+i)), nil, 0o600)
	}
	os.WriteFile(filepath.Join(dir, AttacksFile), []byte("{not json"), 0o600)
	a, err := LoadAttacks(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	m, _ := filepath.Glob(filepath.Join(dir, AttacksFile+".bad-*"))
	if len(m) != MaxBadFiles {
		t.Errorf("%d set-aside copies: %v", len(m), m)
	}
	for _, f := range m {
		if strings.HasSuffix(f, "-1000") || strings.HasSuffix(f, "-1001") || strings.HasSuffix(f, "-1002") {
			t.Errorf("an old copy kept: %s", f)
		}
	}
}

// Many empty journal entries spend the budget, not only the time.
func TestJournalEmptyEntriesCost(t *testing.T) {
	var lines []string
	var curs []string
	for i := 0; i < 50; i++ {
		c := fmt.Sprintf("s=%032x;i=%d", i, i)
		curs = append(curs, c)
		lines = append(lines, entry(c, "app.service", "0", ""))
	}
	src := &journalSrc{entries: lines, cursors: curs}
	n := 0
	_, res, err := ReadJournalUnit(context.Background(), src, hostenv.AppUnit{Name: "app.service"}, nil, NewBudget(10*JournalEntryCost, time.Minute), hostenv.WebAccounts{},
		func(hostenv.JournalEntry, JournalTrust) { n++ })
	if err != nil || n > 11 || !strings.Contains(strings.Join(res.Partial, ","), ReadTruncated) {
		t.Errorf("%d empty entries read on a budget of 10, partial %v, %v", n, res.Partial, err)
	}
}

// stuckSrc stalls opening one log, as a dead mount does, until let go.
type stuckSrc struct {
	*hostenv.Live
	path string
	gate chan struct{}
}

func (s stuckSrc) OpenLog(p string) (hostenv.LogFile, error) {
	if p == s.path {
		<-s.gate
	}
	return s.Live.OpenLog(p)
}

// A round given up keeps what its finished sources gave and their
// cursors; the source being read is read again next round; it is said,
// louder after PassTimeoutsWarn rounds in a row (commander, P5 part 2).
func TestPassAbandon(t *testing.T) {
	live, d, in := passSetup(t)
	write(t, filepath.Join(d, "stuck.log"), accessLine("192.0.2.200", t0, "/marker/7", 200, 10), os.O_CREATE)
	st, _ := hostenv.Stat(live, "/logs/stuck.log")
	srcs := in.Sources.(fakeSources)
	srcs.logs = append(srcs.logs, hostenv.LogSource{Path: "/logs/stuck.log", Server: "nginx", Kind: "access", Format: "combined", Spec: combined, Verified: true, FileID: st.ID})
	in.Sources = srcs
	for round := 1; round <= PassTimeoutsWarn; round++ {
		gate := make(chan struct{})
		in.Src = stuckSrc{live, "/logs/stuck.log", gate}
		in.Now = t0.Add(time.Duration(round) * time.Hour)
		p, err := NewPass(in)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { p.Run(context.Background()); close(done) }()
		for i := 0; i < 500; i++ { // until the round reaches the stuck log
			p.mu.Lock()
			cur := p.current
			p.mu.Unlock()
			if cur == "/logs/stuck.log" {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		p.Abandon(time.Second)
		due := p.Due()
		if round == 1 && (len(due) != 1 || due[0].Level != LevelSuccess) {
			t.Fatalf("round 1: the finished log's attempt not kept: %+v", due)
		}
		txt := p.NoticeText()
		want := "沒有讀完（停在 /logs/stuck.log）"
		if round == PassTimeoutsWarn {
			want = fmt.Sprintf("已連續 %d 輪沒有讀完", PassTimeoutsWarn)
		}
		if !strings.Contains(txt, want) {
			t.Errorf("round %d notice lacks %q:\n%s", round, want, txt)
		}
		for _, g := range due {
			p.Notified(g)
		}
		if err := p.Save(); err != nil {
			t.Fatal(err)
		}
		p.Close()
		close(gate) // the stuck read goes on, after the round was given up
		<-done
		cs, _ := LoadCursors(in.StateDir)
		if _, ok := cs.Sources["/logs/stuck.log"]; ok {
			t.Fatalf("round %d: the stuck log's cursor saved", round)
		}
		if c, ok := cs.Sources["/logs/access.log"]; !ok || c.Offset == 0 {
			t.Fatalf("round %d: the finished log's cursor not saved: %+v", round, c)
		}
	}
	// A round read to its end clears the count.
	in.Src, in.Now = live, t0.Add(10*time.Hour)
	p, err := RunPass(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Attacks().PassTimeouts != 0 || strings.Contains(p.NoticeText(), "沒有讀完") {
		t.Errorf("after a whole round: timeouts %d", p.Attacks().PassTimeouts)
	}
}
