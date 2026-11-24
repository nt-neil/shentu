package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/tools"
)

// sshJournalHost is a Linux host where nothing can be read but journald's
// sshd units, which it answers as journalctl does (-o json, --since,
// --cursor from that entry on), keeping each read's start.
type sshJournalHost struct {
	mu      sync.Mutex
	entries [][2]string // cursor, JSON line
	reads   []string
}

func (h *sshJournalHost) failed(at time.Time, ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(h.entries) + 1
	c := fmt.Sprintf("s=0123456789abcdef0123456789abcdef;i=%x;b=0123456789abcdef0123456789abcdef;m=%x;t=%x;x=%x", n, n, n, n)
	b, _ := json.Marshal(map[string]string{"__CURSOR": c, "__REALTIME_TIMESTAMP": strconv.FormatInt(at.UnixMicro(), 10),
		"_SYSTEMD_UNIT": "ssh.service", "_UID": "0", "_PID": "812", "_COMM": "sshd", "SYSLOG_IDENTIFIER": "sshd",
		"MESSAGE": "Failed password for root from " + ip + " port 22 ssh2"})
	h.entries = append(h.entries, [2]string{c, string(b)})
}

func (h *sshJournalHost) Info() hostenv.SourceInfo         { return hostenv.SourceInfo{GOOS: "linux"} }
func (h *sshJournalHost) ReadFile(string) ([]byte, error)  { return nil, fs.ErrNotExist }
func (h *sshJournalHost) ReadDir(string) ([]string, error) { return nil, fs.ErrNotExist }
func (h *sshJournalHost) Readlink(string) (string, error)  { return "", fs.ErrNotExist }
func (h *sshJournalHost) Run(context.Context, []string) (hostenv.CmdResult, error) {
	return hostenv.CmdResult{}, fs.ErrNotExist
}

func (h *sshJournalHost) RunLinesCut(_ context.Context, argv []string, _ int, fn func(string, bool)) (hostenv.CmdResult, error) {
	if !strings.Contains(strings.Join(argv, " "), "-u ssh -u sshd -u ssh@* -u sshd@*") {
		return hostenv.CmdResult{}, fs.ErrNotExist // the other reads: nothing here
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	from := 0
	for i, a := range argv {
		switch a {
		case "--since":
			h.reads = append(h.reads, "since")
		case "--cursor":
			h.reads = append(h.reads, "cursor "+argv[i+1])
			from = len(h.entries)
			for n, e := range h.entries {
				if e[0] == argv[i+1] {
					from = n
				}
			}
		}
	}
	for _, e := range h.entries[from:] {
		fn(e[1], false)
	}
	return hostenv.CmdResult{}, nil
}

// The patrol keeps block_ip's login index: a patrol with the index on reads
// sshd's journal and saves the index, and a check after it reads on from the
// patrol's cursor only, not the month again.
func TestPatrolRefreshesLoginIndex(t *testing.T) {
	h := &sshJournalHost{}
	h.failed(time.Now().Add(-time.Hour), "203.0.113.50")
	t.Cleanup(tools.SetHostSourceForTest(h))
	cfg := &Config{StateDir: t.TempDir()}
	t.Cleanup(tools.SetLoginIndexForTest(cfg.StateDir))
	if err := patrol(context.Background(), cfg, &tools.Env{}, false, true); err != nil && !errors.Is(err, errNoAnswer) {
		t.Logf("patrol: %v", err) // the report's fate is not this test's; the index is
	}
	b, err := os.ReadFile(filepath.Join(cfg.StateDir, tools.LoginIndexFile))
	if err != nil || !strings.Contains(string(b), h.entries[0][0]) || !strings.Contains(string(b), "203.0.113.50") {
		t.Fatalf("the patrol left no index: %s %v", b, err)
	}
	h.mu.Lock()
	patrolReads := len(h.reads)
	h.mu.Unlock()
	if patrolReads == 0 || h.reads[0] != "since" {
		t.Fatalf("the patrol's reads: %q", h.reads)
	}
	h.failed(time.Now().Add(-time.Minute), "203.0.113.50")
	if _, code, err := tools.RemoteBlockCheck(context.Background(), &tools.Env{}, net.ParseIP("203.0.113.50")); code != tools.BlockOK {
		t.Errorf("the check after the patrol: %s %v", code, err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.reads) != patrolReads+1 || h.reads[patrolReads] != "cursor "+h.entries[0][0] {
		t.Errorf("the check's read: %q, want one read after the patrol's cursor", h.reads[patrolReads:])
	}
}

// slowLoginHost is sshJournalHost whose sshd reads are slow, as in a
// flood: a read started before the patrol's report went out waits for it
// (up to 2s), and says so.
type slowLoginHost struct {
	*sshJournalHost
	notified    chan struct{}
	mu          sync.Mutex
	readsBefore int // sshd reads started before the report was sent
}

func (h *slowLoginHost) RunLinesCut(ctx context.Context, argv []string, max int, fn func(string, bool)) (hostenv.CmdResult, error) {
	if strings.Contains(strings.Join(argv, " "), "-u ssh -u sshd -u ssh@* -u sshd@*") {
		select {
		case <-h.notified:
		default:
			h.mu.Lock()
			h.readsBefore++
			h.mu.Unlock()
			select {
			case <-h.notified:
			case <-time.After(2 * time.Second):
			}
		}
	}
	return h.sshJournalHost.RunLinesCut(ctx, argv, max, fn)
}

// S-222-1: the patrol's report does not wait for the login index to catch
// up (up to loginRefreshBudget in a flood): the checks are sent first, and
// the index is read on after them.
func TestPatrolNotifiesBeforeLoginCatchUp(t *testing.T) {
	h := &slowLoginHost{sshJournalHost: &sshJournalHost{}, notified: make(chan struct{})}
	h.failed(time.Now().Add(-time.Hour), "203.0.113.51")
	t.Cleanup(tools.SetHostSourceForTest(h))
	var once sync.Once
	var sent atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hook" {
			http.Error(w, "no model here", http.StatusServiceUnavailable)
			return
		}
		sent.Add(1)
		once.Do(func() { close(h.notified) })
	}))
	t.Cleanup(srv.Close)
	cfg := &Config{StateDir: t.TempDir()}
	cfg.LLM.BaseURL, cfg.LLM.Timeout = srv.URL+"/nomodel", "5s"
	t.Cleanup(tools.SetLoginIndexForTest(cfg.StateDir))
	old := patrolProcesses
	patrolProcesses = func(bool) ([]tools.Proc, error) {
		return []tools.Proc{{PID: 4242, Exe: "/tmp/.x/kworkerds", Cmdline: "/tmp/.x/kworkerds", Flags: []string{"exe_in_tmp"}}}, nil
	}
	t.Cleanup(func() { patrolProcesses = old })
	if err := patrol(context.Background(), cfg, &tools.Env{NotifyURL: srv.URL + "/hook", HTTP: srv.Client()}, false, false); err != nil {
		t.Logf("patrol: %v", err)
	}
	if sent.Load() == 0 {
		t.Fatal("the patrol sent no report")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.readsBefore != 0 {
		t.Errorf("%d sshd reads before the report: the report waited for the login index to catch up", h.readsBefore)
	}
	if len(h.reads) == 0 {
		t.Error("the patrol did not read the login index on after its report")
	}
}
