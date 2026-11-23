package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/tools"
)

// sshJournalHost is a Linux host where nothing can be read but journald's
// sshd units, which it answers as journalctl does (-o json, --since,
// --after-cursor), keeping each read's start.
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
		case "--after-cursor":
			h.reads = append(h.reads, "after "+argv[i+1])
			from = -1
			for n, e := range h.entries {
				if e[0] == argv[i+1] {
					from = n + 1
				}
			}
			if from < 0 {
				return hostenv.CmdResult{ExitCode: 1, Stderr: "Failed to seek to cursor\n"}, nil
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
	if len(h.reads) != patrolReads+1 || h.reads[patrolReads] != "after "+h.entries[0][0] {
		t.Errorf("the check's read: %q, want one read after the patrol's cursor", h.reads[patrolReads:])
	}
}
