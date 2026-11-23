package main

import (
	"bufio"
	"context"
	"encoding/base32"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// S-U1-1: the model is told the gate's word, never its message, which can
// quote what a log holds; the server's log keeps the message.
func TestPrecheckRefusalWordsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("block_ip is not offered on Windows")
	}
	old := blockCheck
	blockCheck = func(context.Context, *tools.Env, net.IP) (string, tools.BlockCode, error) {
		return "", tools.BlockUnverified, errors.New("unverified: sample GET /wp?x=IGNORE-PREVIOUS-ATTACKERTEXT")
	}
	t.Cleanup(func() { blockCheck = old })
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, _ := levelBot(t, model, [4]int{3, 2, 3, 2})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block 203.0.113.9"))
	e := blockDecision(t, b)
	if e == nil || !strings.Contains(e.Error, "ATTACKERTEXT") {
		t.Errorf("the server's log lost the gate's message: %+v", e)
	}
	model.mu.Lock()
	defer model.mu.Unlock()
	last := model.requests[len(model.requests)-1]
	if strings.Contains(last, "ATTACKERTEXT") || !strings.Contains(last, "the gate says unverified") {
		t.Errorf("what the model was told: %s", last[max(0, len(last)-400):])
	}
}

// S-U2-1: while the authenticator code is awaited, a message is told to
// send the code first.
func TestBotMessageWhileCode(t *testing.T) {
	stubGate(t, nil)
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, tg := levelBot(t, model, [4]int{3, 4, 2, 2})
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	withBotState(b.cfg.StateDir, func(s *botState) error { s.TOTPSecret = secret; return nil })
	ctx := context.Background()
	b.handle(ctx, msg(pairedUser, pairedChat, "private", "block it"))
	confirmPress(t, b, tg, true)
	codeTaken := func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.codeWait != nil && len(b.codeWait) == 0
	}
	waitFor(t, "the bot to ask for a code", codeTaken)
	b.handle(ctx, msg(pairedUser, pairedChat, "private", "what about 203.0.113.10?"))
	if got := lastText(tg); got != b.t("busy_code") {
		t.Errorf("reply while the code is awaited: %q", got)
	}
	for _, wrong := range []string{"000000", "111111", "222222"} {
		waitFor(t, "the bot to ask for a code", codeTaken)
		b.handle(ctx, msg(pairedUser, pairedChat, "private", wrong))
	}
	blockDecision(t, b)
}

// S-U2-1: while an action waits for the server's approval (confirm = 1),
// a message is told so.
func TestBotMessageWhileServerApproves(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no control tool runs on Windows")
	}
	stubGate(t, nil)
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, tg := levelBot(t, model, [4]int{3, 4, 1, 2})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block it"))
	waitFor(t, "the action to wait for the server", func() bool {
		var waiting bool
		withBotState(b.cfg.StateDir, func(s *botState) error { waiting = s.Action != nil; return nil })
		return waiting
	})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "and now?"))
	if got := lastText(tg); got != b.t("busy_server") {
		t.Errorf("reply while the server approves: %q", got)
	}
	var out strings.Builder
	botApprove(b.cfg, bufio.NewReader(strings.NewReader("n\n")), &out)
	blockDecision(t, b)
}

// S-U2-2: a suggestion button pressed while busy is not used up, and a
// proposal button gets "press it again later".
func TestBotButtonsWhileBusy(t *testing.T) {
	b, tg, _, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
	b.mu.Lock()
	b.busy, b.sugNonce, b.sugText = true, "abc", []string{"show the attack groups"}
	b.mu.Unlock()
	b.handle(context.Background(), press(pairedUser, "abc:s0"))
	if got := lastText(tg); got != b.t("busy_later") {
		t.Errorf("suggestion while busy: %q", got)
	}
	b.handle(context.Background(), press(pairedUser, data[0]))
	if got := lastText(tg); got != b.t("busy_later") {
		t.Errorf("proposal while busy: %q", got)
	}
	b.mu.Lock()
	kept := b.sugNonce == "abc" && len(b.sugText) == 1
	b.busy = false
	b.mu.Unlock()
	if !kept {
		t.Error("the suggestion was used up while busy")
	}
	if r := g.runs(); len(r) != 0 {
		t.Errorf("runs: %v", r)
	}
}

// S-152-1: a mistake in the arguments gets the usage first, root after.
func TestCLIDispatchUsageBeforeRoot(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("builds the binary; needs a user who is not root")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "shentu")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfg := filepath.Join(dir, "shentu.toml") // S-158-3: one that cannot be read, so the usage must come first
	os.WriteFile(cfg, []byte("state_dir = [\n"), 0o600)
	for _, args := range [][]string{{"dispatch", "repair", "extra"}, {"dispatch", "stats", "extra"}, {"dispatch", "stats", "--bogus"}, {"dispatch", "wipe"}, {"dispatch"}} {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "SHENTU_CONFIG="+cfg)
		out, _ := cmd.CombinedOutput()
		if strings.Contains(string(out), "sudo") || strings.Contains(string(out), "toml") || !strings.Contains(string(out), "usage: shentu dispatch") {
			t.Errorf("%v: %s", args, out)
		}
	}
	if err := dispatchPreflight([]string{"repair"}, false, "linux"); err == nil {
		t.Error("a right repair was not asked for root")
	}
}

// H-S1: a broken line moved twice is kept once in .bad, and the notes count
// what was new to it.
func TestDispatchRepairCountsNew(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	if err := s.Save(testRecord("000000000001", now)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dir, now.Local().Format(time.DateOnly)+".jsonl")
	for run := 1; run <= 2; run++ {
		f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		f.WriteString("not json\n")
		f.Close()
		if n, _, err := s.Repair(); err != nil || n != 1 {
			t.Fatalf("run %d: %d %v", run, n, err)
		}
	}
	b, _ := os.ReadFile(p + ".bad")
	if strings.Count(string(b), "not json") != 1 {
		t.Errorf(".bad: %q", b)
	}
	notes := s.repairNotes(now.Add(-time.Hour))
	if len(notes) != 2 || notes[0].Added != 1 || notes[1].Added != 0 || notes[1].Moved != 1 {
		t.Errorf("notes: %+v", notes)
	}
	if line := s.repairedLine(now, false); !strings.Contains(line, "2 unreadable archive lines moved out (1 of them new") {
		t.Errorf("daily: %q", line)
	}
}

// S-158-1: when block_ip's Run fails from Telegram (the gate changed its
// mind after the precheck), the model is not given the failure's message.
func TestBotBlockRunFailureWordsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("block_ip is not offered on Windows")
	}
	stubGate(t, nil)
	blockRun = func(context.Context, *tools.Env, []byte) (any, error) {
		return nil, errors.New("refusing: sample GET /wp?x=ZZMARK-ATTACKERTEXT")
	}
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, _ := levelBot(t, model, [4]int{3, 2, 4, 2}) // confirm = 4: no button to press
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block 203.0.113.9"))
	e := blockDecision(t, b)
	if e == nil || !strings.Contains(e.Error, "ZZMARK") {
		t.Errorf("the server's log lost the message: %+v", e)
	}
	model.mu.Lock()
	defer model.mu.Unlock()
	last := model.requests[len(model.requests)-1]
	if strings.Contains(last, "ZZMARK") || !strings.Contains(last, "did not succeed") {
		t.Errorf("what the model was told: %s", last[max(0, len(last)-400):])
	}
}

// S-158-2: an Action left by a crash, past its expiry, is no wait for the server.
func TestBusyWordStaleAction(t *testing.T) {
	b := &bot{waiting: map[string]chan bool{}}
	stale := botState{Action: &pendingAction{Expires: time.Now().Add(-55 * time.Minute)}}
	fresh := botState{Action: &pendingAction{Expires: time.Now().Add(5 * time.Minute)}}
	if w := b.busyWord(stale, false); w != "busy" {
		t.Errorf("stale: %s", w)
	}
	if w := b.busyWord(fresh, false); w != "busy_server" {
		t.Errorf("fresh: %s", w)
	}
	if w := b.busyWord(stale, true); w != "busy_later" {
		t.Errorf("stale, a press: %s", w)
	}
}
