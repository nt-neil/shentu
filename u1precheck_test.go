package main

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/tools"
)

// U1: from Telegram, an address the gate refuses is refused before the
// operator is asked: no ✅, the gate's reason to the model and the log.
func TestBotBlockRefusedBeforeConfirm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("block_ip is not offered on Windows")
	}
	stubGate(t, map[string]tools.BlockCode{"203.0.113.9": tools.BlockUnverified})
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, tg := levelBot(t, model, [4]int{3, 2, 3, 2})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block 203.0.113.9"))
	e := blockDecision(t, b)
	if e == nil || e.Confirmed || e.OK || !strings.Contains(e.Error, "unverified") {
		t.Errorf("block_ip entry: %+v", e)
	}
	for _, s := range tg.sent() {
		if rm, ok := s["reply_markup"]; ok && strings.Contains(s["text"].(string), "203.0.113.9") {
			t.Errorf("the operator was asked about an address the gate refuses: %v %v", s["text"], rm)
		}
	}
	model.mu.Lock()
	last := model.requests[len(model.requests)-1]
	model.mu.Unlock()
	if !strings.Contains(last, "unverified") {
		t.Error("the model was not told why")
	}
}

// U1: an address the gate allows is still asked about, and its press decides.
func TestBotBlockAllowedStillAsks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("block_ip is not offered on Windows")
	}
	stubGate(t, nil)
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, tg := levelBot(t, model, [4]int{3, 2, 3, 2})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block 203.0.113.9"))
	confirmPress(t, b, tg, false)
	if e := blockDecision(t, b); e == nil || e.Confirmed || e.Error != "declined by operator" {
		t.Errorf("block_ip entry: %+v", e)
	}
}

// U1 is for block_ip from a chat channel only: shentu chat and other tools
// keep their flow.
func TestRemotePrecheckScope(t *testing.T) {
	stubGate(t, map[string]tools.BlockCode{"203.0.113.9": tools.BlockUnverified})
	args := json.RawMessage(`{"ip":"203.0.113.9"}`)
	if _, err := remotePrecheck(context.Background(), &tools.Env{Remote: false}, "block_ip", args); err != nil {
		t.Errorf("shentu chat: %v", err)
	}
	if _, err := remotePrecheck(context.Background(), &tools.Env{Remote: true}, "unblock_ip", args); err != nil {
		t.Errorf("unblock_ip: %v", err)
	}
	if _, err := remotePrecheck(context.Background(), &tools.Env{Remote: true}, "block_ip", args); err == nil {
		t.Error("Telegram block_ip was not prechecked")
	}
}
