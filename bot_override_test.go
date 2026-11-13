package main

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// From Telegram, block_ip with override_unverified is refused at every
// confirm level, "none" too, before anything is shown or run: only the
// server's own shentu chat may override the login gate.
func TestBotCannotOverrideLoginGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no control tool runs on Windows (block_ip refuses there)")
	}
	for _, level := range []int{1, 2, 3, 4} {
		model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.77","reason":"x","override_unverified":true}`), done}}
		b, tg := testBot(t, model, true)
		b.cfg.Bot.Interaction, b.cfg.Bot.Confirm = 4, level
		pairDirectly(t, b)
		b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block 203.0.113.77, I checked"))
		var got *logEntry
		for i := 0; i < 150 && got == nil; i++ {
			for _, e := range auditLines(t, b.cfg.StateDir) {
				if e.Tool == "block_ip" {
					e := e
					got = &e
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if got == nil || got.Confirmed || got.OK || !strings.Contains(got.Error, "not accepted from a chat channel") {
			t.Errorf("confirm level %d: %+v", level, got)
		}
		for _, s := range tg.sent() {
			if _, ok := s["reply_markup"]; ok {
				t.Errorf("confirm level %d: a confirmation was asked for", level)
			}
		}
	}
}

// The tool refuses it too, whoever calls it with a remote env; the server's
// own env may override.
func TestBlockIPRemoteOverrideRefused(t *testing.T) {
	args := json.RawMessage(`{"ip":"203.0.113.77","reason":"x","override_unverified":true}`)
	tool, ok := tools.Find("block_ip")
	if !ok || runtime.GOOS == "windows" {
		t.Skip("block_ip is not offered on Windows")
	}
	if _, err := tool.Run(context.Background(), &tools.Env{Remote: true}, args); err == nil || !strings.Contains(err.Error(), "not accepted from a chat channel") {
		t.Errorf("remote override ran: %v", err)
	}
	if err := tools.RemoteRefused(&tools.Env{}, "block_ip", args); err != nil {
		t.Errorf("server override refused: %v", err)
	}
	if err := tools.RemoteRefused(&tools.Env{Remote: true}, "block_ip", json.RawMessage(`{"ip":"203.0.113.77","reason":"x"}`)); err != nil {
		t.Errorf("remote without override refused: %v", err)
	}
}
