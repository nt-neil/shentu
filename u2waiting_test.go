package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func lastText(tg *fakeTelegram) string {
	s := tg.sent()
	if len(s) == 0 {
		return ""
	}
	t, _ := s[len(s)-1]["text"].(string)
	return t
}

// U2: a message while a confirmation waits for its button is told to
// answer the confirmation first, not "Still working"; the confirmation is
// not sent again.
func TestBotMessageWhileConfirming(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("block_ip is not offered on Windows")
	}
	stubGate(t, nil)
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, tg := levelBot(t, model, [4]int{3, 2, 3, 2})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block 203.0.113.9"))
	waitFor(t, "the confirmation", func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return len(b.waiting) > 0
	})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "and 203.0.113.10?"))
	if got := lastText(tg); got != b.t("busy_confirm") {
		t.Errorf("reply while confirming: %q", got)
	}
	prompts := 0
	for _, s := range tg.sent() {
		if text, _ := s["text"].(string); strings.Contains(text, "nft add element") {
			prompts++
		}
	}
	if prompts != 1 {
		t.Errorf("%d confirmation prompts sent", prompts)
	}
	confirmPress(t, b, tg, false)
	answered(t, b)
}

// U2: a proposal button pressed while a confirmation waits gets the same
// word, and stays for later.
func TestProposalPressWhileConfirming(t *testing.T) {
	b, tg, _, g, data := offerOne(t, propRec(proposalRecord{IP: "203.0.113.1"}))
	b.mu.Lock()
	b.busy = true
	b.waiting["pending"] = make(chan bool, 1)
	b.mu.Unlock()
	b.handle(context.Background(), press(pairedUser, data[0]))
	if got := lastText(tg); got != b.t("busy_press") { // S-U2-2: the button stays, press it later
		t.Errorf("reply: %q", got)
	}
	if r := g.runs(); len(r) != 0 {
		t.Errorf("runs: %v", r)
	}
	b.mu.Lock()
	b.busy = false // as the answer that held it would, at its end
	delete(b.waiting, "pending")
	b.mu.Unlock()
}
