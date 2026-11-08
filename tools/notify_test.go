package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type capture struct {
	paths  []string
	bodies []map[string]any
	hdrs   []http.Header
	raw    []string
}

func recorder(t *testing.T, c *capture, status func(n int) int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		c.paths, c.bodies, c.hdrs, c.raw = append(c.paths, r.URL.Path), append(c.bodies, m), append(c.hdrs, r.Header), append(c.raw, string(b))
		if status != nil {
			if s := status(len(c.paths)); s == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(s)
				return
			} else if s != 0 {
				w.WriteHeader(s)
				return
			}
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestChannelKind(t *testing.T) {
	for raw, want := range map[string]string{
		"https://hooks.slack.com/services/T0/B0/XYZ": "slack",
		"https://discord.com/api/webhooks/1/abc":     "discord",
		"https://discordapp.com/api/webhooks/1/abc":  "discord",
		"https://discord.com/other":                  "https",
		"http://hooks.slack.com/services/x":          "http",
		"https://example.com/hook":                   "https",
		"telegram://123:abc@telegram?chats=1":        "telegram",
		"ntfy://ntfy.sh/topic":                       "ntfy",
	} {
		u, _ := url.Parse(raw)
		if got := channelKind(u); got != want {
			t.Errorf("channelKind(%s) = %s, want %s", raw, got, want)
		}
	}
}

func TestNotifySlack(t *testing.T) {
	var c capture
	srv := recorder(t, &c, nil)
	u, _ := url.Parse(srv.URL + "/services/T/B/secret")
	if err := deliver(context.Background(), srv.Client(), "slack", u, "t", "a <b> & c", "warning"); err != nil {
		t.Fatal(err)
	}
	if len(c.bodies) != 1 || !strings.Contains(c.bodies[0]["text"].(string), "a &lt;b&gt; &amp; c") {
		t.Errorf("slack body = %v", c.bodies)
	}
}

func TestNotifyDiscordChunksAndMentions(t *testing.T) {
	var c capture
	srv := recorder(t, &c, nil)
	u, _ := url.Parse(srv.URL + "/api/webhooks/1/secret")
	msg := strings.Repeat("line of text @everyone\n", 200) // about 4600 characters
	if err := deliver(context.Background(), srv.Client(), "discord", u, "t", msg, "info"); err != nil {
		t.Fatal(err)
	}
	if len(c.bodies) != 3 {
		t.Fatalf("discord posts = %d, want 3", len(c.bodies))
	}
	for _, b := range c.bodies {
		if n := len([]rune(b["content"].(string))); n > 2000 {
			t.Errorf("discord chunk too long: %d", n)
		}
		if am, _ := b["allowed_mentions"].(map[string]any); am == nil || len(am["parse"].([]any)) != 0 {
			t.Errorf("allowed_mentions missing: %v", b)
		}
	}
}

func TestNotifyTelegramChats(t *testing.T) {
	var c capture
	srv := recorder(t, &c, nil)
	old := telegramAPI
	telegramAPI = srv.URL
	defer func() { telegramAPI = old }()
	u, _ := url.Parse("telegram://123:TOKEN@telegram?chats=11,22")
	if err := deliver(context.Background(), srv.Client(), "telegram", u, "t", "m", "critical"); err != nil {
		t.Fatal(err)
	}
	if len(c.paths) != 2 || c.paths[0] != "/bot123:TOKEN/sendMessage" || c.bodies[1]["chat_id"] != "22" {
		t.Errorf("telegram requests = %v %v", c.paths, c.bodies)
	}
}

func TestNotifyRetriesOnce429(t *testing.T) {
	var c capture
	srv := recorder(t, &c, func(n int) int {
		if n == 1 {
			return http.StatusTooManyRequests
		}
		return 0
	})
	u, _ := url.Parse(srv.URL + "/api/webhooks/1/secret")
	if err := deliver(context.Background(), srv.Client(), "discord", u, "t", "m", "info"); err != nil || len(c.paths) != 2 {
		t.Errorf("err=%v posts=%d, want nil and 2", err, len(c.paths))
	}
	c = capture{}
	srv2 := recorder(t, &c, func(int) int { return http.StatusInternalServerError })
	u2, _ := url.Parse(srv2.URL + "/hook")
	if err := deliver(context.Background(), srv2.Client(), "http", u2, "t", "m", "info"); err == nil || len(c.paths) != 1 {
		t.Errorf("500 must fail without retry: err=%v posts=%d", err, len(c.paths))
	}
}

func TestNotifyWebhookSigned(t *testing.T) {
	var c capture
	srv := recorder(t, &c, nil)
	t.Setenv("SHENTU_WEBHOOK_SECRET", "s3")
	u, _ := url.Parse(srv.URL + "/hook")
	if err := deliver(context.Background(), srv.Client(), "http", u, "t", "m", "info"); err != nil {
		t.Fatal(err)
	}
	if c.bodies[0]["title"] != "t" || !strings.HasPrefix(c.hdrs[0].Get("X-Shentu-Signature"), "sha256=") {
		t.Errorf("webhook = %v %v", c.bodies[0], c.hdrs[0])
	}
}

func TestNotifyErrorHidesSecret(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // connection refused
	u, _ := url.Parse(srv.URL + "/api/webhooks/1/topsecret")
	err := deliver(context.Background(), http.DefaultClient, "discord", u, "t", "m", "info")
	if err == nil || strings.Contains(err.Error(), "topsecret") {
		t.Errorf("error leaks the webhook path: %v", err)
	}
}

func TestChunks(t *testing.T) {
	if got := Chunks("short", 10); len(got) != 1 || got[0] != "short" {
		t.Errorf("chunks short = %q", got)
	}
	s := strings.Repeat("中", 25)
	got := Chunks(s, 10)
	if len(got) != 3 || strings.Join(got, "") != s {
		t.Errorf("chunks CJK = %q", got)
	}
	got = Chunks("aaaaaaa\nbbbbbbbbbb", 10)
	if got[0] != "aaaaaaa\n" {
		t.Errorf("chunks should break at newline: %q", got)
	}
}
