package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// waitForStart accepts only "/start <code>" from a person in a private chat.
func TestWaitForStart(t *testing.T) {
	var mu sync.Mutex
	served := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasSuffix(r.URL.Path, "/getUpdates") || served {
			w.Write([]byte(`{"ok":true,"result":[]}`))
			return
		}
		served = true
		w.Write([]byte(`{"ok":true,"result":[
			{"update_id":1,"message":{"text":"/start ABCD2345","chat":{"id":-5,"type":"group"},"from":{"username":"g"}}},
			{"update_id":2,"message":{"text":"/start wrong","chat":{"id":6,"type":"private"},"from":{"username":"x"}}},
			{"update_id":3,"message":{"text":"/start ABCD2345","chat":{"id":7,"type":"private"},"from":{"is_bot":true,"username":"b"}}},
			{"update_id":4,"message":{"text":"/start ABCD2345","chat":{"id":8,"type":"private"},"from":{"username":"owner"}}}]}`))
	}))
	defer srv.Close()
	tg := &telegramClient{api: srv.URL, token: "1:T", hc: srv.Client()}
	for text, want := range map[string]bool{"ABCD2345": true, "abcd-2345": true, " /start ABCD2345": true, "abcd 2345": true, "ABCD234": false, "/start": false} {
		if codeMatches(text, "ABCD2345") != want {
			t.Errorf("codeMatches(%q) != %v", text, want)
		}
	}
	chat, who, err := waitForStart(context.Background(), tg, "ABCD2345", 5*time.Second)
	if err != nil || chat != 8 || who != "@owner" {
		t.Errorf("waitForStart = %d %q %v, want 8 @owner", chat, who, err)
	}
	if _, _, err := waitForStart(context.Background(), tg, "ABCD2345", 1500*time.Millisecond); err == nil {
		t.Errorf("no matching /start must time out")
	}
}

// setup.toml overrides shentu.toml, and the notify URL itself stays in env.
func TestSetupTomlOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHENTU_CONFIG", filepath.Join(dir, "shentu.toml"))
	os.WriteFile(filepath.Join(dir, "shentu.toml"), []byte("language = \"English\"\n[notify]\nurl = \"\"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "env"), []byte("NOTIFY_URL=ntfy://ntfy.sh/x\n"), 0o600)
	os.Unsetenv("NOTIFY_URL")
	t.Cleanup(func() { os.Unsetenv("NOTIFY_URL") })
	if err := writeSetup("繁體中文", true, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "setup.toml"))
	if strings.Contains(string(b), "ntfy.sh") {
		t.Errorf("the notify URL was written to setup.toml instead of the env file")
	}
	cfg, err := loadConfig(configPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Language != "繁體中文" || cfg.Notify.URL != "ntfy://ntfy.sh/x" {
		t.Errorf("language %q, notify %q", cfg.Language, cfg.Notify.URL)
	}
}
