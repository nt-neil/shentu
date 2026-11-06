package tools

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var notifyTool = Tool{
	Name:        "notify",
	Description: "Send a message to the operator's configured channel (Telegram, ntfy or webhook).",
	Params: schema(`{"type":"object","required":["title","message"],"properties":{
		"title":{"type":"string"},
		"message":{"type":"string"},
		"severity":{"type":"string","enum":["info","warning","critical"]}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct{ Title, Message, Severity string }
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		if err := Notify(ctx, env, a.Title, a.Message, a.Severity); err != nil {
			return nil, err
		}
		return map[string]any{"sent": true}, nil
	},
}

// Notify sends one message. The URL forms are:
//
//	telegram://<bot-token>@telegram?chats=<id>[,<id>]
//	ntfy://<host>/<topic>[?token=<token>]
//	https://<webhook>   (signed with SHENTU_WEBHOOK_SECRET when set)
func Notify(ctx context.Context, env *Env, title, message, severity string) error {
	if env.NotifyURL == "" {
		return errors.New("no notify url configured")
	}
	if severity == "" {
		severity = "info"
	}
	host, _ := os.Hostname()
	u, err := url.Parse(env.NotifyURL)
	if err != nil {
		return fmt.Errorf("bad notify url: %w", err)
	}
	switch u.Scheme {
	case "telegram":
		token := u.User.Username()
		text := fmt.Sprintf("%s [%s] %s\n\n%s", icon(severity), host, title, message)
		if len(text) > 4000 {
			text = Cut(text, 4000)
		}
		for _, chat := range strings.Split(u.Query().Get("chats"), ",") {
			body := map[string]any{"chat_id": strings.TrimSpace(chat), "text": text, "disable_web_page_preview": true}
			if err := postJSON(ctx, env.HTTP, "https://api.telegram.org/bot"+token+"/sendMessage", body, nil); err != nil {
				return errors.New(strings.ReplaceAll(err.Error(), token, "***"))
			}
		}
		return nil
	case "ntfy":
		q := u.Query()
		target := "https://" + u.Host + u.Path
		req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(message))
		if err != nil {
			return err
		}
		req.Header.Set("Title", "["+host+"] "+title)
		req.Header.Set("Priority", map[string]string{"info": "3", "warning": "4", "critical": "5"}[severity])
		if t := q.Get("token"); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
		return doJSON(env.HTTP, req, nil)
	case "http", "https":
		b, _ := json.Marshal(map[string]any{"host": host, "title": title, "message": message, "severity": severity, "time": time.Now().UTC()})
		req, err := http.NewRequestWithContext(ctx, "POST", env.NotifyURL, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if secret := os.Getenv("SHENTU_WEBHOOK_SECRET"); secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(b)
			req.Header.Set("X-Shentu-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		return doJSON(env.HTTP, req, nil)
	}
	return errors.New("unsupported notify url scheme: " + u.Scheme)
}

func icon(sev string) string {
	switch sev {
	case "critical":
		return "🚨"
	case "warning":
		return "⚠️"
	}
	return "ℹ️"
}
