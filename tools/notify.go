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
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var notifyTool = Tool{
	Name:        "notify",
	Description: "Send a message to the operator's configured channel (Telegram, Slack, Discord, ntfy or webhook).",
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

// telegramAPI is replaced in tests.
var telegramAPI = "https://api.telegram.org"

// Notify sends one message. The URL forms are:
//
//	telegram://<bot-token>@telegram?chats=<id>[,<id>]
//	ntfy://<host>/<topic>[?token=<token>]
//	https://hooks.slack.com/services/...   (Slack incoming webhook)
//	https://discord.com/api/webhooks/...   (Discord webhook)
//	https://<webhook>   (JSON, signed with SHENTU_WEBHOOK_SECRET when set)
func Notify(ctx context.Context, env *Env, title, message, severity string) error {
	if env.NotifyURL == "" {
		return errors.New("no notify url configured")
	}
	if severity == "" {
		severity = "info"
	}
	u, err := url.Parse(env.NotifyURL)
	if err != nil {
		return errors.New("bad notify url")
	}
	return deliver(ctx, env.HTTP, channelKind(u), u, title, message, severity)
}

func channelKind(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	switch {
	case u.Scheme == "https" && host == "hooks.slack.com":
		return "slack"
	case u.Scheme == "https" && (host == "discord.com" || host == "discordapp.com") && strings.HasPrefix(u.Path, "/api/webhooks/"):
		return "discord"
	}
	return u.Scheme
}

func deliver(ctx context.Context, hc *http.Client, kind string, u *url.URL, title, message, severity string) error {
	host, _ := os.Hostname()
	text := fmt.Sprintf("%s [%s] %s\n\n%s", icon(severity), host, title, message)
	switch kind {
	case "telegram":
		// A bot token is "<id>:<secret>", which url.Parse splits into user and password.
		token := u.User.Username()
		if pw, ok := u.User.Password(); ok {
			token += ":" + pw
		}
		for _, chat := range strings.Split(u.Query().Get("chats"), ",") {
			for _, part := range Chunks(text, 4000) {
				b, _ := json.Marshal(map[string]any{"chat_id": strings.TrimSpace(chat), "text": part, "disable_web_page_preview": true})
				if err := post(ctx, hc, telegramAPI+"/bot"+token+"/sendMessage", b, nil); err != nil {
					return errors.New(strings.ReplaceAll(err.Error(), token, "***"))
				}
			}
		}
		return nil
	case "slack":
		for _, part := range Chunks(text, 3000) {
			b, _ := json.Marshal(map[string]any{"text": slackEscape(part)})
			if err := post(ctx, hc, u.String(), b, nil); err != nil {
				return err
			}
		}
		return nil
	case "discord":
		for _, part := range Chunks(text, 1900) {
			// parse: [] stops @everyone, @here and role mentions copied from logs.
			b, _ := json.Marshal(map[string]any{"content": part, "allowed_mentions": map[string]any{"parse": []string{}}})
			if err := post(ctx, hc, u.String(), b, nil); err != nil {
				return err
			}
		}
		return nil
	case "ntfy":
		q := u.Query()
		hdr := map[string]string{
			"Content-Type": "text/plain; charset=utf-8",
			"Title":        "[" + host + "] " + title,
			"Priority":     map[string]string{"info": "3", "warning": "4", "critical": "5"}[severity],
		}
		if t := q.Get("token"); t != "" {
			hdr["Authorization"] = "Bearer " + t
		}
		return post(ctx, hc, "https://"+u.Host+u.Path, []byte(message), hdr)
	case "http", "https":
		b, _ := json.Marshal(map[string]any{"host": host, "title": title, "message": message, "severity": severity, "time": time.Now().UTC()})
		var hdr map[string]string
		if secret := os.Getenv("SHENTU_WEBHOOK_SECRET"); secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(b)
			hdr = map[string]string{"X-Shentu-Signature": "sha256=" + hex.EncodeToString(mac.Sum(nil))}
		}
		return post(ctx, hc, u.String(), b, hdr)
	}
	return errors.New("unsupported notify url scheme: " + kind)
}

// post sends body (JSON unless hdr sets Content-Type). On HTTP 429 it waits for
// Retry-After (at most 30s) and tries once more; nothing else is retried, because
// a repeated send would duplicate the message. Errors never include the URL path,
// which holds the webhook secret.
func post(ctx context.Context, hc *http.Client, target string, body []byte, hdr map[string]string) error {
	host := target
	if u, err := url.Parse(target); err == nil {
		host = u.Host
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(body))
		if err != nil {
			return errors.New("bad notify url")
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := hc.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			return fmt.Errorf("%s: %v", host, err)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			wait, _ := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64)
			select {
			case <-time.After(time.Duration(min(max(wait, 1), 30) * float64(time.Second))):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("%s: HTTP %d", host, resp.StatusCode)
		}
		return nil
	}
}

// Chunks splits s into pieces of at most n runes, preferring to break at a newline.
func Chunks(s string, n int) []string {
	var out []string
	for {
		r := []rune(s)
		if len(r) <= n {
			return append(out, s)
		}
		cut := n
		if i := strings.LastIndex(string(r[:n]), "\n"); i > 0 && utf8.RuneCountInString(string(r[:n])[:i]) > n/2 {
			cut = utf8.RuneCountInString(string(r[:n])[:i]) + 1
		}
		out = append(out, string(r[:cut]))
		s = string(r[cut:])
	}
}

// slackEscape escapes the three characters Slack treats as markup.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
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
