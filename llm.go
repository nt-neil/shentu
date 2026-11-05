package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nt-nerdtechnic/shentu/tools"
)

// The one LLM adapter: the OpenAI-compatible chat/completions API with tool calling.
// Ollama, OpenAI, OpenRouter, vLLM and Anthropic's OpenAI-compatible endpoint all speak it.

type message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []toolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type toolDef struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type llmClient struct {
	baseURL, model, apiKey string
	http                   *http.Client
}

func newLLM(c *Config) *llmClient {
	return &llmClient{c.LLM.BaseURL, c.LLM.Model, c.apiKey(), &http.Client{Timeout: dur(c.LLM.Timeout)}}
}

func (l *llmClient) chat(ctx context.Context, msgs []message, tools []toolDef) (message, error) {
	if err := checkLocalLLM(l.baseURL); err != nil {
		return message{}, err
	}
	body := map[string]any{"model": l.model, "messages": msgs, "temperature": 0.2}
	if len(tools) > 0 {
		body["tools"] = tools
	}
	b, _ := json.Marshal(body)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		req, err := http.NewRequestWithContext(ctx, "POST", l.baseURL+"/chat/completions", bytes.NewReader(b))
		if err != nil {
			return message{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		if l.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+l.apiKey)
		}
		resp, err := l.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			lastErr = fmt.Errorf("LLM HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
			if resp.StatusCode >= 500 || resp.StatusCode == 429 {
				continue
			}
			return message{}, lastErr
		}
		var r struct {
			Choices []struct {
				Message message `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Choices) == 0 {
			lastErr = fmt.Errorf("unexpected LLM response: %s", truncate(string(raw), 300))
			continue
		}
		return r.Choices[0].Message, nil
	}
	return message{}, lastErr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// checkLocalLLM refuses an endpoint on this machine unless every listener on
// its port is owned by root or the ollama account. Otherwise any local user could
// bind the port first and impersonate the model. It fails closed for loopback
// targets. Linux only (it reads /proc/net/tcp).
func checkLocalLLM(baseURL string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("bad LLM base_url: %w", err)
	}
	if !isLoopbackHost(u.Hostname()) {
		return nil
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = map[string]int{"http": 80, "https": 443}[u.Scheme]
	}
	if port == 0 {
		return fmt.Errorf("cannot tell the port of %s", baseURL)
	}
	allowed := map[string]bool{"0": true}
	if uid, ok := tools.UIDOf("ollama"); ok {
		allowed[uid] = true
	}
	for _, uid := range tools.LoopbackListenerUIDs(port) {
		if !allowed[uid] {
			return fmt.Errorf("refusing the local LLM on port %d: a listener there is owned by uid %s, not root or ollama", port, uid)
		}
	}
	return nil // no listener at all: the request simply fails
}

func isLoopbackHost(host string) bool {
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}
