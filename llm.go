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
	"strings"
	"time"

	"github.com/nt-neil/shentu/tools"
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
	maxTokens              int
	http                   *http.Client
	usedIn, usedOut        int // tokens used by the last call, for the audit log
}

func newLLM(c *Config) *llmClient {
	// Every connection goes through localDialer, which checks the owner of the listener
	// whenever the address it actually connected to is on this machine.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = localDialer
	if u, err := url.Parse(c.LLM.BaseURL); err == nil && isLoopbackHost(u.Hostname()) {
		tr.Proxy = nil
	}
	hc := &http.Client{Timeout: dur(c.LLM.Timeout), Transport: tr}
	return &llmClient{baseURL: c.LLM.BaseURL, model: c.LLM.Model, apiKey: c.apiKey(), maxTokens: c.LLM.MaxTokens, http: hc}
}

func (l *llmClient) chat(ctx context.Context, msgs []message, tools []toolDef) (message, error) {
	// max_tokens bounds the cost of each call; some providers require it.
	body := map[string]any{"model": l.model, "messages": msgs, "temperature": 0.2, "max_tokens": l.maxTokens}
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
			Usage struct {
				In  int `json:"prompt_tokens"`
				Out int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Choices) == 0 {
			lastErr = fmt.Errorf("unexpected LLM response: %s", truncate(string(raw), 300))
			continue
		}
		l.usedIn, l.usedOut = r.Usage.In, r.Usage.Out
		return r.Choices[0].Message, nil
	}
	return message{}, lastErr
}

func truncate(s string, n int) string {
	return tools.Cut(s, n)
}

// localDialer is used for every LLM connection. When the connected address is on
// this machine (loopback or one of its own addresses, whatever the host name said),
// it looks up who owns the server side of that exact connection and hangs up unless
// it is root or the ollama account. Otherwise any local user could bind the port while
// Ollama is down and impersonate the model. Checking the connected socket itself
// leaves no gap between check and use.
func localDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	if err != nil || runtime.GOOS != "linux" {
		return conn, err
	}
	local, _ := conn.LocalAddr().(*net.TCPAddr)
	remote, _ := conn.RemoteAddr().(*net.TCPAddr)
	if local == nil || remote == nil {
		conn.Close()
		return nil, fmt.Errorf("local LLM: not a TCP connection")
	}
	if !isLocalIP(remote.IP) {
		return conn, nil
	}
	uid, found := tools.PeerUID(local, remote)
	allowed := uid == "0"
	if ou, ok := tools.UIDOf("ollama"); ok && uid == ou {
		allowed = true
	}
	if !found || !allowed {
		conn.Close()
		return nil, fmt.Errorf("refusing the local LLM at %s: its listener is owned by uid %q, not root or ollama", addr, uid)
	}
	return conn, nil
}

func isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
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
