package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	usedIn, usedOut        int     // tokens used by the last call, for the audit log
	usedReason             int     // reasoning tokens, when the provider reports them
	usedCost               float64 // what the provider charged, when it says
	opaqueErrors           bool    // keep no part of an error answer (a model outside this host, for sub-agents)
}

func newLLM(c *Config) *llmClient {
	// Every connection goes through localDialer, which checks the owner of the listener
	// whenever the address it actually connected to is on this machine.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = llmDial
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
			if l.opaqueErrors { // url.Error quotes the URL, which may hold a secret
				err = opaqueDoError(ctx, err)
			}
			lastErr = err
			if ctx.Err() != nil { // cancelled or past its deadline: a retry cannot help
				return message{}, err
			}
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			// A refused key is the answer most likely to quote the key back, in
			// whatever encoding: none of it is kept.
			return message{}, fmt.Errorf("LLM HTTP %d: the provider refused the request (check the API key; its answer is not shown)", resp.StatusCode)
		}
		if resp.StatusCode/100 != 2 && l.opaqueErrors {
			// Its answer could quote the key in any encoding: none of it is kept.
			lastErr = fmt.Errorf("LLM HTTP %d: the model outside this host answered with an error (its answer is not shown)", resp.StatusCode)
			if resp.StatusCode >= 500 || resp.StatusCode == 429 {
				continue
			}
			return message{}, lastErr
		}
		if resp.StatusCode/100 != 2 {
			lastErr = fmt.Errorf("LLM HTTP %d: %s", resp.StatusCode, l.scrub(string(raw), 300))
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
				In      int `json:"prompt_tokens"`
				Out     int `json:"completion_tokens"`
				Details struct {
					Reasoning int `json:"reasoning_tokens"`
				} `json:"completion_tokens_details"`
			} `json:"usage"`
			Charged float64 `json:"price_charged"` // AppleToken reports what the call cost
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Choices) == 0 {
			lastErr = fmt.Errorf("unexpected LLM response: %s", l.scrub(string(raw), 300))
			if l.opaqueErrors {
				lastErr = errors.New("unexpected LLM response from the model outside this host (not shown)")
			}
			continue
		}
		l.usedIn, l.usedOut, l.usedReason, l.usedCost = r.Usage.In, r.Usage.Out, r.Usage.Details.Reasoning, r.Charged
		return r.Choices[0].Message, nil
	}
	return message{}, lastErr
}

// scrub is a provider's answer for an error message, at most n bytes: the
// key replaced by [key] first, wherever it is (some gateways echo the
// Authorization header back in a 401), then cut, so a cut never leaves part
// of a key behind. Errors go to log.jsonl and, through a sub-agent's
// report, to the commander's model, which may be another provider's.
func (l *llmClient) scrub(s string, n int) string {
	if l.apiKey != "" {
		for _, form := range keyForms(l.apiKey) {
			s = strings.ReplaceAll(s, form, "[key]")
		}
	}
	return truncate(s, n)
}

// opaqueDoError is a failed request to a model outside this host as a
// kind of failure only: no URL, no address, no text the far end chose.
func opaqueDoError(ctx context.Context, err error) error {
	kind := "connection failed"
	var nerr net.Error
	var dnsErr *net.DNSError
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("LLM request to the model outside this host: %w", ctx.Err())
	case errors.As(err, &dnsErr):
		kind = "name lookup failed"
	case connRefused(err):
		kind = "connection refused"
	case errors.As(err, &nerr) && nerr.Timeout():
		kind = "timeout"
	case strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:"):
		kind = "TLS failed"
	}
	return errors.New("LLM request to the model outside this host: " + kind)
}

// keyForms are the ways an answer can quote key: as is, escaped for a URL
// query or path, and escaped in JSON (a slash as \/, and Go's own escapes).
func keyForms(key string) []string {
	j, _ := json.Marshal(key)
	forms := []string{key, url.QueryEscape(key), url.PathEscape(key),
		strings.ReplaceAll(key, "/", `\/`), strings.Trim(string(j), `"`),
		strings.ReplaceAll(strings.Trim(string(j), `"`), "/", `\/`)}
	seen := map[string]bool{}
	var out []string
	for _, f := range forms {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func truncate(s string, n int) string {
	return tools.Cut(s, n)
}

// llmDial is localDialer; tests swap it to reach a fake model on a loopback port.
var llmDial = localDialer

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
