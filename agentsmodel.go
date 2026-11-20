package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// The sub-agents' own model ([agents] base_url, model, api_key_env), off
// unless set: without it they use [llm] as before. A model outside this
// host gets this host's logs and settings (masked, as every tool result
// is), so it is refused without a monthly budget, and each dispatch that
// used one says so in its record, its note to the commander and the daily
// report. The key is read from the named environment variable, like
// [llm]'s, and never written anywhere.

// agentsExternal says whether baseURL is outside this host; tests swap it.
// Only a literal loopback address or "localhost" is this host: any other
// name is outside, whatever it resolves to now (it can resolve elsewhere
// at the next connection), and so is a LAN address, this host's own
// included; its user sets the budget it then needs.
var agentsExternal = func(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return true
	}
	h := u.Hostname()
	if strings.EqualFold(h, "localhost") {
		return false
	}
	ip := net.ParseIP(h)
	return ip == nil || !ip.IsLoopback()
}

// agentsLLM is the client the sub-agents of a dispatch use, and whether it
// is outside this host. An unusable setting is an error, and the dispatch
// then runs no sub-agent: it never falls back to another model quietly.
func agentsLLM(cfg *Config, main *llmClient) (*llmClient, bool, error) {
	ag := cfg.Agents
	if ag.BaseURL == "" && ag.Model == "" && ag.APIKeyEnv == "" {
		return main, false, nil
	}
	if ag.BaseURL == "" || ag.Model == "" {
		return nil, false, errors.New("[agents] base_url and model go together")
	}
	external := agentsExternal(ag.BaseURL)
	// Tokens, not cost: only some providers report what a call cost, so a
	// cost limit alone may never be reached.
	if external && cfg.Budget.MonthlyTokens <= 0 {
		return nil, true, errors.New("[agents] names a model outside this host: set a monthly token limit first ([budget] monthly_tokens, `shentu budget --tokens N`)")
	}
	if ag.APIKeyEnv != "" && os.Getenv(ag.APIKeyEnv) == "" {
		return nil, external, fmt.Errorf("[agents] api_key_env names %s, which is not set", ag.APIKeyEnv)
	}
	c := *cfg
	c.LLM.BaseURL, c.LLM.Model, c.LLM.APIKeyEnv = ag.BaseURL, ag.Model, ag.APIKeyEnv
	l := newLLM(&c)
	l.opaqueErrors = external // keyForms still scrubs the rest, as a second line
	if main != nil && main.maxTokens > 0 {
		l.maxTokens = main.maxTokens
	}
	return l, external, nil
}

// agentsOnThisHost says whether baseURL may well be this host, for running
// sub-agents at once (on this host's model they only compete for it): any
// loopback or unspecified address in any form (127.1, 0x7f.1, 0.0.0.0, ::),
// an address of this host's interfaces, a .localhost name, or a name that
// resolves to one of those. Anything it cannot tell counts as this host:
// the cost of a wrong guess is only running in turn. The budget and the
// labels go by agentsExternal's literal reading instead. Tests swap it.
var agentsOnThisHost = func(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return true
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	local := func(ip net.IP) bool {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true
		}
		addrs, err := interfaceAddrs()
		if err != nil { // cannot tell: this host, so in turn
			return true
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return true
			}
		}
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return local(ip)
	}
	if ip := atonV4(h); ip != nil {
		return local(ip)
	}
	ips, err := net.LookupIP(h)
	if err != nil {
		return true
	}
	for _, ip := range ips {
		if local(ip) {
			return true
		}
	}
	return false
}

// interfaceAddrs is net.InterfaceAddrs; tests swap it.
var interfaceAddrs = net.InterfaceAddrs

// atonV4 reads an IPv4 address the way inet_aton does (and so connect does):
// one to four parts, each decimal, octal (0...) or hex (0x...), the last
// filling the bytes left (127.1 is 127.0.0.1). nil when s is not one.
func atonV4(s string) net.IP {
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	var v [4]uint64
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 0, 32)
		if err != nil || p == "" {
			return nil
		}
		v[i] = n
	}
	last := len(parts) - 1
	for i := 0; i < last; i++ {
		if v[i] > 255 {
			return nil
		}
	}
	if v[last] >= 1<<(8*uint(4-last)) {
		return nil
	}
	var a uint64
	for i := 0; i < last; i++ {
		a |= v[i] << (8 * uint(3-i))
	}
	a |= v[last]
	return net.IPv4(byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
}
