package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
)

// The sub-agents' own model ([agents] base_url, model, api_key_env), off
// unless set: without it they use [llm] as before. A model outside this
// host gets this host's logs and settings (masked, as every tool result
// is), so it is refused without a monthly budget, and each dispatch that
// used one says so in its record, its note to the commander and the daily
// report. The key is read from the named environment variable, like
// [llm]'s, and never written anywhere.

// agentsExternal says whether baseURL is outside this host; tests swap it.
var agentsExternal = func(baseURL string) bool {
	u, err := url.Parse(baseURL)
	return err != nil || !isLoopbackHost(u.Hostname())
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
	if external && cfg.Budget.MonthlyTokens <= 0 && cfg.Budget.MonthlyCost <= 0 {
		return nil, true, errors.New("[agents] names a model outside this host: set a monthly limit first ([budget] monthly_tokens or monthly_cost, `shentu budget`)")
	}
	if ag.APIKeyEnv != "" && os.Getenv(ag.APIKeyEnv) == "" {
		return nil, external, fmt.Errorf("[agents] api_key_env names %s, which is not set", ag.APIKeyEnv)
	}
	c := *cfg
	c.LLM.BaseURL, c.LLM.Model, c.LLM.APIKeyEnv = ag.BaseURL, ag.Model, ag.APIKeyEnv
	l := newLLM(&c)
	if main != nil && main.maxTokens > 0 {
		l.maxTokens = main.maxTokens
	}
	return l, external, nil
}
