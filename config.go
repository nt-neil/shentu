package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is /etc/shentu/shentu.toml.
type Config struct {
	LLM struct {
		BaseURL   string `toml:"base_url"`
		Model     string `toml:"model"`
		APIKeyEnv string `toml:"api_key_env"`
		MaxSteps  int    `toml:"max_steps"`
		MaxTokens int    `toml:"max_tokens"`
		Timeout   string `toml:"timeout"`
	} `toml:"llm"`
	Notify struct {
		URL string `toml:"url"`
	} `toml:"notify"`
	// Optional monthly limit on model use (0: none). At 80% an alert goes out; at 100%
	// the model is not called until the next month, and patrols send raw findings.
	Budget struct {
		MonthlyCost   float64 `toml:"monthly_cost"`   // in the provider's currency (AppleToken: USD); needs a provider that reports cost
		MonthlyTokens int     `toml:"monthly_tokens"` // input + output + reasoning tokens
	} `toml:"budget"`
	// Telegram interaction: four ranges, each a level from 1 (safest) to 4.
	Bot struct {
		TelegramToken string `toml:"telegram_token"` // default: the bot of a telegram:// notify url
		Interaction   int    `toml:"interaction"`    // 1 notifications only, 2 questions, 3 + block/unblock, 4 + every control tool
		Answers       int    `toml:"answers"`        // 1 problem or not, 2 summary, 3 full (deleted after 24h), 4 full and kept
		Confirm       int    `toml:"confirm"`        // actions: 1 approve on the server, 2 ✅ + one-time code, 3 ✅, 4 none
		Protection    int    `toml:"protection"`     // 1 strict, 2 standard, 3 loose, 4 off
	} `toml:"bot"`
	Tools struct {
		LogPaths    []string `toml:"log_paths"`
		WatchPaths  []string `toml:"watch_paths"`
		CertTargets []string `toml:"cert_targets"`
		WebUsers    []string `toml:"web_users"`
		AppPaths    []string `toml:"app_paths"`
	} `toml:"tools"`
	Patrol struct {
		SSHThreshold int    `toml:"ssh_threshold"`
		Cooldown     string `toml:"cooldown"`
	} `toml:"patrol"`
	StateDir string `toml:"state_dir"`
	Language string `toml:"language"`
}

func loadConfig(path string) (*Config, error) {
	c := &Config{}
	c.LLM.BaseURL = "http://127.0.0.1:11434/v1"
	c.LLM.Model = "qwen2.5:7b"
	c.LLM.MaxSteps = 10
	c.LLM.MaxTokens = 4096
	c.LLM.Timeout = "180s"
	c.Tools.LogPaths = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/nginx/*.log", "/var/log/apache2/*.log"}
	c.Tools.WatchPaths = []string{"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/var/www", "/root/.ssh"}
	c.Tools.WebUsers = []string{"www-data", "apache", "nginx", "http"}
	c.Tools.AppPaths = []string{"/var/www", "/srv", "/opt", "/home", "/root"}
	c.Patrol.SSHThreshold = 10
	c.Patrol.Cooldown = "24h"
	c.Bot.Interaction, c.Bot.Answers, c.Bot.Confirm, c.Bot.Protection = 1, 2, 2, 2
	c.StateDir = "/var/lib/shentu"
	c.Language = "English"

	loadEnvFile(filepath.Join(filepath.Dir(path), "env"))
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// ${VAR} in the file is taken from the environment, so tokens stay out of it.
	if _, err := toml.Decode(expandEnv(string(b)), c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Files written by `shentu setup` override shentu.toml: llm.toml ([llm]) and
	// setup.toml (language, [notify], [bot]) and budget.toml ([budget]).
	for _, name := range []string{"llm.toml", "setup.toml", "budget.toml"} {
		if lb, err := os.ReadFile(filepath.Join(filepath.Dir(path), name)); err == nil {
			if _, err := toml.Decode(expandEnv(string(lb)), c); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	for _, d := range []string{c.LLM.Timeout, c.Patrol.Cooldown} {
		if _, err := time.ParseDuration(d); err != nil {
			return nil, fmt.Errorf("%s: invalid duration %q", path, d)
		}
	}
	for _, v := range []*int{&c.Bot.Interaction, &c.Bot.Answers, &c.Bot.Confirm, &c.Bot.Protection} {
		*v = min(max(*v, 1), 4)
	}
	c.LLM.BaseURL = strings.TrimSuffix(c.LLM.BaseURL, "/")
	return c, nil
}

func (c *Config) apiKey() string {
	if c.LLM.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(c.LLM.APIKeyEnv)
}

func dur(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces only ${VAR}, so a bare $ in regular expressions is left alone.
func expandEnv(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(m string) string { return os.Getenv(m[2 : len(m)-1]) })
}

// loadEnvFile sets KEY=value lines from the env file (the one systemd also loads)
// for variables that are not already set, so `sudo shentu chat` finds the API key.
func loadEnvFile(p string) {
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok && k != "" && !strings.HasPrefix(k, "#") && os.Getenv(k) == "" {
			os.Setenv(k, strings.Trim(v, `"'`))
		}
	}
}
