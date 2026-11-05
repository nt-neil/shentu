package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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
		Timeout   string `toml:"timeout"`
	} `toml:"llm"`
	Notify struct {
		URL string `toml:"url"`
	} `toml:"notify"`
	Tools struct {
		LogPaths    []string `toml:"log_paths"`
		WatchPaths  []string `toml:"watch_paths"`
		CertTargets []string `toml:"cert_targets"`
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
	c.LLM.Timeout = "180s"
	c.Tools.LogPaths = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/nginx/*.log", "/var/log/apache2/*.log"}
	c.Tools.WatchPaths = []string{"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/var/www", "/root/.ssh"}
	c.Patrol.SSHThreshold = 10
	c.Patrol.Cooldown = "24h"
	c.StateDir = "/var/lib/shentu"
	c.Language = "English"

	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	// ${VAR} in the file is taken from the environment, so tokens stay out of it.
	if _, err := toml.Decode(expandEnv(string(b)), c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, d := range []string{c.LLM.Timeout, c.Patrol.Cooldown} {
		if _, err := time.ParseDuration(d); err != nil {
			return nil, fmt.Errorf("%s: invalid duration %q", path, d)
		}
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
