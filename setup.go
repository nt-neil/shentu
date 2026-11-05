package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// setup chooses the LLM for this server: a local model that Shentu downloads
// itself through Ollama, or a hosted model with an API key.
// The result goes to llm.toml next to the main config (it overrides [llm]),
// and an API key goes to the env file, readable by root only.

type provider struct {
	name, baseURL, model, keyVar string
}

var providers = []provider{
	{"anthropic", "https://api.anthropic.com/v1", "claude-haiku-5-5", "ANTHROPIC_API_KEY"},
	{"openai", "https://api.openai.com/v1", "gpt-4.1-mini", "OPENAI_API_KEY"},
	{"openrouter", "https://openrouter.ai/api/v1", "anthropic/claude-haiku-5-5", "OPENROUTER_API_KEY"},
}

const ollamaURL = "http://127.0.0.1:11434"

func setup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	local := fs.Bool("local", false, "use a local model (installs Ollama if needed, downloads a model sized for this server)")
	model := fs.String("model", "", "model name (default: chosen from available memory, or the provider default)")
	prov := fs.String("provider", "", "hosted provider: anthropic, openai or openrouter; the key is read from SHENTU_API_KEY or prompted")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		return errors.New("setup writes to /etc/shentu; run it with sudo")
	}
	in := bufio.NewReader(os.Stdin)
	if !*local && *prov == "" {
		fmt.Println("Which LLM should Shentu use?")
		fmt.Println("  1) Local model on this server (private, free; needs memory and disk)")
		fmt.Println("  2) Anthropic Claude (API key)")
		fmt.Println("  3) OpenAI (API key)")
		fmt.Println("  4) OpenRouter (API key)")
		switch ask(in, "Choose [1-4]: ") {
		case "1":
			*local = true
		case "2":
			*prov = "anthropic"
		case "3":
			*prov = "openai"
		case "4":
			*prov = "openrouter"
		default:
			return errors.New("no choice made")
		}
	}
	if *local {
		return setupLocal(ctx, in, *model, *yes)
	}
	return setupHosted(ctx, in, *prov, *model)
}

func setupLocal(ctx context.Context, in *bufio.Reader, model string, yes bool) error {
	memGB := memTotalGB()
	if model == "" {
		model = modelForMemory(memGB)
	}
	if model == "" {
		return fmt.Errorf("this server has %.1f GB of memory; at least 3 GB is needed for a local model. Use an API key instead: shentu setup --provider anthropic", memGB)
	}
	fmt.Printf("Memory: %.1f GB → model %s\n", memGB, model)

	if !ollamaUp(ctx) {
		if _, err := exec.LookPath("ollama"); err != nil {
			fmt.Println("Ollama (the local model runtime) is not installed.")
			fmt.Println("It will be installed with its official script: curl -fsSL https://ollama.com/install.sh | sh")
			if !yes && !strings.EqualFold(ask(in, "Install Ollama now? [y/N] "), "y") {
				return errors.New("cancelled")
			}
			cmd := exec.CommandContext(ctx, "sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("installing Ollama: %w", err)
			}
		}
		exec.CommandContext(ctx, "systemctl", "enable", "--now", "ollama").Run()
		for i := 0; i < 30 && !ollamaUp(ctx); i++ {
			time.Sleep(time.Second)
		}
		if !ollamaUp(ctx) {
			return errors.New("Ollama is installed but not answering on " + ollamaURL)
		}
	}
	if err := ollamaPull(ctx, model); err != nil {
		return err
	}
	if err := writeLLM(ollamaURL+"/v1", model, ""); err != nil {
		return err
	}
	return testLLM(ctx)
}

func setupHosted(ctx context.Context, in *bufio.Reader, name, model string) error {
	var p provider
	for _, c := range providers {
		if c.name == name {
			p = c
		}
	}
	if p.name == "" {
		return errors.New("unknown provider: " + name)
	}
	if model == "" {
		model = p.model
	}
	key := strings.TrimSpace(os.Getenv("SHENTU_API_KEY"))
	if key == "" {
		key = askSecret(in, p.name+" API key (input hidden): ")
	}
	if key == "" {
		return errors.New("no API key given")
	}
	if err := setEnv(p.keyVar, key); err != nil {
		return err
	}
	os.Setenv(p.keyVar, key)
	if err := writeLLM(p.baseURL, model, p.keyVar); err != nil {
		return err
	}
	return testLLM(ctx)
}

// modelForMemory picks the largest Qwen 2.5 model (good at tool calling) that fits.
func modelForMemory(gb float64) string {
	switch {
	case gb >= 24:
		return "qwen2.5:14b"
	case gb >= 10:
		return "qwen2.5:7b"
	case gb >= 3:
		return "qwen2.5:3b"
	}
	return ""
}

func memTotalGB() float64 {
	b, _ := os.ReadFile("/proc/meminfo")
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "MemTotal:"); ok {
			kb, _ := strconv.ParseFloat(strings.Fields(v)[0], 64)
			return kb / 1024 / 1024
		}
	}
	return 0
}

func ollamaUp(ctx context.Context) bool {
	req, _ := http.NewRequestWithContext(ctx, "GET", ollamaURL+"/api/version", nil)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func ollamaPull(ctx context.Context, model string) error {
	fmt.Println("Downloading", model, "…")
	b, _ := json.Marshal(map[string]any{"model": model, "stream": true})
	req, _ := http.NewRequestWithContext(ctx, "POST", ollamaURL+"/api/pull", bytes.NewReader(b))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	last := ""
	for sc.Scan() {
		var p struct {
			Status    string `json:"status"`
			Total     int64  `json:"total"`
			Completed int64  `json:"completed"`
			Error     string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &p) != nil {
			continue
		}
		if p.Error != "" {
			return errors.New("download failed: " + p.Error)
		}
		line := p.Status
		if p.Total > 0 {
			line = fmt.Sprintf("%s %d%%", p.Status, p.Completed*100/p.Total)
		}
		if line != last {
			fmt.Printf("\r  %-60s", line)
			last = line
		}
	}
	fmt.Println()
	return sc.Err()
}

func configDir() string { return filepath.Dir(configPath()) }

func writeLLM(baseURL, model, keyVar string) error {
	if err := os.MkdirAll(configDir(), 0o755); err != nil {
		return err
	}
	text := fmt.Sprintf("# Written by `shentu setup`; overrides [llm] in shentu.toml.\n[llm]\nbase_url = %q\nmodel = %q\napi_key_env = %q\n", baseURL, model, keyVar)
	p := filepath.Join(configDir(), "llm.toml")
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		return err
	}
	fmt.Println("Saved", p)
	return nil
}

// setEnv writes or replaces KEY=value in the env file that the systemd units load.
func setEnv(key, value string) error {
	p := filepath.Join(configDir(), "env")
	old, _ := os.ReadFile(p)
	var lines []string
	for _, l := range strings.Split(string(old), "\n") {
		if l != "" && !strings.HasPrefix(l, key+"=") {
			lines = append(lines, l)
		}
	}
	lines = append(lines, key+"="+value)
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("Saved the key to", p, "(root only)")
	return os.Chmod(p, 0o600)
}

func testLLM(ctx context.Context) error {
	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}
	fmt.Print("Testing the model… ")
	reply, err := newLLM(cfg).chat(ctx, []message{{Role: "user", Content: "Reply with the single word: ready"}}, nil)
	if err != nil {
		return fmt.Errorf("the model did not answer: %w", err)
	}
	fmt.Printf("OK (%s)\nNext: sudo shentu chat\n", truncate(strings.TrimSpace(reply.Content), 40))
	return nil
}

func ask(in *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

// askSecret turns off terminal echo with stty while the key is typed.
func askSecret(in *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	echoOff := off.Run() == nil
	line, _ := in.ReadString('\n')
	if echoOff {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		on.Run()
	}
	fmt.Println()
	return strings.TrimSpace(line)
}
