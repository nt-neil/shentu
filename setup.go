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
	"runtime"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
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
	{"openai", "https://api.openai.com/v1", "gpt-6-luna", "OPENAI_API_KEY"},
	{"openrouter", "https://openrouter.ai/api/v1", "anthropic/claude-haiku-5-5", "OPENROUTER_API_KEY"},
	{"appletoken", "https://appletoken.app/v1", "grok-4-1-fast-reasoning", "APPLETOKEN_API_KEY"},
}

const ollamaURL = "http://127.0.0.1:11434"

// errSetupWindows: setup installs Ollama with curl | sh and manages systemd
// units, neither of which exists on Windows.
var errSetupWindows = errors.New("shentu setup is not supported on Windows yet; write %ProgramData%\\Shentu\\shentu.toml by hand (see INSTALL.md in the zip)")

func setup(ctx context.Context, args []string) error {
	if runtime.GOOS == "windows" {
		return errSetupWindows
	}
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	local := fs.Bool("local", false, "use a local model (installs Ollama if needed, downloads a model sized for this server)")
	model := fs.String("model", "", "model name (default: chosen from available memory, or the provider default)")
	prov := fs.String("provider", "", "hosted provider: anthropic, openai, openrouter or appletoken; the key is read from SHENTU_API_KEY or prompted")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		return errors.New("setup writes to /etc/shentu; run it with sudo")
	}
	in := bufio.NewReader(os.Stdin)
	if !*local && *prov == "" && *model == "" {
		// No flags: the guided setup, from the model to the first report.
		if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
			return errors.New("setup asks questions and needs a terminal; for scripts use flags, e.g. SHENTU_API_KEY=… shentu setup --provider anthropic")
		}
		return wizard(ctx, in, *yes)
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

// chooseLLM asks which model to use and sets it up, including the test call.
func chooseLLM(ctx context.Context, in *bufio.Reader, w *wiz) error {
	fmt.Println(w.t("Which AI model should Shentu use?", "Shentu 要用哪個 AI 模型？"))
	fmt.Println(w.t("  1) Local model on this server (private, free; needs memory and disk)", "  1) 這台伺服器上的本機模型（資料不外流、免費；需要記憶體和磁碟）"))
	fmt.Println(w.t("  2) Anthropic Claude (API key)", "  2) Anthropic Claude（API 金鑰）"))
	fmt.Println(w.t("  3) OpenAI (API key)", "  3) OpenAI（API 金鑰）"))
	fmt.Println(w.t("  4) OpenRouter (API key)", "  4) OpenRouter（API 金鑰）"))
	fmt.Println(w.t("  5) AppleToken (API key)", "  5) AppleToken（API 金鑰）"))
	switch ask(in, w.t("Choose [1-5]: ", "請選擇 [1-5]：")) {
	case "1":
		return setupLocal(ctx, in, "", w.yes)
	case "2":
		return setupHosted(ctx, in, "anthropic", "")
	case "3":
		return setupHosted(ctx, in, "openai", "")
	case "4":
		return setupHosted(ctx, in, "openrouter", "")
	case "5":
		return setupHosted(ctx, in, "appletoken", "")
	}
	return errors.New("no choice made")
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
	src, err := hostenv.NewLive(nil)
	if err != nil {
		return 0
	}
	return float64(hostenv.LinuxCollector{}.Resources(src).Value.MemTotalBytes) / (1 << 30)
}

func ollamaUp(ctx context.Context) bool {
	req, _ := http.NewRequestWithContext(ctx, "GET", ollamaURL+"/api/version", nil)
	resp, err := (&http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: localDialer}}).Do(req)
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
	resp, err := (&http.Client{Transport: &http.Transport{DialContext: localDialer}}).Do(req)
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
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("the value must be a single line")
	}
	p := filepath.Join(configDir(), "env")
	old, _ := os.ReadFile(p)
	var lines []string
	for _, l := range strings.Split(string(old), "\n") {
		if l != "" && !strings.HasPrefix(l, key+"=") {
			lines = append(lines, l)
		}
	}
	lines = append(lines, key+"="+value)
	// Write a new root-only file and rename it, so the key is never in a file with looser permissions.
	tmp := p + ".tmp"
	os.Remove(tmp)
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	fmt.Println("Saved the key to", p, "(root only)")
	return nil
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
	fmt.Printf("OK (%s)\n", truncate(strings.TrimSpace(reply.Content), 40))
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
