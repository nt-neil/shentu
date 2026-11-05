// Shentu is a small security assistant for Linux servers: an LLM with a set of
// security tools and playbooks (skills). See README.md.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/nt-nerdtechnic/shentu/tools"
)

var version = "dev"

const usage = `shentu — security assistant for Linux servers

Usage:
  shentu setup                choose the LLM: download a local model, or enter an API key
               [--local] [--provider anthropic|openai|openrouter] [--model NAME] [--yes]
  shentu chat [question]      ask in plain language; with a question, answer once and exit
  shentu patrol [--daily]     run the checks once and notify on new findings (for a systemd timer)
                [--dry-run]   print the report instead of sending it
  shentu version

Config: /etc/shentu/shentu.toml (override with SHENTU_CONFIG)
`

func configPath() string {
	if p := os.Getenv("SHENTU_CONFIG"); p != "" {
		return p
	}
	return "/etc/shentu/shentu.toml"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "version" || cmd == "--version" {
		fmt.Println("shentu", version)
		return
	}
	if cmd == "setup" {
		if err := setup(ctx, args); err != nil {
			fatal(err)
		}
		return
	}
	cfg, err := loadConfig(configPath())
	if err != nil {
		fatal(err)
	}
	env := &tools.Env{
		LogPaths:    cfg.Tools.LogPaths,
		WatchPaths:  cfg.Tools.WatchPaths,
		CertTargets: cfg.Tools.CertTargets,
		NotifyURL:   cfg.Notify.URL,
		HTTP:        &http.Client{Timeout: 30 * time.Second},
	}
	switch cmd {
	case "chat":
		err = chat(ctx, cfg, env, strings.Join(args, " "))
	case "patrol":
		fs := flag.NewFlagSet("patrol", flag.ExitOnError)
		daily := fs.Bool("daily", false, "always send a full daily report")
		dry := fs.Bool("dry-run", false, "print the report, do not notify")
		fs.Parse(args)
		err = patrol(ctx, cfg, env, *daily, *dry)
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "shentu:", err)
	os.Exit(1)
}

// chat is the interactive assistant. Control tools are offered only here, and
// every one of them waits for the operator to type y.
func chat(ctx context.Context, cfg *Config, env *tools.Env, question string) error {
	in := bufio.NewReader(os.Stdin)
	skills := loadSkills(filepath.Join(filepath.Dir(configPath()), "skills"))
	a := &agent{
		cfg: cfg, llm: newLLM(cfg), env: env, skills: skills,
		allowControl: true, actor: "chat", log: newAuditLog(cfg.StateDir),
		confirm: func(tool, preview string) bool {
			fmt.Printf("\n⚠️  %s wants to run:\n    %s\nAllow? [y/N] ", tool, printable(preview))
			line, _ := in.ReadString('\n')
			return strings.EqualFold(strings.TrimSpace(line), "y")
		},
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "note: not running as root; some logs and process details will be unreadable and block_ip will fail.")
	}
	msgs := []message{{Role: "system", Content: systemPrompt(cfg, skills)}}
	ask := func(q string) error {
		msgs = append(msgs, message{Role: "user", Content: q})
		fmt.Fprintln(os.Stderr, "…thinking")
		answer, hist, err := a.run(ctx, msgs)
		msgs = hist
		if err != nil {
			return err
		}
		fmt.Printf("\n%s\n\n", strings.TrimSpace(answer))
		return nil
	}
	if question != "" {
		return ask(question)
	}
	fmt.Println("Shentu chat. Ask about this server's security; type exit to quit.")
	for {
		fmt.Print("> ")
		line, err := in.ReadString('\n')
		q := strings.TrimSpace(line)
		if q == "exit" || q == "quit" || (err != nil && q == "") {
			return nil
		}
		if q == "" {
			continue
		}
		if err := ask(q); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	}
}

// printable replaces non-printable characters (ESC, CR, newlines, bidi overrides…) so text from the
// model cannot redraw the terminal and disguise what the operator confirms.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) || r == 0x2028 || r == 0x2029 {
			return '?'
		}
		return r
	}, s)
}
