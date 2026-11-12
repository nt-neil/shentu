// Shentu is a small security assistant for Linux servers: an LLM with a set of
// security tools and playbooks (skills). See README.md.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/nt-neil/shentu/tools"
)

var version = "dev"

const usage = `shentu — security assistant for Linux servers

Usage:
  shentu setup                choose the LLM: download a local model, or enter an API key
               [--local] [--provider anthropic|openai|openrouter|appletoken] [--model NAME] [--yes]
  shentu chat [question]      ask in plain language; with a question, answer once and exit
  shentu patrol [--daily]     run the checks once and notify on new findings (for a systemd timer)
                [--dry-run]   print the report instead of sending it
  shentu survey               survey this server (services, exposure, stacks, SSH, firewall) and save it as the baseline
  shentu bot [pair|unpair|status|approve|totp|resume]
                              answer questions from Telegram (a systemd service); pair one user first
                approve       show the action proposed from Telegram and run it or not (confirm = 1)
                totp          enrol an authenticator app; actions from Telegram then ask for its code (confirm = 2)
                resume        unpause the bot after /lockdown, then restart the service
  shentu usage                model calls, tokens and cost: today, last 7 and 30 days
  shentu budget [--cost USD] [--tokens N] [--off]
                              optional monthly AI limit: alert at 80%, stop calling the model at 100%
  shentu version

Config: /etc/shentu/shentu.toml (override with SHENTU_CONFIG)
`

func configPath() string {
	if p := os.Getenv("SHENTU_CONFIG"); p != "" {
		return p
	}
	return defaultConfigPath()
}

// printUsage prints the usage for help (help, --help, -h) to stdout and
// returns 0; for a missing or unknown command, to stderr and returns 2.
func printUsage(cmd string, stdout, stderr io.Writer) int {
	u := strings.Replace(usage, "/etc/shentu/shentu.toml", defaultConfigPath(), 1) // the same text on Unix
	if runtime.GOOS == "windows" {
		u = strings.Replace(u, "  shentu version\n", "  shentu service install|uninstall|start|stop|status [--bot]\n"+
			"                              run patrol as a Windows service (LocalSystem): every 30 minutes, daily report at 09:00;\n"+
			"                              --bot: the Telegram bot as its own service (ShentuBot)\n  shentu version\n", 1)
	}
	if cmd == "help" || cmd == "--help" || cmd == "-h" {
		fmt.Fprint(stdout, u)
		return 0
	}
	fmt.Fprint(stderr, u)
	return 2
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(printUsage("", os.Stdout, os.Stderr))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, args := os.Args[1], os.Args[2:]
	switch cmd { // before the config: help and a mistyped command need none
	case "help", "--help", "-h":
		os.Exit(printUsage(cmd, os.Stdout, os.Stderr))
	case "version", "--version", "setup", "chat", "survey", "bot", "budget", "usage", "patrol", "service":
	default:
		os.Exit(printUsage(cmd, os.Stdout, os.Stderr))
	}
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
	tools.SetWebUsers(cfg.Tools.WebUsers)
	tools.SetAuditLimits(cfg.Tools.AuditMaxMemoryMB, cfg.Tools.AuditWorkers)
	tools.SetCacheDir(filepath.Join(cfg.StateDir, "cache"))
	env := &tools.Env{
		LogPaths:    cfg.Tools.LogPaths,
		WatchPaths:  cfg.Tools.WatchPaths,
		CertTargets: cfg.Tools.CertTargets,
		AppPaths:    cfg.Tools.AppPaths,
		NotifyURL:   cfg.Notify.URL,
		HTTP:        &http.Client{Timeout: 30 * time.Second},
	}
	switch cmd {
	case "chat":
		err = chat(ctx, cfg, env, strings.Join(args, " "))
	case "survey":
		var p tools.SiteProfile
		p, err = survey(ctx, cfg, env)
		if err == nil {
			b, _ := json.MarshalIndent(p, "", "  ")
			fmt.Println(string(b))
		}
	case "bot":
		err = botCommand(ctx, cfg, env, args)
	case "budget":
		err = budgetCommand(cfg, args)
	case "usage":
		fmt.Println(usageReport(cfg.StateDir, time.Now(), strings.Contains(cfg.Language, "中文") || strings.HasPrefix(strings.ToLower(cfg.Language), "zh")))
	case "patrol":
		fs := flag.NewFlagSet("patrol", flag.ExitOnError)
		daily := fs.Bool("daily", false, "always send a full daily report")
		dry := fs.Bool("dry-run", false, "print the report, do not notify")
		fs.Parse(args)
		err = patrol(ctx, cfg, env, *daily, *dry)
	case "service":
		err = serviceCommand(ctx, cfg, env, args)
	default:
		os.Exit(printUsage(cmd, os.Stdout, os.Stderr))
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
	if !privileged() {
		fmt.Fprintln(os.Stderr, unprivilegedNote)
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

// survey runs the site survey and stores it as the baseline that patrol compares with.
func survey(ctx context.Context, cfg *Config, env *tools.Env) (tools.SiteProfile, error) {
	if err := ensureStateDir(cfg.StateDir); err != nil {
		return tools.SiteProfile{}, err
	}
	st := loadState(cfg.StateDir)
	st.Profile = tools.Survey(ctx, env)
	return st.Profile, st.save(cfg.StateDir)
}
