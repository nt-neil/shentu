//go:build eval

package main

// Only in builds with -tags eval (the model comparison in eval/): `shentu eval-bot <question>`
// answers once exactly as the Telegram bot does at answers = 2, without Telegram.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nt-neil/shentu/tools"
)

func init() {
	if len(os.Args) < 3 || os.Args[1] != "eval-bot" {
		return
	}
	cfg, err := loadConfig(configPath())
	if err != nil {
		fatal(err)
	}
	cfg.Bot.Answers = 2
	tools.SetWebUsers(cfg.Tools.WebUsers)
	env := &tools.Env{LogPaths: cfg.Tools.LogPaths, WatchPaths: cfg.Tools.WatchPaths, CertTargets: cfg.Tools.CertTargets,
		AppPaths: cfg.Tools.AppPaths, HTTP: &http.Client{Timeout: 30 * time.Second}}
	skills := loadSkills(filepath.Join(filepath.Dir(configPath()), "skills"))
	b := &bot{cfg: cfg}
	a := &agent{cfg: cfg, llm: newLLM(cfg), env: env, skills: skills, actor: "bot", log: newAuditLog(cfg.StateDir)}
	answer, _, err := a.run(context.Background(), []message{
		{Role: "system", Content: systemPrompt(cfg, skills) + answerRule(2, b.zh())},
		{Role: "user", Content: strings.Join(os.Args[2:], " ")}})
	if err != nil {
		fatal(err)
	}
	answer, next := splitSuggestions(strings.TrimSpace(answer))
	answer = tools.Cut(answer, maxAnswer(2))
	fmt.Printf("%s\n\nSUGGESTIONS:\n", answer)
	for _, s := range next {
		fmt.Println("» " + s)
	}
	os.Exit(0)
}
