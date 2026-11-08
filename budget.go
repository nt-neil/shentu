package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nt-neil/shentu/tools"
)

var errBudget = errors.New("the monthly AI budget is used up; raise it with `sudo shentu budget` or wait for next month")

// monthUsage adds up model cost and tokens since the start of this month.
func monthUsage(stateDir string, now time.Time) (cost float64, tokens int) {
	f, err := os.Open(filepath.Join(stateDir, "log.jsonl"))
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	y, m, _ := now.Date()
	start := time.Date(y, m, 1, 0, 0, 0, 0, now.Location())
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e logEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Tool != "llm" || e.Time.Before(start) {
			continue
		}
		cost += e.Cost
		tokens += e.InTokens + e.OutTokens + e.ReasonTokens
	}
	return cost, tokens
}

// budgetUsed is the larger share of the limits that are set (0 when none is).
func budgetUsed(cfg *Config, now time.Time) float64 {
	if cfg.Budget.MonthlyCost <= 0 && cfg.Budget.MonthlyTokens <= 0 {
		return 0
	}
	cost, tokens := monthUsage(cfg.StateDir, now)
	used := 0.0
	if cfg.Budget.MonthlyCost > 0 {
		used = cost / cfg.Budget.MonthlyCost
	}
	if cfg.Budget.MonthlyTokens > 0 {
		used = max(used, float64(tokens)/float64(cfg.Budget.MonthlyTokens))
	}
	return used
}

// budgetAlert notifies once a month at 80% and once at 100%.
func budgetAlert(ctx context.Context, cfg *Config, env *tools.Env, now time.Time) {
	used := budgetUsed(cfg, now)
	level := 0
	switch {
	case used >= 1:
		level = 100
	case used >= 0.8:
		level = 80
	default:
		return
	}
	p := filepath.Join(cfg.StateDir, "budget.json")
	var st struct {
		Month  string `json:"month"`
		Warned int    `json:"warned"`
	}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &st)
	}
	month := now.Format("2006-01")
	if st.Month == month && st.Warned >= level {
		return
	}
	st.Month, st.Warned = month, level
	b, _ := json.Marshal(st)
	os.WriteFile(p, b, 0o600)
	zh := isZh(cfg)
	line := budgetLine(cfg, now, zh)
	if level == 100 {
		msg := "The model will not be called again this month. Patrols keep running and send their raw findings. Raise the limit with: sudo shentu budget"
		if zh {
			msg = "這個月不會再呼叫 AI 模型。巡邏照常進行，告警會改成只列原始發現。要提高上限請在伺服器執行：sudo shentu budget"
		}
		tools.Notify(ctx, env, map[bool]string{false: "AI budget used up", true: "AI 預算已用完"}[zh], line+"\n"+msg, "critical")
		return
	}
	tools.Notify(ctx, env, map[bool]string{false: "AI budget at 80%", true: "AI 預算已用掉 80%"}[zh], line, "warning")
}

// budgetLine says how much of this month's budget is used, or "" when none is set.
func budgetLine(cfg *Config, now time.Time, zh bool) string {
	if cfg.Budget.MonthlyCost <= 0 && cfg.Budget.MonthlyTokens <= 0 {
		return ""
	}
	cost, tokens := monthUsage(cfg.StateDir, now)
	s := map[bool]string{false: "This month's AI budget: ", true: "本月 AI 預算："}[zh]
	if cfg.Budget.MonthlyCost > 0 {
		s += fmt.Sprintf("$%.4f / $%.2f", cost, cfg.Budget.MonthlyCost)
	}
	if cfg.Budget.MonthlyTokens > 0 {
		if cfg.Budget.MonthlyCost > 0 {
			s += map[bool]string{false: ", ", true: "，"}[zh]
		}
		s += fmt.Sprintf("%s / %s tokens", kTokens(tokens), kTokens(cfg.Budget.MonthlyTokens))
	}
	return s + fmt.Sprintf(" (%.0f%%)", budgetUsed(cfg, now)*100)
}

func isZh(cfg *Config) bool {
	return (&bot{cfg: cfg}).zh()
}

// budgetCommand shows or sets the monthly limit: shentu budget [--cost USD] [--tokens N] [--off].
func budgetCommand(cfg *Config, args []string) error {
	fs := flag.NewFlagSet("budget", flag.ExitOnError)
	cost := fs.Float64("cost", -1, "monthly limit in the provider's currency (AppleToken: USD); 0 removes it")
	tok := fs.Int("tokens", -1, "monthly limit in tokens (input + output + reasoning); 0 removes it")
	off := fs.Bool("off", false, "remove both limits")
	fs.Parse(args)
	if *cost < 0 && *tok < 0 && !*off {
		if l := budgetLine(cfg, time.Now(), isZh(cfg)); l != "" {
			fmt.Println(l)
		} else {
			fmt.Println("No monthly AI budget is set. Set one with: shentu budget --cost 5   (or --tokens 2000000)")
		}
		return nil
	}
	if *off {
		*cost, *tok = 0, 0
	}
	if *cost >= 0 {
		cfg.Budget.MonthlyCost = *cost
	}
	if *tok >= 0 {
		cfg.Budget.MonthlyTokens = *tok
	}
	if err := writeBudget(cfg.Budget.MonthlyCost, cfg.Budget.MonthlyTokens); err != nil {
		return err
	}
	if l := budgetLine(cfg, time.Now(), isZh(cfg)); l != "" {
		fmt.Println(l)
	} else {
		fmt.Println("Monthly AI budget removed.")
	}
	return nil
}

func writeBudget(cost float64, tokens int) error {
	p := filepath.Join(configDir(), "budget.toml")
	body := fmt.Sprintf("# Written by `shentu budget` / `shentu setup`. 0 means no limit.\n[budget]\nmonthly_cost = %g\nmonthly_tokens = %d\n", cost, tokens)
	return os.WriteFile(p, []byte(body), 0o644)
}
