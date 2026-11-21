package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/nt-neil/shentu/tools"
)

var errBudget = errors.New("the monthly AI budget is used up; raise it with `sudo shentu budget` or wait for next month")

// errBudgetReserved is a budget stop that only other dispatches' live
// reservations make (R1): the month's use alone is under the limit. It is
// an errBudget, with its own words.
type errBudgetReserved struct{ tokens int }

func (e errBudgetReserved) Error() string {
	return fmt.Sprintf("other dispatches in progress have reserved %s tokens, so this month's remaining AI budget is not enough to answer; a reservation is released within about %d minutes, try again later", kTokens(e.tokens), int(reserveTTL().Minutes()))
}

func (e errBudgetReserved) Is(target error) bool { return target == errBudget }

// budgetStop is the check before a model call: errBudget when the month's
// use reaches a limit, errBudgetReserved when only the others' reservations
// (all but self's) make it, and an errReservations error, which names the
// file and how to reset it, when the reservations cannot be trusted.
func budgetStop(cfg *Config, now time.Time, self string) error {
	if budgetUsed(cfg, now) >= 1 {
		return errBudget
	}
	if cfg.Budget.MonthlyTokens <= 0 {
		return nil
	}
	n, err := othersReserved(cfg, self, now)
	if err != nil {
		return err
	}
	if budgetUsedExcept(cfg, now, self, true) >= 1 {
		return errBudgetReserved{n}
	}
	return nil
}

// monthUsage adds up model cost and tokens since the start of this month.
func monthUsage(stateDir string, now time.Time) (cost float64, tokens int) {
	cost, tokens, _, _ = monthUsageStrict(stateDir, now)
	return cost, tokens
}

// maxLogLine is the longest log.jsonl line monthUsageStrict reads; a model
// call's line is far shorter, so a longer one is skipped and counted.
const maxLogLine = 1 << 20

var errLongLLMLine = errors.New("log.jsonl: a model call's line is longer than 1 MiB")

// monthUsageStrict is monthUsage that also says when log.jsonl could not
// be read to its end (no log yet is no use, not an error): what stops on
// it must not take a part for the whole. long counts the lines past
// maxLogLine, skipped without stopping the count.
func monthUsageStrict(stateDir string, now time.Time) (cost float64, tokens, long int, err error) {
	f, err := os.Open(filepath.Join(stateDir, "log.jsonl"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, 0, 0, nil
	}
	if err != nil {
		return 0, 0, 0, err
	}
	defer f.Close()
	y, m, _ := now.Date()
	start := time.Date(y, m, 1, 0, 0, 0, 0, now.Location())
	r := bufio.NewReaderSize(f, maxLogLine)
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// A model call's line (its error can quote a provider's answer)
			// is never skipped: its use would go uncounted.
			if bytes.Contains(line[:min(len(line), 4096)], []byte(`"tool":"llm"`)) {
				return cost, tokens, long, errLongLLMLine
			}
			long++
			for errors.Is(err, bufio.ErrBufferFull) { // the rest of it
				_, err = r.ReadSlice('\n')
			}
			if err == io.EOF {
				return cost, tokens, long, nil
			}
			if err != nil {
				return cost, tokens, long, err
			}
			continue
		}
		if len(line) > 0 {
			var e logEntry
			if json.Unmarshal(line, &e) == nil && e.Tool == "llm" && !e.Time.Before(start) {
				cost += e.Cost
				tokens += e.InTokens + e.OutTokens + e.ReasonTokens
			}
		}
		if err == io.EOF {
			return cost, tokens, long, nil
		}
		if err != nil {
			return cost, tokens, long, err
		}
	}
}

// budgetUsed is the larger share of the limits that are set (0 when none is),
// and 1 when log.jsonl could not be read to its end.
func budgetUsed(cfg *Config, now time.Time) float64 { return budgetUsedExcept(cfg, now, "", false) }

// budgetUsedExcept is budgetUsed for a model call: with others set, the
// tokens other dispatches have reserved count as used, all but self's; a
// reservation file that cannot be read counts as the limit reached.
func budgetUsedExcept(cfg *Config, now time.Time, self string, others bool) float64 {
	if cfg.Budget.MonthlyCost <= 0 && cfg.Budget.MonthlyTokens <= 0 {
		return 0
	}
	// A log read only in part could hide use: count it as the limit reached.
	cost, tokens, _, err := monthUsageStrict(cfg.StateDir, now)
	if err != nil {
		return 1
	}
	if others && cfg.Budget.MonthlyTokens > 0 {
		n, err := othersReserved(cfg, self, now)
		if err != nil {
			return 1
		}
		tokens += n
	}
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
	s += fmt.Sprintf(" (%.0f%%)", budgetUsed(cfg, now)*100)
	if cfg.Budget.MonthlyTokens > 0 { // R1: what dispatches in progress hold, read only
		switch n, err := peekReserved(cfg, now); {
		case err != nil:
			s += map[bool]string{false: "; the reservations of dispatches in progress cannot be read", true: "；進行中派遣的預留無法讀取"}[zh]
		case n > 0:
			s += fmt.Sprintf(map[bool]string{false: "; besides that, %s are reserved by dispatches in progress", true: "；另有 %s 被進行中的派遣預留"}[zh], kTokens(n))
		}
	}
	return s
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
