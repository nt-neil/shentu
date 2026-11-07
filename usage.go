package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// usageRow adds up the model calls of one period and one actor (bot, patrol, chat).
type usageRow struct {
	Calls, In, Out, Reason int
	Cost                   float64
	Priced                 int // calls the provider reported a charge for
}

func (r *usageRow) add(e logEntry) {
	r.Calls++
	r.In += e.InTokens
	r.Out += e.OutTokens
	r.Reason += e.ReasonTokens
	if e.Cost > 0 {
		r.Cost += e.Cost
		r.Priced++
	}
}

// usageSummary reads the audit log and adds up model use for today, the last 7 days
// and the last 30 days, per actor.
func usageSummary(stateDir string, now time.Time) [3]map[string]*usageRow {
	var out [3]map[string]*usageRow
	for i := range out {
		out[i] = map[string]*usageRow{}
	}
	f, err := os.Open(filepath.Join(stateDir, "log.jsonl"))
	if err != nil {
		return out
	}
	defer f.Close()
	y, m, d := now.Date()
	starts := [3]time.Time{time.Date(y, m, d, 0, 0, 0, 0, now.Location()), now.AddDate(0, 0, -7), now.AddDate(0, 0, -30)}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e logEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Tool != "llm" {
			continue
		}
		for i, s := range starts {
			if !e.Time.Before(s) {
				r := out[i][e.Actor]
				if r == nil {
					r = &usageRow{}
					out[i][e.Actor] = r
				}
				r.add(e)
			}
		}
	}
	return out
}

func usageReport(stateDir string, now time.Time, zh bool) string {
	sum := usageSummary(stateDir, now)
	periods := [3][2]string{{"Today", "今天"}, {"Last 7 days", "最近 7 天"}, {"Last 30 days", "最近 30 天"}}
	actors := map[string][2]string{"bot": {"Telegram", "Telegram 對話"}, "patrol": {"patrols", "自動巡邏"}, "chat": {"server chat", "伺服器上的 chat"}}
	i := 0
	if zh {
		i = 1
	}
	colon := ": "
	if zh {
		colon = "："
	}
	var b strings.Builder
	for p, rows := range sum {
		var total usageRow
		var lines []string
		for _, a := range []string{"bot", "patrol", "chat"} {
			r := rows[a]
			if r == nil {
				continue
			}
			total.Calls += r.Calls
			total.In += r.In
			total.Out += r.Out
			total.Reason += r.Reason
			total.Cost += r.Cost
			total.Priced += r.Priced
			lines = append(lines, "  "+actors[a][i]+colon+usageLine(r, zh))
		}
		b.WriteString(periods[p][i] + colon + usageLine(&total, zh) + "\n")
		if len(lines) > 1 {
			b.WriteString(strings.Join(lines, "\n") + "\n")
		}
	}
	if zh {
		b.WriteString("（tokens：輸入／輸出／思考。費用是模型服務回報的實際扣款；沒有回報的服務只列 tokens。）")
	} else {
		b.WriteString("(tokens: input / output / reasoning. Cost is what the provider reported charging; providers that do not report it show tokens only.)")
	}
	return b.String()
}

func usageLine(r *usageRow, zh bool) string {
	s := fmt.Sprintf("%d calls, %s / %s / %s tokens", r.Calls, kTokens(r.In), kTokens(r.Out), kTokens(r.Reason))
	if zh {
		s = fmt.Sprintf("%d 次，%s／%s／%s tokens", r.Calls, kTokens(r.In), kTokens(r.Out), kTokens(r.Reason))
	}
	if r.Priced > 0 {
		s += map[bool]string{false: ", ", true: "，"}[zh] + fmt.Sprintf("$%.4f", r.Cost)
		if r.Priced < r.Calls {
			s += map[bool]string{false: " (some calls unpriced)", true: "（部分呼叫沒有報價）"}[zh]
		}
	}
	return s
}

func kTokens(n int) string {
	if n >= 10000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprint(n)
}

// usageBrief is the one line the daily report carries.
func usageBrief(stateDir string, now time.Time, zh bool) string {
	var total usageRow
	for _, r := range usageSummary(stateDir, now)[1] {
		total.Calls += r.Calls
		total.In += r.In
		total.Out += r.Out
		total.Reason += r.Reason
		total.Cost += r.Cost
		total.Priced += r.Priced
	}
	if zh {
		return "最近 7 天 AI 用量：" + usageLine(&total, true)
	}
	return "AI use, last 7 days: " + usageLine(&total, false)
}
