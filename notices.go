package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Notices the patrol and the bot send through notify url, in the
// configured language as the bot's own messages are (F-1, F-4: the
// automatic incident check and "Approved from Telegram" went out in
// English whatever [language] said).

var noticeText = map[string][2]string{ // English, Chinese
	"auto_title":      {"Automatic incident check", "自動事件調查"},
	"auto_head":       {"An L3 attack alert (the attack probably succeeded) was checked by the incident sub-agent on its own. It only read; nothing was changed.", "有一則 L3 攻擊警報（攻擊很可能成功），神荼自動派事件調查子 Agent 去查。它只讀取資料，沒有改動任何東西。"},
	"auto_id":         {"- dispatch: %s", "- 派遣編號：%s"},
	"auto_status":     {"- result: %s", "- 結果：%s"},
	"auto_sub":        {"- %s: %s (%s), %d steps, %d tokens", "- %s：%s（%s），查了 %d 輪，用了 %d tokens"},
	"auto_findings":   {"- findings: %s (counts only: the sub-agent's own words are not put in a notice)", "- 發現：%s（只列數量：子 Agent 寫的內容不放進通知）"},
	"auto_nofind":     {"none", "沒有"},
	"auto_unlisted":   {"- not checked: %d item(s) (treat them as unknown, not clean):", "- 沒查到：%d 項（請當成「不知道」，不要當成「沒問題」）："},
	"auto_unitem":     {"  - %s: %s", "  - %s：%s"},
	"auto_unsaid":     {" (as the sub-agent says, not confirmed)", "（子 Agent 回報，未經確認）"},
	"auto_unother":    {"  - %d item(s) for another reason (the sub-agent's own words, not put in a notice)", "  - 其他原因 %d 項（內容由 AI 撰寫，不放進通知）"},
	"auto_unchecked":  {"- not checked: %d item(s) the sub-agent listed as not checked (written by the model, so not put in a notice); treat them as unknown, not clean", "- 沒查到：%d 項。這些是子 Agent 自己列出、說沒有查到的項目，內容由 AI 撰寫，所以不放進通知；請當成「不知道」，不要當成「沒問題」"},
	"auto_allchecked": {"- not checked: nothing the sub-agent listed", "- 沒查到：子 Agent 沒有列出沒查的項目"},
	"auto_noprop":     {"- proposals: none this time; nothing is suggested", "- 建議：這次沒有建議任何動作"},
	"auto_prop":       {"- proposals: block %d IP address(es); the buttons come in the next message. Nothing is blocked unless you press one", "- 建議：封鎖 %d 個 IP，按鈕在下一則訊息；你沒有按，就不會封鎖"},
	"auto_unsaved":    {"- its record could not be saved to the dispatch archive (state_dir/dispatch): no buttons; it still counts toward today's limit", "- 這次的紀錄沒能存進派遣紀錄（state_dir/dispatch），所以沒有按鈕；仍然算進今天的次數"},
	"auto_partial":    {"- an incomplete check is not a clean one: what it did not check is unknown", "- 沒查完不代表沒問題：沒查到的部分，現在還不知道"},

	"approved_title":   {"Approved from Telegram", "已在 Telegram 確認"},
	"approved_block":   {"Blocking %s now, as you confirmed in Telegram; it is lifted by itself after %s. The bot's reply says whether it worked.", "已依你在 Telegram 的確認，開始封鎖 %s；%s後自動解除。是否成功，以 bot 的回覆為準。"},
	"approved_unblock": {"Unblocking %s now, as you confirmed in Telegram. The bot's reply says whether it worked.", "已依你在 Telegram 的確認，開始解除封鎖 %s。是否成功，以 bot 的回覆為準。"},
	"approved_other":   {"Running %s now, as you confirmed in Telegram. The bot's reply says whether it worked.", "已依你在 Telegram 的確認，開始執行 %s。是否成功，以 bot 的回覆為準。"},
	"approved_detail":  {"Technical detail:", "技術細節："},

	"paired_title":   {"Telegram bot paired", "Telegram bot 已配對"},
	"paired_body":    {"The bot now accepts questions from %s. If this was not you, run: sudo shentu bot unpair", "bot 現在開始接受 %s 的提問。如果不是你，請在伺服器執行：sudo shentu bot unpair"},
	"unpaired_title": {"Telegram bot unpaired", "Telegram bot 已解除配對"},
	"unpaired_body":  {"The bot no longer accepts commands from %s.", "bot 不再接受 %s 的指令。"},

	"det_carry_title":   {"Attack detection: last patrol's sends failed", "攻擊偵測：上一輪巡邏有通知沒送出去"},
	"det_more_title":    {"%d more attack attempts", "另外 %d 組攻擊紀錄"},
	"det_attempt_title": {"Attack attempt", "攻擊紀錄"},
	"det_notice_title":  {"Attack detection notice", "攻擊偵測注意事項"},
	"det_carry_head":    {"Attack detection, last patrol(s) — not done after the report:", "攻擊偵測：上一輪（或前幾輪）巡邏在報告送出後沒做完的事："},
}

func nt(zh bool, key string) string {
	if zh {
		return noticeText[key][1]
	}
	return noticeText[key][0]
}

var (
	statusZh      = map[string]string{statusComplete: "完成", statusPartial: "部分完成", statusIncomplete: "沒有完成"}
	reasonZh      = map[string]string{reasonOK: "正常結束", reasonStepLimit: "步數用完", reasonTokenCap: "token 上限到了", reasonBudget: "本月 AI 預算用完", reasonTimeout: "時間到了", reasonModelError: "AI 模型出錯", reasonBadReport: "回報格式不對", reasonSaidNot: "子 Agent 說沒查完", reasonUnsupported: "這個平台還不支援", reasonOther: "其他原因"}
	roleZh        = map[string]string{"patrol": "巡邏", "surface": "攻擊面", "attack": "攻擊", "incident": "事件調查"}
	uncheckedText = map[string][2]string{
		uncheckedToolFailed:    {"the tool failed", "工具執行失敗"},
		uncheckedPermission:    {"not readable (permission)", "權限不足，讀不到"},
		uncheckedNotApplicable: {"not on this server", "這台主機沒有這一項"},
		uncheckedTimeLimit:     {"no time or steps left", "時間或步數不夠，沒查到"},
		uncheckedNotAvailable:  {"not supported on this platform yet", "這個平台還不支援"},
		uncheckedFindingsCut:   {"more findings than a report keeps", "發現太多，超過上限的沒有列出"},
	}
	severityZh = map[string]string{"critical": "嚴重", "high": "高", "medium": "中", "low": "低", "info": "資訊", "unknown": "未分級"}
)

// enumWord is an enumeration from a record, in the notice's language; a
// value it does not know is kept as word() leaves it.
func enumWord(zh bool, m map[string]string, v string) string {
	if w, ok := m[v]; ok && zh {
		return w
	}
	return word(v)
}

// approvedNotice is what goes to notify url once the operator approved a
// control tool from Telegram: what happens, in plain words, first; the
// command itself after it.
func approvedNotice(zh bool, tool, preview string) (title, body string) {
	var head string
	if m := reBlockPreview.FindStringSubmatch(preview); tool == "block_ip" && m != nil {
		secs, _ := strconv.Atoi(m[2])
		head = fmt.Sprintf(nt(zh, "approved_block"), m[1], ttlWords(zh, time.Duration(secs)*time.Second))
	} else if m := reUnblockPreview.FindStringSubmatch(preview); tool == "unblock_ip" && m != nil {
		head = fmt.Sprintf(nt(zh, "approved_unblock"), m[1])
	} else {
		head = fmt.Sprintf(nt(zh, "approved_other"), tool)
	}
	return nt(zh, "approved_title"), head + "\n\n" + nt(zh, "approved_detail") + "\n" + tool + ": " + preview
}

// The previews block_ip and unblock_ip make (tools/firewall.go).
var (
	reBlockPreview   = regexp.MustCompile(`^nft add element inet \S+ block[46] \{ (\S+) timeout (\d+)s \}`)
	reUnblockPreview = regexp.MustCompile(`^nft delete element inet \S+ block[46] \{ (\S+) \}`)
)

// ttlWords is a block's duration as people say it: "24 hours", "7 days".
func ttlWords(zh bool, d time.Duration) string {
	h := int(d.Hours())
	switch {
	case d%(24*time.Hour) == 0 && h >= 48:
		if zh {
			return fmt.Sprintf("%d 天", h/24)
		}
		return fmt.Sprintf("%d days", h/24)
	case d%time.Hour == 0 && h > 0:
		if zh {
			return fmt.Sprintf("%d 小時", h)
		}
		return fmt.Sprintf("%d hours", h)
	}
	if zh {
		return strings.TrimSuffix(d.String(), "0s")
	}
	return d.String()
}

// uncheckedLines is a record's unchecked items as notice lines: the fixed
// words in plain language, one line per tool and reason; the items with
// no fixed words (other, or a record before v0.5.4) as a count.
func uncheckedLines(zh bool, s subRecord) []string {
	if s.Unchecked == 0 {
		return []string{nt(zh, "auto_allchecked")}
	}
	if len(s.UncheckedWhy) == 0 {
		return []string{fmt.Sprintf(nt(zh, "auto_unchecked"), s.Unchecked)}
	}
	out := []string{fmt.Sprintf(nt(zh, "auto_unlisted"), s.Unchecked)}
	i := 0
	if zh {
		i = 1
	}
	type key struct {
		tool, reason string
		picked       bool
	}
	seen := map[key]int{}
	var order []key
	other := s.Unchecked - len(s.UncheckedWhy)
	for _, u := range s.UncheckedWhy {
		t, ok := uncheckedText[u.Reason]
		if !ok {
			other++
			continue
		}
		k := key{u.Tool, t[i], uncheckedPicks[u.Reason]}
		if seen[k] == 0 {
			order = append(order, k)
		}
		seen[k]++
	}
	for _, k := range order {
		what := map[bool]string{false: "(no tool)", true: "（沒有指明工具）"}[zh]
		if l, ok := toolLabels[k.tool]; ok {
			what = l[i]
		} else if k.tool != "" {
			what = word(k.tool)
		}
		line := fmt.Sprintf(nt(zh, "auto_unitem"), what, k.reason)
		if k.picked { // the sub-agent's pick, not the program's own finding (S-193r-2)
			line += nt(zh, "auto_unsaid")
		}
		if n := seen[k]; n > 1 {
			line += fmt.Sprintf(map[bool]string{false: " (%d)", true: "（%d 項）"}[zh], n)
		}
		out = append(out, line)
	}
	if other > 0 {
		out = append(out, fmt.Sprintf(nt(zh, "auto_unother"), other))
	}
	return out
}
