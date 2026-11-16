package detect

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// The alert's text (plan 0743f0, P4 part 4), in Chinese: what P5 sends to
// Telegram, and the report's, whose addresses are masked for sharing.
// Sending it and the block_ip gate are P5's.

var severityZh = map[string]string{"info": "資訊", "low": "低", "medium": "中", "high": "高", "critical": "嚴重"}

var levelZh = map[string]string{
	LevelRoute:   "L1：請求打到有漏洞的路由，但沒有帶已知的攻擊內容",
	LevelPayload: "L2：請求打到漏洞，並帶有同類型的攻擊內容或專為它寫的簽章",
	LevelSuccess: "L3：攻擊很可能已經成功",
	LevelUnknown: "無法判定：請求被截斷，比對不完整",
}

// NoTelegramUnblock is said of every alert whose source cannot be believed.
const NoTelegramUnblock = "不能從 Telegram 放行封鎖，必須在伺服器上用 shentu chat 加 override"

// AlertText is the Telegram alert for a group due (Attacks.Due), with its
// surface entry when found. The addresses are shown in full: blocking is
// one address. Every field from a log is Printable: one line each. P5
// sends it as plain text (no parse_mode).
func AlertText(g *Group, s *Surface) string {
	return alertText(g, s, false)
}

// ReportText is the same for the report file and a shared copy: the
// addresses masked (MaskIP), in the samples too.
func ReportText(g *Group, s *Surface) string {
	return alertText(g, s, true)
}

// NoticeText is what the state itself says, sent apart from any group's
// alert (then Attacks.NoticesSent): pending groups merged into overflow
// groups or lost past the bounds, and what loading found wrong. "" when
// there is nothing.
func NoticeText(a *Attacks) string {
	var b strings.Builder
	if a.DroppedPending > 0 {
		fmt.Fprintf(&b, "【Shentu 攻擊偵測】注意：有 %d 組尚未推播的攻擊紀錄超過容量上限，已併入「溢出彙總」告警（或超過彙總上限而遺失）。請到伺服器上查看完整報告。\n", a.DroppedPending)
	}
	if a.Note != "" {
		b.WriteString("【Shentu 攻擊偵測】狀態檔異常：" + Printable(a.Note) + "。計數已重新開始，期間的攻擊可能未完整彙總。\n")
	}
	return b.String()
}

// maskIPs masks every address in text (a sample) for a report.
var ipInText = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b`)

func maskIPs(text string) string {
	return ipInText.ReplaceAllStringFunc(text, func(m string) string {
		if _, err := netip.ParseAddr(m); err != nil {
			return m
		}
		return MaskIP(m)
	})
}

func alertText(g *Group, s *Surface, mask bool) string {
	var b strings.Builder
	e, found := entryOf(s, g.Entry)
	fmt.Fprintf(&b, "【Shentu 攻擊偵測】嚴重度：%s（%s）\n", severityZh[g.Severity], g.Severity)
	if g.Prefix == PrefixOverflow {
		fmt.Fprintf(&b, "溢出彙總：%d 組待推播的紀錄超過容量上限，合併在這裡\n", g.Merged)
	}
	if g.ClockSkew {
		b.WriteString("時鐘異常：這組紀錄的時間晚於主機現在的時間（時鐘曾被調回），請檢查主機時間\n")
	}
	b.WriteString("漏洞：" + Printable(vulnText(g, e, found)) + "\n")
	b.WriteString("等級：" + levelZh[g.Level] + "\n")
	if g.Success != "" {
		b.WriteString("成功跡象：" + Printable(g.Success) + "\n")
	}
	var why []string
	if g.KEV {
		why = append(why, "列在 CISA KEV（已知遭實際利用）")
	}
	if found && strings.EqualFold(e.Severity, "critical") {
		why = append(why, "漏洞本身為嚴重等級")
	}
	if g.Campaign {
		why = append(why, "同一個 IP 在 24 小時內嘗試了 3 個以上不同漏洞（campaign）")
	}
	if len(why) > 0 {
		b.WriteString("加重原因：" + strings.Join(why, "；") + "\n")
	}
	fmt.Fprintf(&b, "次數：%d 次（首次 %s，最後 %s）\n", g.Count, g.First.Local().Format(time.DateTime), g.Last.Local().Format(time.DateTime))
	ips := make([]string, len(g.IPs))
	for i, ip := range g.IPs {
		if ips[i] = Printable(ip); mask {
			ips[i] = MaskIP(ip)
		}
	}
	src := strings.Join(ips, "、")
	if more := g.IPsSeen - len(g.IPs); more > 0 {
		src += fmt.Sprintf("（另有 %d 個", more)
		if len(g.Seen) >= MaxGroupSeen {
			src += "以上"
		}
		src += "）"
	}
	network := Printable(g.Prefix)
	switch {
	case g.Prefix == "*":
		network = "不分來源，依 sink 彙總"
	case g.Prefix == PrefixOverflow:
		network = "多個網段（溢出彙總）"
	case mask:
		network = MaskIP(strings.SplitN(g.Prefix, "/", 2)[0])
	}
	fmt.Fprintf(&b, "來源 IP（共 %d 個，網段 %s）：%s\n", g.IPsSeen, network, src)
	if len(g.Samples) > 0 {
		b.WriteString("樣本（敏感參數已遮罩）：\n")
		for _, x := range g.Samples {
			x = Printable(x)
			if mask {
				x = maskIPs(x)
			}
			b.WriteString("  " + x + "\n")
		}
	}
	if len(g.ForwardedFor) > 0 {
		xs := g.ForwardedFor
		if mask {
			xs = make([]string, len(g.ForwardedFor))
			for i, x := range g.ForwardedFor {
				parts := strings.Split(x, ",")
				for j, p := range parts {
					parts[j] = MaskIP(strings.TrimSpace(p))
				}
				xs[i] = strings.Join(parts, ", ")
			}
		}
		for i := range xs {
			xs[i] = Printable(xs[i])
		}
		b.WriteString(NoteXFF + "：" + strings.Join(xs, "；") + "\n")
	}
	if g.Unverified {
		b.WriteString("來源可信度：未驗證。" + Printable(strings.Join(g.Reasons, "；")) + "\n")
	} else {
		b.WriteString("來源可信度：已驗證（受信任的記錄檔，IP 取自連線位址）\n")
	}
	var marks []string
	for _, m := range []struct {
		on   bool
		text string
	}{
		{g.Cut, "請求或記錄行被截斷"},
		{g.Suspicious, "記錄行格式可疑（只能從行尾切開）"},
		{g.Ambiguous, "記錄行有多種解讀"},
		{g.Encoded, "使用了規避用的編碼"},
		{g.TimedOut, "比對時間超過上限"},
	} {
		if m.on {
			marks = append(marks, m.text)
		}
	}
	if len(marks) > 0 {
		b.WriteString("標記：" + strings.Join(marks, "、") + "\n")
	}
	if g.Level == LevelUnknown {
		classes := "未知類型的攻擊內容"
		if len(g.HiddenClasses) > 0 {
			classes = strings.Join(g.HiddenClasses, "、")
		}
		sink := g.Entry
		if sink == "" {
			sink = "（主機上沒有已知的 sink）"
		}
		fmt.Fprintf(&b, "無法判定：請求被截斷，可能藏有 %s；相關 sink：%s\n", classes, Printable(sink))
	}
	b.WriteString("說明：" + RoutesMeaningZh + "。" + NoRoutesMeaningZh + "。\n")
	if g.Unverified {
		b.WriteString("封鎖：" + NoTelegramUnblock + "\n")
	} else if g.Level != LevelUnknown && g.Level != LevelRoute {
		b.WriteString("封鎖：只會針對單一 IP，不會封整個網段\n")
	}
	return b.String()
}

func entryOf(s *Surface, id string) (Entry, bool) {
	if s == nil || id == "" {
		return Entry{}, false
	}
	for _, e := range s.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// vulnText names the vulnerability: the CVE (and the package) for a
// package's, the sink's file and line (and rule) for code.
func vulnText(g *Group, e Entry, found bool) string {
	switch {
	case found && e.Kind == "package":
		id := e.CVE
		if id == "" {
			id = e.Advisory
		}
		return fmt.Sprintf("%s（套件 %s %s）", id, e.Package, e.Version)
	case found && e.Kind == "code":
		return fmt.Sprintf("程式碼 sink %s:%d（規則 %s）", e.Path, e.Line, e.Rule)
	case g.CVE != "":
		return g.CVE
	case g.File != "":
		return fmt.Sprintf("程式碼 sink %s:%d", g.File, g.Line)
	case g.Entry != "":
		return g.Entry
	}
	return "（未對應到主機上的漏洞）"
}

// MaskIP is an address for a report others may read: an IPv4 address's
// first two parts (203.0.x.x), an IPv6 address's first 32 bits
// (2001:db8:x:x:...); anything else wholly masked.
func MaskIP(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "x.x.x.x"
	}
	a = a.Unmap()
	if a.Is4() {
		v := a.As4()
		return fmt.Sprintf("%d.%d.x.x", v[0], v[1])
	}
	v := a.As16()
	return fmt.Sprintf("%x:%x:x:x:x:x:x:x", uint16(v[0])<<8|uint16(v[1]), uint16(v[2])<<8|uint16(v[3]))
}
