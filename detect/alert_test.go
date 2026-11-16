package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// P4 part 4: the alert's and the report's text.

func alertSurface() *Surface {
	s := Build([]CodeSink{{Rule: "php-sqli", CWE: "CWE-89", Severity: "critical", Path: "app/x.php", Line: 12,
		Routes: []engine.RouteRef{{Model: "m", Framework: "laravel", Method: "get", Pattern: "/marker/{id}", File: "routes/web.php", Line: 3}}}},
		[]PackageVuln{{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "marker/pkg", Version: "1.0", ID: "CVE-2099-0007", KEV: true, KEVCVE: "CVE-2099-0007"}})
	return &s
}

func alertGroup(entry, level string, verified bool) *Group {
	a := newAttacks()
	var g *Group
	for i, ip := range []string{"203.0.113.5", "203.0.113.6"} {
		x := Attempt{IP: ip, Entry: entry, Level: level, Time: t0.Add(time.Duration(i) * time.Minute), Verified: verified,
			Sample: "GET /marker/5?q=marker-one&" + "pass" + "word=[REDACTED]", Severe: true}
		if !verified {
			x.Reason = "marker reason"
		}
		g = a.Add(x, t0)
	}
	return g
}

func TestAlertText(t *testing.T) {
	s := alertSurface()
	code := "code:php-sqli:app/x.php:12"
	txt := AlertText(alertGroup(code, LevelPayload, true), s)
	for _, want := range []string{"嚴重度：嚴重（critical）", "程式碼 sink app/x.php:12（規則 php-sqli）", "L2：", "次數：2 次", "203.0.113.5、203.0.113.6",
		"203.0.113.0/24", "樣本（敏感參數已遮罩）", "[REDACTED]", "來源可信度：已驗證", RoutesMeaningZh, NoRoutesMeaningZh, "只會針對單一 IP"} {
		if !strings.Contains(txt, want) {
			t.Errorf("alert lacks %q:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, NoTelegramUnblock) {
		t.Errorf("verified, but no unblock from Telegram said:\n%s", txt)
	}
	// Unverified: the reason, and no unblock from Telegram.
	txt = AlertText(alertGroup(code, LevelPayload, false), s)
	for _, want := range []string{"來源可信度：未驗證", "marker reason", NoTelegramUnblock, "嚴重度：中"} {
		if !strings.Contains(txt, want) {
			t.Errorf("unverified alert lacks %q:\n%s", want, txt)
		}
	}
	// A package's CVE, KEV.
	pkg := "pkg:CVE-2099-0007:marker/pkg@1.0#/srv/composer.lock"
	g := alertGroup(pkg, LevelPayload, true)
	g.KEV = true
	if txt = AlertText(g, s); !strings.Contains(txt, "CVE-2099-0007（套件 marker/pkg 1.0）") || !strings.Contains(txt, "CISA KEV") {
		t.Errorf("package alert:\n%s", txt)
	}
	// Marks, L3, campaign, dropped groups.
	g = alertGroup(code, LevelSuccess, true)
	g.Cut, g.Suspicious, g.Ambiguous, g.Encoded, g.Campaign, g.Success = true, true, true, true, true, "marker evidence"
	txt = AlertText(g, s)
	for _, want := range []string{"L3：", "成功跡象：marker evidence", "請求或記錄行被截斷", "記錄行格式可疑", "多種解讀", "規避用的編碼", "campaign"} {
		if !strings.Contains(txt, want) {
			t.Errorf("alert lacks %q:\n%s", want, txt)
		}
	}
}

func TestAlertUnknown(t *testing.T) {
	a := newAttacks()
	var g *Group
	for i := 0; i < UnknownNotifyAt; i++ {
		g = a.Add(Attempt{IP: "198.51.100.9", Entry: "code:php-sqli:app/x.php:12", Level: LevelUnknown, Time: t0, Verified: true,
			Unknown: true, Cut: true, HiddenClasses: []string{"path", "sqli"}}, t0)
	}
	txt := AlertText(g, alertSurface())
	for _, want := range []string{"無法判定：請求被截斷，可能藏有 path、sqli；相關 sink：code:php-sqli:app/x.php:12", "不分來源，依 sink 彙總", RoutesMeaningZh} {
		if !strings.Contains(txt, want) {
			t.Errorf("unknown alert lacks %q:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "只會針對單一 IP") {
		t.Errorf("a block offered for an undetermined request:\n%s", txt)
	}
}

// The report's copy masks every address.
func TestReportMasksAddresses(t *testing.T) {
	g := alertGroup("code:php-sqli:app/x.php:12", LevelPayload, true)
	txt := ReportText(g, alertSurface())
	if strings.Contains(txt, "203.0.113.5") || strings.Contains(txt, "203.0.113.0") || !strings.Contains(txt, "203.0.x.x") {
		t.Errorf("report:\n%s", txt)
	}
	for in, want := range map[string]string{"203.0.113.5": "203.0.x.x", "::ffff:198.51.100.1": "198.51.x.x", "2001:db8:1:2::9": "2001:db8:x:x:x:x:x:x", "host.example": "x.x.x.x"} {
		if got := MaskIP(in); got != want {
			t.Errorf("MaskIP(%s) = %s, want %s", in, got, want)
		}
	}
}
