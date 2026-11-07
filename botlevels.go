package main

// The four ranges of Telegram interaction ([bot] interaction, answers, confirm,
// protection), each a level from 1 (safest) to 4. Levels are read from the config
// file on the server only, so they can be raised only by someone who can log in
// there; every change is logged and notified. /lockdown works at every level.

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/tools"
)

var levelNames = [4][4][2]string{ // [range][level-1] {English, Chinese}
	{{"notifications only", "只收通知"}, {"questions", "問答"}, {"simple actions (block/unblock IPs)", "簡單操作（封鎖、解除封鎖 IP）"}, {"all control tools", "所有權限"}},
	{{"problem or not", "只說有沒有事"}, {"summary", "摘要"}, {"full, deleted after 24h", "完整，24 小時後刪除"}, {"full, kept", "完整並保留"}},
	{{"approve on the server", "到伺服器確認"}, {"✅ + one-time code", "✅ 加動態密碼"}, {"✅ only", "按 ✅ 就好"}, {"none", "不用確認"}},
	{{"strict", "嚴格"}, {"standard", "標準"}, {"loose", "寬鬆"}, {"off", "關閉"}},
}

var rangeNames = [4][2]string{{"interaction", "互動能力"}, {"answers", "回答內容"}, {"confirm", "操作確認"}, {"protection", "帳號保護"}}

func botLevels(cfg *Config) [4]int {
	return [4]int{cfg.Bot.Interaction, cfg.Bot.Answers, cfg.Bot.Confirm, cfg.Bot.Protection}
}

// describeLevels is one line per range, for status output and notifications.
func describeLevels(l [4]int, zh bool) string {
	i := 0
	if zh {
		i = 1
	}
	var b strings.Builder
	for r := 0; r < 4; r++ {
		fmt.Fprintf(&b, "%s: %d (%s)\n", rangeNames[r][i], l[r], levelNames[r][l[r]-1][i])
	}
	return b.String()
}

// noteLevelChanges compares the configured levels with the ones the service last
// ran with, and reports every change (raises are warnings).
func (b *bot) noteLevelChanges(ctx context.Context) {
	now := botLevels(b.cfg)
	var before [4]int
	withBotState(b.cfg.StateDir, func(s *botState) error {
		before = s.Levels
		s.Levels = now
		return nil
	})
	if before == [4]int{} {
		before = [4]int{1, 2, 2, 2} // first start: compare with the defaults
	}
	if before == now {
		return
	}
	raised := false // in every range a higher level is less strict
	for r := range now {
		raised = raised || now[r] > before[r]
	}
	sev := "info"
	if raised {
		sev = "warning"
	}
	b.log.write(logEntry{Actor: "bot", Tool: "bot_levels", Args: fmt.Sprint(before, " -> ", now), OK: true})
	tools.Notify(ctx, b.env, b.t("levels_changed"), describeLevels(now, b.zh())+b.t("levels_hint"), sev)
}

// answerRule is added to the system prompt for answer levels 1 and 2; maxAnswer caps
// the reply length in code, whatever the model writes.
func answerRule(level int, zh bool) string {
	switch level {
	case 1:
		return "\nThis reply goes to a phone chat. Answer in at most two sentences: is there a problem, and how serious. Do not include IP addresses, user names, paths, commands or log lines. End with: details: run `sudo shentu chat` on the server."
	case 2:
		return "\nThis reply goes to a phone chat. Give a short summary in at most 8 lines: what you found and what to do. Do not quote raw log lines, configuration files or long lists."
	}
	return ""
}

func maxAnswer(level int) int {
	switch level {
	case 1:
		return 400
	case 2:
		return 1500
	}
	return 0
}

// --- one-time codes (TOTP, RFC 6238: SHA-1, 30 s, 6 digits) ---

func totpCode(secret []byte, counter uint64) string {
	m := hmac.New(sha1.New, secret)
	binary.Write(m, binary.BigEndian, counter)
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// totpCheck accepts the code for now ±30 s, and never the same time step twice.
func totpCheck(secretB32, code string, last uint64, now time.Time) (uint64, bool) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil || len(code) != 6 {
		return 0, false
	}
	c := uint64(now.Unix() / 30)
	for _, step := range []uint64{c - 1, c, c + 1} {
		if step > last && hmac.Equal([]byte(totpCode(secret, step)), []byte(code)) {
			return step, true
		}
	}
	return 0, false
}

// botTOTP enrolls an authenticator app: `shentu bot totp` on the server.
func botTOTP(cfg *Config, in *bufio.Reader, out io.Writer) error {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	host, _ := os.Hostname()
	fmt.Fprintf(out, "Add this key to your authenticator app (Google Authenticator, 1Password, …):\n\n    %s\n\nor as a link: otpauth://totp/Shentu:%s?secret=%s&issuer=Shentu\n\nThen type the 6-digit code it shows: ", secret, host, secret)
	line, _ := in.ReadString('\n')
	step, ok := totpCheck(secret, strings.TrimSpace(line), 0, time.Now())
	if !ok {
		return errors.New("that code does not match; run `sudo shentu bot totp` again")
	}
	return withBotState(cfg.StateDir, func(s *botState) error {
		s.TOTPSecret, s.TOTPLast = secret, step
		fmt.Fprintln(out, "Saved. Actions from Telegram now ask for this code (confirm = 2).")
		return nil
	})
}

// botApprove shows an action proposed from Telegram and lets root approve it (confirm = 1).
func botApprove(cfg *Config, in *bufio.Reader, out io.Writer) error {
	var p *pendingAction
	withBotState(cfg.StateDir, func(s *botState) error { p = s.Action; return nil })
	if p == nil || time.Now().After(p.Expires) || p.Decided {
		fmt.Fprintln(out, "No action is waiting for approval.")
		return nil
	}
	fmt.Fprintf(out, "Proposed from Telegram at %s:\n    %s: %s\nRun it? [y/N] ", p.At.Format("15:04:05"), p.Tool, printable(p.Preview))
	line, _ := in.ReadString('\n')
	yes := strings.EqualFold(strings.TrimSpace(line), "y")
	return withBotState(cfg.StateDir, func(s *botState) error {
		if s.Action != nil && s.Action.Nonce == p.Nonce {
			s.Action.Decided, s.Action.Approved = true, yes
		}
		return nil
	})
}

// hasNetAdmin reports whether this process may change the firewall (CAP_NET_ADMIN,
// bit 12). The bot unit grants it only through the drop-in that setup writes for
// interaction 3 and 4.
func hasNetAdmin() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && caps&(1<<12) != 0
		}
	}
	return false
}

const netAdminDropIn = "/etc/systemd/system/shentu-bot.service.d/actions.conf"

// writeActionDropIn gives the bot service CAP_NET_ADMIN, or takes it away again.
func writeActionDropIn(enable bool) error {
	if !enable {
		if err := os.Remove(netAdminDropIn); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll("/etc/systemd/system/shentu-bot.service.d", 0o755); err != nil {
		return err
	}
	text := "# Written by `shentu setup` for [bot] interaction = 3 or 4: lets block_ip change the firewall.\n[Service]\nCapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN\n"
	return os.WriteFile(netAdminDropIn, []byte(text), 0o644)
}

// openNow says whether strict protection allows answering at this hour (08–20 local).
func openNow(level int, now time.Time) bool {
	return level != 1 || now.Hour() >= 8 && now.Hour() < 20
}

const strictDailyLimit = 50
