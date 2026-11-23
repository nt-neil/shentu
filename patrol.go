package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/tools"
)

// A finding is one anomaly from the deterministic checks. Key is used to
// avoid alerting about the same thing again within the cooldown.
type finding struct {
	Key      string `json:"key"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Evidence any    `json:"evidence,omitempty"`
	// zh is Summary in Chinese, for the report with a Chinese setting;
	// not saved: "" (or a finding read back) falls back to Summary.
	zh string
}

// newFinding is a finding whose summary is report text key with args, in
// English and in Chinese.
func newFinding(key, severity string, evidence any, text string, args ...any) finding {
	return newFindingIn(key, severity, evidence, text, args, args)
}

// newFindingIn is newFinding with values said differently in each language,
// such as a list joined with ", " in English and "、" in Chinese.
func newFindingIn(key, severity string, evidence any, text string, en, zh []any) finding {
	return finding{key, severity, fmt.Sprintf(dt(false, text), en...), evidence, fmt.Sprintf(dt(true, text), zh...)}
}

// procFinding, sharedKeyFinding and preloadFinding list their values with
// ", " in English and "、" in Chinese.
func procFinding(p tools.Proc) finding {
	return newFindingIn(fmt.Sprintf("proc:%s:%s", p.Exe, p.Cmdline), "critical", p, "f_proc",
		[]any{p.PID, strings.Join(p.Flags, ", "), p.Cmdline}, []any{p.PID, strings.Join(p.Flags, "、"), p.Cmdline})
}

func sharedKeyFinding(k tools.SharedKey) finding {
	return newFindingIn("sharedkey:"+k.Fingerprint, "warning", k, "f_sharedkey",
		[]any{k.Fingerprint, strings.Join(k.Users, ", ")}, []any{k.Fingerprint, strings.Join(k.Users, "、")})
}

func preloadFinding(libs []string) finding {
	return newFindingIn("preload:"+strings.Join(libs, ","), "critical", libs, "f_preload",
		[]any{strings.Join(libs, ", ")}, []any{strings.Join(libs, "、")})
}

// said is the finding's summary as the report says it.
func (f finding) said(zh bool) string {
	if zh && f.zh != "" {
		return f.zh
	}
	return f.Summary
}

// state is kept in <state_dir>/state.json.
type state struct {
	Alerted map[string]time.Time `json:"alerted"`
	Ports   map[string]bool      `json:"ports"` // baseline of listening ports
	// PortsV is the baseline's version, set once a read was made into it:
	// 0 in a state from before it (N-177-2).
	PortsV  int               `json:"ports_v,omitempty"`
	LastRun time.Time         `json:"last_run"`
	Profile tools.SiteProfile `json:"profile"` // baseline from the last survey
}

func loadState(dir string) *state {
	s := &state{Alerted: map[string]time.Time{}}
	if b, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		json.Unmarshal(b, s)
	}
	if s.Alerted == nil {
		s.Alerted = map[string]time.Time{}
	}
	return s
}

func (s *state) save(dir string) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}

// checks runs the deterministic checks. No LLM is involved, so alerts still
// work when the model is down.
// replaceOrAppend puts each of add in place of a finding with the same key (the hourly webshell
// check and the daily code audit report one file), so the report lists it once, with the audit's
// detail; the others are appended.
func replaceOrAppend(all, add []finding) []finding {
	at := make(map[string]int, len(all)+len(add))
	for i, f := range all {
		if _, ok := at[f.Key]; !ok {
			at[f.Key] = i
		}
	}
	for _, f := range add {
		if i, ok := at[f.Key]; ok {
			all[i] = f
			continue
		}
		at[f.Key] = len(all)
		all = append(all, f)
	}
	return all
}

// sshFindings turns an SSH login summary into findings, one per source at
// or over threshold. why is a Not checked line when the logs could not be read
// in full (an error, or a log cut short or unreadable): then no finding is no
// proof that there were no failed logins.
func sshFindings(r map[string]any, err error, threshold int, zh bool) (out []finding, why string) {
	if err != nil {
		return nil, fmt.Sprintf(dt(zh, "ssh_failed"), cutLine(mask(err.Error())))
	}
	note, noteZh := "", ""
	if v, _ := r["verified"].(bool); !v {
		note, noteZh = dt(false, "f_ssh_text"), dt(true, "f_ssh_text")
	}
	sources, _ := r["sources"].([]tools.SSHSource)
	for _, s := range sources {
		if n := s.Failed + s.InvalidUser; n >= threshold {
			sev := "warning"
			if s.Accepted > 0 {
				sev = "critical"
			}
			out = append(out, finding{"ssh:" + s.IP, sev,
				fmt.Sprintf(dt(false, "f_ssh"), n, s.IP, s.Accepted, note), s, fmt.Sprintf(dt(true, "f_ssh"), n, s.IP, s.Accepted, noteZh)})
		}
	}
	if c, _ := r["complete"].(bool); !c {
		// The reason is the error, else what was read (source says why it is
		// not enough: an empty journal with no text log to confirm it, ...).
		detail, _ := r["error"].(string)
		if detail == "" {
			detail, _ = r["source"].(string)
		}
		if detail == "" {
			detail = dt(zh, "ssh_cut")
		}
		detail = cutLine(mask(detail))
		if u, _ := r["unsupported"].(bool); u {
			return out, fmt.Sprintf(dt(zh, "ssh_failed"), detail)
		}
		advice := ""
		if p, _ := r["permission"].(bool); p { // root helps only when rights were missing
			advice = dt(zh, "ssh_root")
		}
		why = fmt.Sprintf(dt(zh, "ssh_partial"), detail, advice)
	}
	return out, why
}

// dnsHint says, after an error, that a failed name lookup is a DNS problem on
// this host (the resolver in /etc/resolv.conf), not the service's; "" otherwise.
func dnsHint(err error, zh bool) string {
	var d *net.DNSError
	if !errors.As(err, &d) {
		return ""
	}
	return fmt.Sprintf(dt(zh, "vuln_dns"), mask(d.Name))
}

// uncheckedSection lists, at the end of a report, the checks that could not
// tell (a file they need could not be read, e.g. when not run as root), so a
// silent part is not read as a clean one. "" when there are none.
func uncheckedSection(risks []tools.Risk, zh bool) string {
	var b strings.Builder
	for _, r := range risks {
		if tools.Unchecked(r) {
			fmt.Fprintf(&b, "- %q\n", mask(r.Summary))
		}
	}
	if b.Len() == 0 {
		return ""
	}
	as := dt(zh, "perm_root")
	if runtime.GOOS == "windows" {
		as = dt(zh, "perm_win")
	}
	return fmt.Sprintf(dt(zh, "perm_head"), as) + b.String()
}

// notCheckedSection lists what the code audit could not tell (a web
// root's ACL on Windows), so it is not read as checked. "" when nothing.
func notCheckedSection(items []string, zh bool) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(dt(zh, "audit_head"))
	for _, it := range items {
		fmt.Fprintf(&b, "- %q\n", mask(it))
	}
	return b.String()
}

// uncheckedVulns says, for the daily report, when the vulnerability check of
// what failed (an advisory feed offline: ALAS, OSV) or covered only part
// ("partial"): "no known vulnerabilities" must not stand for "not checked".
// The same goes for the CISA KEV list (none on it must not read as "none
// exploited"), lock files that could not be checked, and ecosystems OSV does
// not carry.
func uncheckedVulns(what string, r map[string]any, err error, zh bool) string {
	if err != nil {
		return fmt.Sprintf(dt(zh, "vuln_failed"), what, cutLine(mask(err.Error())), dnsHint(err, zh))
	}
	var lines []string
	if p, ok := r["partial"]; ok {
		lines = append(lines, fmt.Sprintf(dt(zh, "vuln_partly"), cutLine(mask(fmt.Sprint(p)))))
	}
	// With no vulnerability found there is nothing to look up in KEV.
	if n, _ := r["total_vulns"].(int); n > 0 {
		if k, _ := r["kev"].(string); strings.Contains(k, "unavailable") {
			lines = append(lines, fmt.Sprintf(dt(zh, "vuln_nokev"), cutLine(mask(k))))
		} else if u, _ := r["kev_unchecked"].(int); u > 0 {
			lines = append(lines, fmt.Sprintf(dt(zh, "vuln_kevleft"), u))
		}
	}
	if files, ok := r["files"].([]tools.AppResult); ok {
		// One line per distinct error as shown (cut), at most uncheckedFiles
		// paths in all and uncheckedErrors lines; the rest are counted.
		byErr := map[string][]string{}
		var order []string
		for _, f := range files {
			if f.Error == "" {
				continue
			}
			e := hostenv.CutString(mask(f.Error), 80)
			if _, seen := byErr[e]; !seen {
				order = append(order, e)
			}
			byErr[e] = append(byErr[e], f.Path)
		}
		listed, skipped := 0, 0
		for i, e := range order {
			if i >= uncheckedErrors {
				skipped += len(byErr[e])
				continue
			}
			paths := byErr[e]
			show := paths[:min(len(paths), max(uncheckedFiles-listed, 0))]
			listed += len(show)
			names := make([]string, len(show))
			for i, p := range show {
				names[i] = mask(p)
			}
			line := fmt.Sprintf(dt(zh, "vuln_file"), e, strings.Join(names, ", "))
			if more := len(paths) - len(show); more > 0 {
				line += fmt.Sprintf(dt(zh, "vuln_filemore"), more)
			}
			lines = append(lines, cutLine(line))
		}
		if skipped > 0 {
			lines = append(lines, fmt.Sprintf(dt(zh, "vuln_otherfiles"), skipped))
		}
	}
	if nq, ok := r["ecosystems_not_queried"].([]string); ok {
		for _, e := range nq {
			lines = append(lines, fmt.Sprintf(dt(zh, "vuln_noeco"), cutLine(mask(e))))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return fmt.Sprintf(dt(zh, "vuln_head"), what) + strings.Join(lines, "\n") + "\n"
}

// uncheckedFiles caps the lock file paths the unchecked section lists;
// maxUncheckedLine the length of one line of it.
const (
	uncheckedFiles   = 10
	uncheckedErrors  = 10 // distinct error lines
	maxUncheckedLine = 200
)

// cutLine keeps a report line to maxUncheckedLine bytes.
func cutLine(s string) string { return hostenv.CutString(s, maxUncheckedLine) }

// uncheckedConfigs lists the web server configuration files the code audit
// could not read: the sites they serve were audited as plain folders.
func uncheckedConfigs(unread []string, zh bool) string {
	if len(unread) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(dt(zh, "conf_head"))
	for _, u := range unread {
		fmt.Fprintf(&b, "- %q\n", mask(u))
	}
	return b.String()
}

// unparsedLinesMax is how many unparsed line numbers one warning lists.
const unparsedLinesMax = 20

// unparsedKeysFinding is one warning for an authorized_keys file's lines that
// are neither a key nor a comment: the first unparsedLinesMax line numbers,
// then how many in all.
func unparsedKeysFinding(k tools.KeyFile) finding {
	lines := make([]string, 0, unparsedLinesMax)
	for _, l := range k.Unparsed[:min(len(k.Unparsed), unparsedLinesMax)] {
		lines = append(lines, strconv.Itoa(l))
	}
	more, moreZh := "", ""
	if n := len(k.Unparsed); n > unparsedLinesMax {
		more = fmt.Sprintf(dt(false, "f_unparsed_more"), n-unparsedLinesMax, n)
		moreZh = fmt.Sprintf(dt(true, "f_unparsed_more"), n-unparsedLinesMax, n)
	}
	return newFindingIn("authorized_key_unparsed:"+k.Path, "warning", nil, "f_unparsed",
		[]any{k.Path, strings.Join(lines, ", "), more}, []any{k.Path, strings.Join(lines, "、"), moreZh})
}

// patrolListMax is how many findings one patrol report lists.
const patrolListMax = 50

// mostSevere keeps the n most severe findings, critical first, in their order.
func mostSevere(fs []finding, n int) []finding {
	if len(fs) <= n {
		return fs
	}
	rank := map[string]int{"critical": 0, "warning": 1}
	out := slices.Clone(fs)
	sort.SliceStable(out, func(i, j int) bool {
		ri, ok := rank[out[i].Severity]
		if !ok {
			ri = 2
		}
		rj, ok := rank[out[j].Severity]
		if !ok {
			rj = 2
		}
		return ri < rj
	})
	return out[:n]
}

// codeAuditFindings turns the code audit into patrol findings. An injection
// finding is pushed only when its rule's tier is "alert"; info-tier findings, and
// the note about files the rules could not finish, stay in the tool's output and
// chat.
func codeAuditFindings(audit tools.CodeAudit) []finding {
	var out []finding
	for _, f := range audit.Findings {
		if f.Kind == "injection" && f.Tier != "alert" || f.Kind == "audit" || f.Kind == "webroot_acl_unknown" { // "audit": the audit's own summaries, below; ACL unknown: Not checked
			continue
		}
		key := fmt.Sprintf("code:%s:%s:%d", f.Kind, f.Path, f.Line)
		switch f.Kind {
		case "webshell":
			key = "webshell:" + f.Path // the same key as the hourly file check, so it is told once
		case "injection":
			key += ":" + f.Rule
		}
		where := f.Path
		if f.Line > 0 {
			where = fmt.Sprintf("%s line %d", f.Path, f.Line)
		}
		detail := f.Detail
		if f.Rule != "" {
			detail = fmt.Sprintf("%s (%s, rule %s)", f.Detail, f.CWE, f.Rule)
		}
		out = append(out, finding{key, f.Severity, fmt.Sprintf("%s: %s; fix: %s", where, detail, f.Fix), f, ""})
	}
	// An audit that did not check everything, or listed only part of what it
	// found, says so: silence would read as nothing found.
	for _, f := range audit.Findings {
		if f.Kind != "audit" {
			continue
		}
		key := "code:audit:truncated"
		if strings.Contains(f.Detail, "unfinished") {
			key = "code:audit:unfinished"
		}
		out = append(out, finding{key, "warning", fmt.Sprintf("code audit: %s; fix: %s", f.Detail, f.Fix), f, ""})
	}
	return out
}

// checks returns the findings, and a Not checked line for the SSH logins
// when their logs could not be read in full ("" otherwise).
func checks(ctx context.Context, cfg *Config, env *tools.Env, st *state, daily bool) (out []finding, sshUnchecked string) {
	// Survey first: risks that follow from the configuration, and changes since the baseline.
	surveyEnv := *env
	if !daily {
		surveyEnv.AppPaths = nil // walking app folders for lock files is a daily job
	}
	prof := tools.Survey(ctx, &surveyEnv)
	if !daily {
		prof.Stacks, prof.Lockfiles = st.Profile.Stacks, st.Profile.Lockfiles
	}
	for _, r := range append(prof.Risks, tools.Drift(st.Profile, prof)...) {
		if r.Severity != "info" {
			out = append(out, finding{r.Key, r.Severity, r.Summary, nil, ""})
		}
	}
	st.Profile = prof
	since := st.LastRun
	if since.IsZero() || time.Since(since) > 24*time.Hour {
		since = time.Now().Add(-1 * time.Hour)
	}

	// On Windows logon failures come from the survey's checks (auth.bruteforce);
	// a second alert for the same source would say "SSH" for RDP or SMB.
	if runtime.GOOS != "windows" {
		r, err := tools.SSHSummary(ctx, env, time.Now().Add(-1*time.Hour), "")
		f, why := sshFindings(r, err, cfg.Patrol.SSHThreshold, isZh(cfg))
		out = append(out, f...)
		sshUnchecked = why
	}

	if ports, err := tools.ListeningPorts(); err == nil {
		out = append(out, portFindings(st, ports)...)
	} // else the survey's services:unreadable says it is not checked (N-177-1)

	pf, why := procFindings(patrolProcesses(false))
	out = append(out, pf...)
	sshUnchecked += why

	acc := tools.AccountsAudit()
	sshUnchecked += accountsUnchecked(acc)
	for _, u := range acc.UID0 {
		if u != "root" {
			out = append(out, newFinding("uid0:"+u, "critical", nil, "f_uid0", u))
		}
	}
	for _, k := range acc.KeyFiles {
		if k.Modified.After(since) {
			out = append(out, newFinding(fmt.Sprintf("keys:%s:%d", k.Path, k.Modified.Unix()), "warning", k, "f_keys", k.Path, k.Keys))
		}
	}
	out = append(out, keyFileFindings(acc.KeyFiles)...)
	for _, k := range acc.SharedKeys {
		out = append(out, sharedKeyFinding(k))
	}
	if len(acc.Preload) > 0 {
		out = append(out, preloadFinding(acc.Preload))
	}
	for _, m := range acc.UnpackagedPAM {
		out = append(out, newFinding("pam:"+m, "warning", m, "f_pam", m, m))
	}

	if r, err := tools.FileChanges(ctx, env.WatchPaths, since); err == nil {
		for _, f := range r["files"].([]tools.Changed) {
			if len(f.Webshell) > 0 {
				out = append(out, newFinding("webshell:"+f.Path, "critical", f, "f_webshell", f.Path))
			}
		}
		sshUnchecked += fileChangesUnchecked(r)
	}

	for _, c := range tools.CertExpiry(ctx, env.CertTargets) {
		if c.Error == "" && c.DaysLeft <= 14 {
			out = append(out, newFinding("cert:"+c.Target, "warning", c, "f_cert", c.Target, c.DaysLeft))
		}
	}
	return out, sshUnchecked
}

// patrol runs once (from a systemd timer): checks → LLM explanation → notify.
// With daily set it always reports, using the daily-patrol skill.
func patrol(ctx context.Context, cfg *Config, env *tools.Env, daily, dryRun bool) error {
	if err := ensureStateDir(cfg.StateDir); err != nil {
		return err
	}
	st := loadState(cfg.StateDir)
	zh := isZh(cfg)
	all, sshUnchecked := checks(ctx, cfg, env, st, daily)
	unchecked := uncheckedSection(st.Profile.Risks, zh) + sshUnchecked // listed in every report, never pushed
	if daily {
		// Once a day: installed packages with vulnerabilities that are being exploited now.
		r, osSurface, err := tools.PackageVulnsSurface(ctx, env.HTTP)
		var partial []string // what the vulnerability surface lacks today
		osFailed := err != nil
		if osFailed {
			partial = append(partial, "作業系統套件（"+err.Error()+"）")
		} else if p, _ := r["partial"].(string); p != "" {
			partial = append(partial, "作業系統套件只查了一部分（"+p+"）")
		}
		if n, _ := r["surface_cves_missing"].(int); n > 0 {
			partial = append(partial, fmt.Sprintf("作業系統套件有 %d 筆 advisory 查不到對應的 CVE：以 CVE 寫的簽章對不到它們", n))
		}
		if len(osSurface) > 0 && !sig.ComparesVersions(osSurface[0].Ecosystem) {
			partial = append(partial, osSurface[0].Ecosystem+" 的套件版本沒有比較器：簽章對到的 CVE 一律列為版本未知（VersionUnknown），不會依版本排除")
		}
		unchecked += uncheckedVulns(dt(zh, "vuln_os"), r, err, zh)
		if err == nil {
			list, _ := r["actively_exploited"].([]tools.Exploit)
			for _, e := range list {
				all = append(all, newFinding("kev:"+e.Package+":"+e.CVE, "critical", e, "f_kev_os", e.Package, e.Version, e.CVE, e.Name, r["upgrade_command"]))
			}
		}
		// The same for application dependencies (npm, PyPI, Composer, Go, RubyGems).
		r, err = tools.AppVulns(ctx, env.HTTP, env.AppPaths)
		unchecked += uncheckedVulns(dt(zh, "vuln_app"), r, err, zh)
		var apps []tools.AppResult
		failedApps := map[string]bool{} // lock files whose check failed: their entries are yesterday's
		if err != nil {
			failedApps["*"] = true
			partial = append(partial, "應用程式相依套件（"+err.Error()+"）")
		}
		if err == nil {
			apps, _ = r["files"].([]tools.AppResult)
			for _, f := range apps {
				if f.Error != "" { // OSV unreachable for this file: AppVulns says so per file, not as its error
					failedApps[f.Path] = true
					partial = append(partial, "應用程式相依套件 "+f.Path+"（"+f.Error+"）")
				}
			}
			for _, f := range apps {
				for _, e := range f.Exploited {
					all = append(all, newFinding("kev:"+f.Path+":"+e.Package+":"+e.CVE, "critical", e, "f_kev_app", f.Path, e.Package, e.Version, e.CVE, e.Name))
				}
			}
		}
		// The applications' own files: exposed secrets, debug mode, webshells, keys in code, injection.
		web, unread := tools.WebRootsReport()
		audit := tools.AppCodeAudit(ctx, env.AppPaths, web)
		all = replaceOrAppend(all, codeAuditFindings(audit))
		unchecked += uncheckedConfigs(unread, zh) + notCheckedSection(audit.NotChecked, zh)
		// The vulnerability surface attack detection judges by, until
		// tomorrow: saved before the report goes (a notify that fails, or
		// none configured, does not lose it); a dry run makes none.
		if dryRun {
			unchecked += dt(zh, "dry_surface")
		} else {
			unchecked += saveDailySurface(cfg, env, audit, web, apps, osSurface, failedApps, osFailed, partial, time.Now())
		}
	}
	// Attack detection: read and judged now (the daily report gets its
	// summary); its alerts go out on their own, as the detector's words,
	// after this patrol's report (deferred: whatever path it ends on).
	carry := detectCarryOver(cfg.StateDir, zh) // what the last patrol's sends could not do
	unchecked = carry + unchecked
	dr := detectJudge(ctx, cfg, time.Now(), daily, dryRun)
	defer finishDetect(ctx, env, dr)
	if daily {
		unchecked += detectSection(dr.sum, zh)
		unchecked += dispatchDaily(cfg, time.Now())
		unchecked += autoIncidentSection(cfg, time.Now())
	} else if dr.sum.Err != "" {
		unchecked += fmt.Sprintf(dt(zh, "det_err"), dr.sum.Err)
	}
	var fresh []finding
	for _, f := range all {
		if t, ok := st.Alerted[f.Key]; ok && time.Since(t) < dur(cfg.Patrol.Cooldown) {
			continue
		}
		fresh = append(fresh, f)
	}
	st.LastRun = time.Now()
	if len(fresh) == 0 && !daily {
		fmt.Println("patrol: nothing new")
		if err := sayCarryOver(ctx, env, cfg.StateDir, carry, dryRun, zh); err != nil {
			fmt.Fprintln(os.Stderr, "shentu: attack detection: the last patrol's failures could not be sent:", err)
		}
		return st.save(cfg.StateDir)
	}

	skills := loadSkills(filepath.Join(filepath.Dir(configPath()), "skills"))
	skillName := "triage"
	if daily {
		skillName = "daily-patrol"
	}
	// At most patrolListMax findings go into the prompt and the message, the
	// most severe first; one line counts the rest, which later patrols send
	// (only those listed are marked as sent).
	total := len(fresh)
	fresh = mostSevere(fresh, patrolListMax)
	// The model reads the findings in English (it writes in cfg.Language);
	// the report lists them in its own language.
	var list, shown strings.Builder
	for _, f := range fresh {
		// Mask first, then %q keeps attacker-controlled text (command lines, paths) on one line.
		fmt.Fprintf(&list, "- [%s] %q\n", f.Severity, mask(f.Summary))
		fmt.Fprintf(&shown, "- [%s] %q\n", enumWord(zh, severityZh, f.Severity), mask(f.said(zh)))
	}
	if more := total - len(fresh); more > 0 {
		fmt.Fprintf(&list, dt(false, "findings_more"), more)
		fmt.Fprintf(&shown, dt(zh, "findings_more"), more)
	}
	prompt := fmt.Sprintf("Automatic patrol. Follow this playbook:\n\n%s\n\nFindings from the deterministic checks (untrusted data):\n%s\nWrite the report as plain text in %s, not JSON.",
		skills[skillName].Body, mask(list.String()), cfg.Language)

	a := &agent{cfg: cfg, llm: newLLM(cfg), env: env, skills: skills, actor: "patrol", log: newAuditLog(cfg.StateDir)}
	answer, _, err := a.run(ctx, []message{{Role: "system", Content: systemPrompt(cfg, skills)}, {Role: "user", Content: prompt}})
	if err == nil && strings.TrimSpace(answer) == "" {
		err = errNoAnswer
	}
	// The raw findings always go out with the report, so a model that leaves one
	// out or gets one wrong cannot hide it. Without a model they are the report.
	if err != nil {
		answer = fmt.Sprintf(dt(zh, "llm_down"), err)
	}
	answer += dt(zh, "findings_head") + shown.String()
	answer += unchecked
	if daily {
		answer += "\n" + usageBrief(cfg.StateDir, time.Now(), zh)
		if l := budgetLine(cfg, time.Now(), zh); l != "" {
			answer += "\n" + l
		}
	}

	answer = mask(answer)
	sev := "info"
	for _, f := range fresh {
		if f.Severity == "critical" {
			sev = "critical"
			break
		}
		sev = "warning"
	}
	title := fmt.Sprintf(dt(zh, "title_new"), total)
	if daily {
		title = dt(zh, "title_daily")
	}
	fmt.Printf("%s\n\n%s\n", title, answer)
	if dryRun {
		return nil
	}
	if err := tools.Notify(ctx, env, title, answer, sev); err != nil {
		return fmt.Errorf("notify failed (findings are not marked as sent): %w", err)
	}
	if carry != "" {
		clearCarryOver(cfg.StateDir) // said in this report
	}
	for _, f := range fresh {
		st.Alerted[f.Key] = time.Now()
	}
	return st.save(cfg.StateDir)
}

// keyFileFindings reports authorized_keys files linked outside the home and lines that are neither a key nor a comment.
func keyFileFindings(keys []tools.KeyFile) []finding {
	var out []finding
	for _, k := range keys {
		if k.SymlinkOutsideHome != "" { // before the Unparsed check: a linked file with no odd lines still warns
			out = append(out, newFinding("authorized_keys_symlink:"+k.Path, "warning", k, "f_keylink", k.Path, k.SymlinkOutsideHome, k.Keys))
		}
		if len(k.Unparsed) == 0 {
			continue
		}
		out = append(out, unparsedKeysFinding(k))
	}
	return out
}

// patrolProcesses is the patrol's process list; tests replace it.
var patrolProcesses = tools.ProcessesErr

// portsBaselineV marks a baseline made from a read (see state.PortsV).
const portsBaselineV = 1

// portFindings is the new listening ports against the baseline in st,
// which it updates. The first read makes the baseline and warns of
// nothing: no baseline, or an empty one from before PortsV (N-177-2: a
// release that read no port on macOS saved {}, and the first good read
// would have warned of every port), once. After that an empty baseline is
// a host with no port, and the first port opened on it is new.
func portFindings(st *state, ports []tools.Port) (out []finding) {
	first := st.Ports == nil || st.PortsV < portsBaselineV && len(st.Ports) == 0
	if st.Ports == nil {
		st.Ports = map[string]bool{}
	}
	st.PortsV = portsBaselineV
	ollama, hasOllama := tools.UIDOf("ollama")
	for _, p := range ports {
		// The local model runtime opens a new loopback port each time it loads a model.
		// Only the ollama account running Ollama's own root-owned binaries is skipped.
		if hasOllama && p.UID == ollama && net.ParseIP(p.Addr).IsLoopback() &&
			(p.Exe == "/usr/local/bin/ollama" || strings.HasPrefix(p.Exe, "/usr/local/lib/ollama/")) {
			continue
		}
		// avahi-daemon opens a random UDP port for unicast mDNS queries on every start;
		// only its fixed port 5353 is part of the baseline.
		if strings.HasPrefix(p.Proto, "udp") && p.Exe == "/usr/sbin/avahi-daemon" && p.Port != 5353 {
			continue
		}
		k := fmt.Sprintf("%s:%d", p.Proto, p.Port)
		if !st.Ports[k] && !first {
			out = append(out, newFinding("port:"+k, "warning", p, "f_port", k, p.Process, p.Exe))
		}
		st.Ports[k] = true
	}
	return out
}

// procFindings is the suspicious processes, and why they were not checked
// when the list could not be read (S-177-1).
func procFindings(procs []tools.Proc, err error) (out []finding, why string) {
	if err != nil {
		return nil, fmt.Sprintf("\n\nNot checked: processes (%q).\n", cutLine(mask(err.Error())))
	}
	for _, p := range procs {
		out = append(out, procFinding(p))
	}
	return out, ""
}

// accountsUnchecked is what the account checks could not read (N-180-1:
// macOS's dscl, or the authorized_keys of homes not readable): "not
// checked", not "nothing found".
func accountsUnchecked(acc tools.Accounts) string {
	var b strings.Builder
	for _, what := range acc.NotRead {
		switch what {
		case "accounts":
			fmt.Fprintf(&b, "\n\nNot checked: accounts (UID 0 and login accounts) (%q).\n", cutLine(mask(acc.Note)))
		case "authorized_keys":
			fmt.Fprintf(&b, "\n\nNot checked: authorized_keys in full (%q).\n", cutLine(mask(acc.Note)))
		}
	}
	return b.String()
}

// fileChangesUnchecked is the watched paths file_changes could not read
// (N-183-1: much of macOS is closed to a user): "not checked", not
// "unchanged".
func fileChangesUnchecked(r map[string]any) string {
	unread, _ := r["unread"].([]string)
	if len(unread) == 0 {
		return ""
	}
	return fmt.Sprintf("\n\nNot checked: file changes under %d paths (%q).\n", len(unread), cutLine(mask(strings.Join(unread, ", "))))
}
