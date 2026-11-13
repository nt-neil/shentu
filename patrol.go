package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

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
}

// state is kept in <state_dir>/state.json.
type state struct {
	Alerted map[string]time.Time `json:"alerted"`
	Ports   map[string]bool      `json:"ports"` // baseline of listening ports
	LastRun time.Time            `json:"last_run"`
	Profile tools.SiteProfile    `json:"profile"` // baseline from the last survey
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

// uncheckedSection lists, at the end of a report, the checks that could not
// tell (a file they need could not be read, e.g. when not run as root), so a
// silent part is not read as a clean one. "" when there are none.
func uncheckedSection(risks []tools.Risk) string {
	var b strings.Builder
	for _, r := range risks {
		if tools.Unchecked(r) {
			fmt.Fprintf(&b, "- %q\n", mask(r.Summary))
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "\n\nNot checked (the permission to read what they need was missing; run Shentu as root):\n" + b.String()
}

// uncheckedVulns says, for the daily report, when the vulnerability check of
// what failed (an advisory feed offline: ALAS, OSV) or covered only part
// ("partial"): "no known vulnerabilities" must not stand for "not checked".
// The same goes for the CISA KEV list (none on it must not read as "none
// exploited"), lock files that could not be checked, and ecosystems OSV does
// not carry.
func uncheckedVulns(what string, r map[string]any, err error) string {
	if err != nil {
		return fmt.Sprintf("\n\nNot checked for vulnerabilities: %s (%q).\n", what, cutLine(mask(err.Error())))
	}
	var lines []string
	if p, ok := r["partial"]; ok {
		lines = append(lines, fmt.Sprintf("- partly checked: %q", cutLine(mask(fmt.Sprint(p)))))
	}
	// With no vulnerability found there is nothing to look up in KEV.
	if n, _ := r["total_vulns"].(int); n > 0 {
		if k, _ := r["kev"].(string); strings.Contains(k, "unavailable") {
			lines = append(lines, fmt.Sprintf("- not checked against the CISA KEV list, so exploited ones are not marked: %q", cutLine(mask(k))))
		} else if u, _ := r["kev_unchecked"].(int); u > 0 {
			lines = append(lines, fmt.Sprintf("- %d vulnerabilities not checked against the CISA KEV list (lookups failed or over the cap)", u))
		}
	}
	if files, ok := r["files"].([]tools.AppResult); ok {
		// One line per distinct error, at most uncheckedFiles paths in all.
		byErr := map[string][]string{}
		var order []string
		for _, f := range files {
			if f.Error == "" {
				continue
			}
			if _, seen := byErr[f.Error]; !seen {
				order = append(order, f.Error)
			}
			byErr[f.Error] = append(byErr[f.Error], f.Path)
		}
		listed := 0
		for _, e := range order {
			paths := byErr[e]
			show := paths[:min(len(paths), max(uncheckedFiles-listed, 0))]
			listed += len(show)
			names := make([]string, len(show))
			for i, p := range show {
				names[i] = mask(p)
			}
			line := fmt.Sprintf("- not checked (%q): %s", hostenv.CutString(mask(e), 80), strings.Join(names, ", "))
			if more := len(paths) - len(show); more > 0 {
				line += fmt.Sprintf(" and %d more", more)
			}
			lines = append(lines, cutLine(line))
		}
	}
	if nq, ok := r["ecosystems_not_queried"].([]string); ok {
		for _, e := range nq {
			lines = append(lines, fmt.Sprintf("- not queried (OSV has no such ecosystem): %q", cutLine(mask(e))))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "\n\nVulnerability check of " + what + " incomplete:\n" + strings.Join(lines, "\n") + "\n"
}

// uncheckedFiles caps the lock file paths the unchecked section lists;
// maxUncheckedLine the length of one line of it.
const (
	uncheckedFiles   = 10
	maxUncheckedLine = 200
)

// cutLine keeps a report line to maxUncheckedLine bytes.
func cutLine(s string) string { return hostenv.CutString(s, maxUncheckedLine) }

// uncheckedConfigs lists the web server configuration files the code audit
// could not read: the sites they serve were audited as plain folders.
func uncheckedConfigs(unread []string) string {
	if len(unread) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\nWeb server configuration not read (its web roots are missing from the code audit):\n")
	for _, u := range unread {
		fmt.Fprintf(&b, "- %q\n", mask(u))
	}
	return b.String()
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
		if f.Kind == "injection" && f.Tier != "alert" || f.Kind == "audit" { // "audit": the audit's own summaries, below
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
		out = append(out, finding{key, f.Severity, fmt.Sprintf("%s: %s; fix: %s", where, detail, f.Fix), f})
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
		out = append(out, finding{key, "warning", fmt.Sprintf("code audit: %s; fix: %s", f.Detail, f.Fix), f})
	}
	return out
}

func checks(ctx context.Context, cfg *Config, env *tools.Env, st *state, daily bool) []finding {
	var out []finding
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
			out = append(out, finding{r.Key, r.Severity, r.Summary, nil})
		}
	}
	st.Profile = prof
	since := st.LastRun
	if since.IsZero() || time.Since(since) > 24*time.Hour {
		since = time.Now().Add(-1 * time.Hour)
	}

	if r, err := tools.SSHSummary(ctx, env, time.Now().Add(-1*time.Hour), ""); err == nil {
		note := ""
		if v, _ := r["verified"].(bool); !v {
			note = "; read from text logs, which anyone on this host can write to: check them before acting"
		}
		for _, s := range r["sources"].([]tools.SSHSource) {
			if n := s.Failed + s.InvalidUser; n >= cfg.Patrol.SSHThreshold {
				sev := "warning"
				if s.Accepted > 0 {
					sev = "critical"
				}
				out = append(out, finding{"ssh:" + s.IP, sev,
					fmt.Sprintf("%d failed SSH logins from %s in the last hour (successful logins: %d)%s", n, s.IP, s.Accepted, note), s})
			}
		}
	}

	if ports, err := tools.ListeningPorts(); err == nil {
		first := st.Ports == nil
		if first {
			st.Ports = map[string]bool{}
		}
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
				out = append(out, finding{"port:" + k, "warning", fmt.Sprintf("new listening port %s by %s (%s)", k, p.Process, p.Exe), p})
			}
			st.Ports[k] = true
		}
	}

	for _, p := range tools.Processes(false) {
		out = append(out, finding{fmt.Sprintf("proc:%s:%s", p.Exe, p.Cmdline), "critical",
			fmt.Sprintf("suspicious process pid %d (%s): %s", p.PID, strings.Join(p.Flags, ", "), p.Cmdline), p})
	}

	acc := tools.AccountsAudit()
	for _, u := range acc.UID0 {
		if u != "root" {
			out = append(out, finding{"uid0:" + u, "critical", "account with UID 0 besides root: " + u, nil})
		}
	}
	for _, k := range acc.KeyFiles {
		if k.Modified.After(since) {
			out = append(out, finding{fmt.Sprintf("keys:%s:%d", k.Path, k.Modified.Unix()), "warning",
				fmt.Sprintf("authorized_keys changed: %s (%d keys)", k.Path, k.Keys), k})
		}
	}
	out = append(out, keyFileFindings(acc.KeyFiles)...)
	for _, k := range acc.SharedKeys {
		out = append(out, finding{"sharedkey:" + k.Fingerprint, "warning",
			fmt.Sprintf("one SSH key (%s) is in the authorized_keys of %s; attackers plant one key in every account, check that it is yours", k.Fingerprint, strings.Join(k.Users, ", ")), k})
	}
	if len(acc.Preload) > 0 {
		out = append(out, finding{"preload:" + strings.Join(acc.Preload, ","), "critical",
			fmt.Sprintf("/etc/ld.so.preload loads %s into every program, a common rootkit trick; check each library with dpkg -S or rpm -qf and verify it with dpkg -V or rpm -V", strings.Join(acc.Preload, ", ")), acc.Preload})
	}
	for _, m := range acc.UnpackagedPAM {
		out = append(out, finding{"pam:" + m, "warning",
			fmt.Sprintf("PAM module %s was not installed by a package; a PAM backdoor can let anyone log in by SSH; check it with dpkg -S or rpm -qf %s", m, m), m})
	}

	if r, err := tools.FileChanges(ctx, env.WatchPaths, since); err == nil {
		for _, f := range r["files"].([]tools.Changed) {
			if len(f.Webshell) > 0 {
				out = append(out, finding{"webshell:" + f.Path, "critical", "possible webshell: " + f.Path, f})
			}
		}
	}

	for _, c := range tools.CertExpiry(ctx, env.CertTargets) {
		if c.Error == "" && c.DaysLeft <= 14 {
			out = append(out, finding{"cert:" + c.Target, "warning", fmt.Sprintf("certificate for %s expires in %d days", c.Target, c.DaysLeft), c})
		}
	}
	return out
}

// patrol runs once (from a systemd timer): checks → LLM explanation → notify.
// With daily set it always reports, using the daily-patrol skill.
func patrol(ctx context.Context, cfg *Config, env *tools.Env, daily, dryRun bool) error {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	st := loadState(cfg.StateDir)
	all := checks(ctx, cfg, env, st, daily)
	unchecked := uncheckedSection(st.Profile.Risks) // listed in every report, never pushed
	if daily {
		// Once a day: installed packages with vulnerabilities that are being exploited now.
		r, err := tools.PackageVulns(ctx, env.HTTP, "")
		unchecked += uncheckedVulns("installed packages", r, err)
		if err == nil {
			list, _ := r["actively_exploited"].([]tools.Exploit)
			for _, e := range list {
				all = append(all, finding{"kev:" + e.Package + ":" + e.CVE, "critical",
					fmt.Sprintf("%s %s has %s, which is being exploited in the wild (%s); update it: %v", e.Package, e.Version, e.CVE, e.Name, r["upgrade_command"]), e})
			}
		}
		// The same for application dependencies (npm, PyPI, Composer, Go, RubyGems).
		r, err = tools.AppVulns(ctx, env.HTTP, env.AppPaths)
		unchecked += uncheckedVulns("application dependencies", r, err)
		if err == nil {
			for _, f := range r["files"].([]tools.AppResult) {
				for _, e := range f.Exploited {
					all = append(all, finding{"kev:" + f.Path + ":" + e.Package + ":" + e.CVE, "critical",
						fmt.Sprintf("%s pins %s %s, which has %s, exploited in the wild (%s); upgrade it", f.Path, e.Package, e.Version, e.CVE, e.Name), e})
				}
			}
		}
		// The applications' own files: exposed secrets, debug mode, webshells, keys in code, injection.
		web, unread := tools.WebRootsReport()
		all = replaceOrAppend(all, codeAuditFindings(tools.AppCodeAudit(ctx, env.AppPaths, web)))
		unchecked += uncheckedConfigs(unread)
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
	var list strings.Builder
	for _, f := range fresh {
		// Mask first, then %q keeps attacker-controlled text (command lines, paths) on one line.
		fmt.Fprintf(&list, "- [%s] %q\n", f.Severity, mask(f.Summary))
	}
	if more := total - len(fresh); more > 0 {
		fmt.Fprintf(&list, "- (%d more finding(s), less severe, not listed: the next patrols send them; shentu chat lists them all)\n", more)
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
		answer = fmt.Sprintf("(LLM unavailable: %v)", err)
	}
	answer += "\n\nFindings:\n" + list.String()
	answer += unchecked
	if daily {
		zh := strings.Contains(cfg.Language, "中文") || strings.HasPrefix(strings.ToLower(cfg.Language), "zh")
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
	title := fmt.Sprintf("%d new finding(s)", total)
	if daily {
		title = "Daily security report"
	}
	fmt.Printf("%s\n\n%s\n", title, answer)
	if dryRun {
		return nil
	}
	if err := tools.Notify(ctx, env, title, answer, sev); err != nil {
		return fmt.Errorf("notify failed (findings are not marked as sent): %w", err)
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
			out = append(out, finding{"authorized_keys_symlink:" + k.Path, "warning",
				fmt.Sprintf("%s links to %s, outside the home; sshd reads the keys there (%d keys), check who can write that file", k.Path, k.SymlinkOutsideHome, k.Keys), k})
		}
		if len(k.Unparsed) == 0 {
			continue
		}
		lines := make([]string, len(k.Unparsed))
		for i, l := range k.Unparsed {
			lines[i] = strconv.Itoa(l)
		}
		out = append(out, finding{"authorized_key_unparsed:" + k.Path, "warning",
			fmt.Sprintf("%s line(s) %s are neither a key nor a comment; sshd ignores them, but check none is a key written in another form", k.Path, strings.Join(lines, ", ")), nil})
	}
	return out
}
