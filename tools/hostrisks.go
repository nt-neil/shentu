package tools

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// sudoRisks: sudo runs commands with no password. For every command, one
// way into such an account is root at once: a warning; except a rule for
// one user in the file cloud-init writes (the cloud image's default user,
// safe only when that user logs in with keys alone), and a rule for some
// commands only: info. sudoers not read in full is said, never taken for
// no such rule.
func sudoRisks(s hostenv.SudoNoPass) []Risk {
	var warn, cloud, some []string
	for _, r := range s.Rules {
		switch {
		case !r.All:
			some = append(some, r.String())
		case r.CloudInit && r.OneUser():
			cloud = append(cloud, r.String())
		default:
			warn = append(warn, r.String())
		}
	}
	var out []Risk
	if len(warn) > 0 {
		out = append(out, Risk{"sudo:nopasswd", "warning", "sudo runs every command as root with no password: " + ruleList(warn) +
			"; whoever gets into one of these accounts is root at once: require the password, or limit NOPASSWD to the commands needed"})
	}
	if len(cloud) > 0 {
		out = append(out, Risk{"sudo:nopasswd:cloud-init", "info", "sudo runs every command as root with no password for the cloud image's default user, as cloud-init sets it up: " + ruleList(cloud) +
			"; safe only while that user can log in with a key alone, never a password"})
	}
	if len(some) > 0 {
		out = append(out, Risk{"sudo:nopasswd:some", "info", "sudo runs some commands with no password: " + ruleList(some)})
	}
	if len(s.Unread) > 0 {
		why := ""
		if slices.ContainsFunc(s.Unread, func(u string) bool { return strings.HasSuffix(u, "(permission denied)") }) {
			why = "; run Shentu as root, as sudo reads them"
		}
		out = append(out, Risk{uncheckedPrefix + "sudoers", "info", "cannot tell in full whether sudo runs commands with no password: " +
			Cut(strings.Join(s.Unread, ", "), 300) + " not read" + why})
	}
	return out
}

// ruleList is the first three rules, each cut, and how many more.
func ruleList(rules []string) string {
	shown := slices.Clone(rules[:min(3, len(rules))])
	for i := range shown {
		shown[i] = Cut(shown[i], 160)
	}
	more := ""
	if len(rules) > 3 {
		more = fmt.Sprintf(" (and %d more)", len(rules)-3)
	}
	return strings.Join(shown, "; ") + more
}

// rebootRisks: an update waits for a reboot: until then the old kernel or
// libraries keep running, their fixes not in effect.
func rebootRisks(r hostenv.RebootPending) []Risk {
	switch {
	case r.Pending:
		return []Risk{{"reboot:pending", "warning", "a reboot is pending: " + r.Why + "; until the host restarts, the old kernel or libraries keep running and their fixes are not in effect"}}
	case r.Unread != "":
		return []Risk{{uncheckedPrefix + "reboot", "info", "cannot tell whether a reboot is pending: " + r.Unread + " could not be read"}}
	}
	return nil
}
