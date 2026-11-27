package tools

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// sudoRisks: sudo runs commands with no password. Every command for
// someone (ALL among the commands, an alias not told, Defaults
// !authenticate for all) means one way into that account is the run-as
// account's power at once: a warning; except a rule for cloud-init's
// default_user alone in the file cloud-init writes (the cloud image's
// default, safe only when that user logs in with keys alone), and rules
// for some commands only: info. sudoers not read in full is said, never
// taken for no such rule.
func sudoRisks(s hostenv.SudoNoPass) []Risk {
	var warn, cloud, some []string
	for _, r := range s.Rules {
		switch {
		case !r.All:
			some = append(some, sudoRuleText(r))
		case r.CloudDefault && r.OneUser():
			cloud = append(cloud, sudoRuleText(r))
		default:
			warn = append(warn, sudoRuleText(r))
		}
	}
	var out []Risk
	if len(warn) > 0 {
		out = append(out, Risk{"sudo:nopasswd", "warning", "sudo runs every command with no password: " + ruleList(warn) +
			"; whoever gets into one of these accounts has the run-as account's power at once: require the password, or limit NOPASSWD to the commands needed"})
	}
	if len(cloud) > 0 {
		out = append(out, Risk{"sudo:nopasswd:cloud-init", "info", "sudo runs every command with no password for cloud-init's default user, as the cloud image sets it up: " + ruleList(cloud) +
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

// sudoRuleText is a rule as read, then what it runs and as whom, as it
// says (S-274-3): "every command" or the commands; root when no run-as
// list is given, any user for ALL.
func sudoRuleText(r hostenv.SudoRule) string {
	what := "every command"
	if !r.All {
		what = "only " + Cut(strings.Join(r.Cmds, ", "), 120)
	}
	var as []string
	for _, a := range r.Runas {
		switch u, _, _ := strings.Cut(a, ":"); {
		case u == "":
			as = append(as, "root")
		case u == "ALL":
			as = append(as, "any user")
		default:
			as = append(as, u)
		}
	}
	if len(as) == 0 {
		as = []string{"root"} // Defaults: sudo's default run-as
	}
	return Cut(r.String(), 160) + " (" + what + ", as " + strings.Join(slices.Compact(as), ", ") + ")"
}

// ruleList is the first three rules, each cut, and how many more.
func ruleList(rules []string) string {
	shown := rules[:min(3, len(rules))]
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
