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
//
// sshPassword is whether sshd lets every user log in with a password
// (sshPasswordLogin): "yes" makes cloud-init's rule a warning, the two
// together; "no" or "unknown" leave it info.
func sudoRisks(s hostenv.SudoNoPass, sshPassword string) []Risk {
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
		out = append(out, Risk{"sudo:nopasswd", "warning", "sudo runs every command with no password asked, by these rules: " + ruleList(warn) +
			"; whoever gets into one of these accounts has the run-as account's power at once: require the password, or limit the no-password rules to the commands needed"})
	}
	switch {
	case len(cloud) > 0 && sshPassword == "yes":
		out = append(out, Risk{"sudo:nopasswd:cloud-init", "warning", "sudo runs every command with no password asked for cloud-init's default user, by these rules: " + ruleList(cloud) +
			"; and sshd lets every user log in with a password (PasswordAuthentication yes, no Match block): whoever guesses or reuses that user's password is root at once, no second password asked. Turn PasswordAuthentication off (keys only), or require sudo's password"})
	case len(cloud) > 0:
		out = append(out, Risk{"sudo:nopasswd:cloud-init", "info", "sudo runs every command with no password asked for cloud-init's default user, as the cloud image sets it up, by these rules: " + ruleList(cloud) +
			"; safe only while that user can log in with a key alone, never a password"})
	}
	if len(some) > 0 {
		out = append(out, Risk{"sudo:nopasswd:some", "info", "sudo runs some commands with no password asked, by these rules: " + ruleList(some)})
	}
	if len(s.Unread) > 0 {
		why := ""
		if slices.ContainsFunc(s.Unread, func(u string) bool { return strings.HasSuffix(u, "(permission denied)") }) {
			why = "; run Shentu as root, as sudo reads them"
		}
		out = append(out, Risk{uncheckedPrefix + "sudoers", "info", "cannot tell in full whether sudo runs commands with no password asked: " +
			Cut(hostenv.MaskSecrets(strings.Join(s.Unread, ", ")), 300) + " not read" + why}) // an include's line read as is: masked
	}
	return out
}

// sudoRuleText is a rule's file and whom it is for, then what it runs and
// as whom, as it says (S-274-3): "every command" or the commands; root when
// no run-as list is given, any user for ALL. Built from the parsed fields,
// never the line (S-274-10).
func sudoRuleText(r hostenv.SudoRule) string {
	what := "every command"
	if !r.All {
		// a command's arguments can hold a secret (mysql --password=...):
		// masked here, as site_profile goes to the model whole
		what = "only " + Cut(hostenv.MaskSecrets(strings.Join(r.Cmds, ", ")), 120)
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
	return r.File + ": " + Cut(sudoWho(r), 80) + " (" + what + ", as " + Cut(hostenv.MaskSecrets(strings.Join(slices.Compact(as), ", ")), 80) + ")"
}

// sudoWho is whom a rule is for, from its parsed fields, not its line: a
// pushed text goes through the secret masking, which takes a line's
// "NOPASSWD: <command>" for a password (S-274-10).
func sudoWho(r hostenv.SudoRule) string {
	switch {
	case !r.Defaults && r.Who == "":
		return "(someone)" // a rule always has a user list; not one told (S-280-4)
	case !r.Defaults:
		return r.Who
	case r.Who != "":
		return "Defaults !authenticate for " + r.Who
	case len(r.Runas) > 0:
		return "Defaults !authenticate for whoever runs as " + strings.Join(r.Runas, ", ")
	case r.Cmds != nil:
		return "Defaults !authenticate for these commands"
	}
	return "Defaults !authenticate for everyone"
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

// sshPasswordLogin is whether sshd lets every user log in with a password:
// "yes", "no", or "unknown". Only with no Match block in any file (all
// read: a Match User may change it for one user) is the global setting
// every user's; one a file sets is taken as it is, sshd's default only
// where it is known: OpenSSH's is yes in every version, and no family read
// here patches it (an unknown distribution: unknown).
func sshPasswordLogin(c hostenv.SSHConfig, family string) string {
	if c.Match != "none" {
		return "unknown"
	}
	v := strings.ToLower(c.Settings["passwordauthentication"])
	switch {
	case v == "unknown" || v == "":
		return "unknown"
	case slices.Contains(c.Set, "passwordauthentication"):
		if v == "yes" {
			return "yes"
		}
		return "no"
	case slices.Contains([]string{"debian", "rhel", "suse", "alpine", "arch"}, family) && v == "yes":
		return "yes"
	}
	return "unknown"
}
