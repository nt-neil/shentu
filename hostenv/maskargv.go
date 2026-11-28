package hostenv

import (
	"regexp"
	"strings"
)

// A command line known as its arguments (/proc's cmdline, ps's, a Windows
// process's) is masked argument by argument (N-286-4): a ; | & there is
// never the shell's (the shell took its own away before), so it is part of
// the argument's value, and a password with one in it is masked whole. The
// line-text rules (MaskSecrets) end a command at an unquoted ; | &, which
// is right for a log line or a shell's history but would leave the rest of
// such a password.
var (
	argvMySQL  = regexp.MustCompile(`(?i)(?:^|[^=\w])(?:mysql(?:dump|check|import|show|pump|binlog|_upgrade|slap|admin|sh)?\d*|mariadb(?:-?(?:dump|admin|check|import|show|binlog|upgrade|slap|backup))?)(?:\.exe)?$`)
	argvCurl   = regexp.MustCompile(`(?i)(?:^|[^=\w])(?:curl|wget)(?:\.exe)?$`)
	argvKV     = regexp.MustCompile(`(?i)^(-{0,2}(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)=).{3,}$`)
	argvUserAt = regexp.MustCompile(`^(?:-[uU]|--(?:proxy-)?user=)[^:]*:`)
)

// argvUserOpt are options whose next argument is a user's name.
var argvUserOpt = map[string]bool{"-u": true, "-U": true, "--user": true, "--username": true}

// MaskArgv masks a command line given as its arguments and joins them with
// spaces. An argument that is a password by its place is masked whole: -p<v>
// after a program of the mysql family, the one after --password or
// --passwd (unless it is an option), user:<v> after curl's or wget's
// -u/-U/--user/--proxy-user (or attached), and key=<v> of a secret's key.
// Every other argument is masked as text, and the joined line once more (a
// rule across arguments: "Bearer" and its token).
func MaskArgv(args []string) string {
	return maskArgv(args, func(s string) string { return s })
}

// MaskWinCmdline is MaskArgv for a Windows command line: one string, split
// at blanks outside double quotes (SplitWinCmdline); the arguments are kept
// as written, quotes and all, and judged without their quotes.
func MaskWinCmdline(s string) string {
	return maskArgv(SplitWinCmdline(s), func(a string) string { return strings.ReplaceAll(a, `"`, "") })
}

func maskArgv(args []string, view func(string) string) string {
	out := make([]string, 0, len(args))
	mysql, curl := false, false
	prev := ""
	for _, a := range args {
		v := view(a)
		switch {
		case mysql && len(v) > 2 && strings.HasPrefix(v, "-p"):
			a = "-p[REDACTED]"
		case (prev == "--password" || prev == "--passwd") && v != "" && !strings.HasPrefix(v, "-"):
			a = "[REDACTED]"
		case curl && (prev == "-u" || prev == "-U" || prev == "--user" || prev == "--proxy-user") && strings.Contains(v, ":"):
			a = v[:strings.Index(v, ":")+1] + "[REDACTED]"
		case curl && argvUserAt.MatchString(v):
			a = argvUserAt.FindString(v) + "[REDACTED]"
		case argvKV.MatchString(v):
			a = argvKV.FindStringSubmatch(v)[1] + "[REDACTED]"
		default:
			a = MaskSecrets(a)
		}
		// A user's name (--user mysql, psql -U mysql) names no program
		// (S-286-10).
		// The program may end an argument after a path or a shell's
		// ; | ( $( or ` (ps joins sh -c's line with spaces: x;mysql).
		if !argvUserOpt[prev] {
			mysql = mysql || argvMySQL.MatchString(v)
			curl = curl || argvCurl.MatchString(v)
		}
		prev = v
		out = append(out, a)
	}
	return maskJoinedArgv(strings.Join(out, " "))
}

// maskJoinedArgv masks the joined arguments with every rule but the four a
// command line's own password is found by in text (mysql's -p, --password,
// curl's -u): each argument was judged by its place above, and in text
// they would read psql -U mysql -p5432 as mysql's password again.
func maskJoinedArgv(s string) string {
	for _, r := range secretRules {
		if !argvTextRule(r.re.String()) {
			s = replaceOutsideSudoTags(s, r.re, r.repl)
		}
	}
	return s
}

func argvTextRule(src string) bool {
	return strings.Contains(src, "(?i:(?:mysql(") || strings.Contains(src, "(?i:(?:curl|wget)") || strings.HasPrefix(src, `(--pass(?:word|wd)\s+)`)
}

// SplitWinCmdline splits a Windows command line at spaces and tabs outside
// double quotes, each argument as written (its quotes kept). As Windows
// reads it (CommandLineToArgvW), a quote after an odd number of
// backslashes is a literal one, after an even number (none, or \\ as in
// "C:\dir\\") it opens or closes a quoted part (S-286-9).
func SplitWinCmdline(s string) []string {
	var out []string
	var b strings.Builder
	quoted := false
	bs := 0 // backslashes just before
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && bs%2 == 0:
			quoted = !quoted
			b.WriteByte(c)
		case (c == ' ' || c == '\t') && !quoted:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteByte(c)
		}
		if c == '\\' {
			bs++
		} else {
			bs = 0
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}
