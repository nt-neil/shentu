package hostenv

import (
	"regexp"
	"strings"
)

// secretRules mirror the root package's mask.go (package main cannot be
// imported). Keep the two lists in step; TestMaskSecretsMatchesRoot guards it.
var secretRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), "[REDACTED PRIVATE KEY]"},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*`), "[REDACTED PRIVATE KEY]"},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "${1} [REDACTED]"},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), "[REDACTED GITHUB TOKEN]"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), "[REDACTED GOOGLE KEY]"},
	{regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@"]+:[^/\s@"]+@`), "${1}[REDACTED]@"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "[REDACTED AWS KEY]"},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`), "[REDACTED GITHUB TOKEN]"},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), "[REDACTED SLACK TOKEN]"},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`), "[REDACTED API KEY]"},
	{regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`), "[REDACTED BOT TOKEN]"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "[REDACTED JWT]"},
	{regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\\?"?\s*[=:]\s*\\?"?)[^\s"\\,;]{3,}`), "${1}[REDACTED]"},
	// S-281-1: a password as a command's own argument, not key=value:
	// the mysql family's -p<secret> (mysql*, mariadb*, any case, .exe),
	// --password/--passwd then the next argument, and curl's or wget's
	// -u/-U/--user/--proxy-user user:<secret> (attached, with =, or an empty
	// user; the program's path may be quoted). The command reaches only to
	// an unquoted ; | & or the line's
	// end (git push -u a:b after it is another command's). A value is one
	// shell word: \x, quoted segments ("a b" or 'a b', at its start or after
	// other characters) and anything but a space, a quote or ; | &. A "..."
	// holding only JSON punctuation (, : { } [ ] and spaces) ends the word
	// instead: it is a JSON string's end and the next one's start
	// ({"msg":"mysql -pab","ip":...}), and the line keeps its shape for the
	// parsers after. Not masked: a password of only that punctuation, the
	// part after a space in an unquoted one (argv joined by spaces), and a
	// pretty-printed JSON argv over several lines.
	{regexp.MustCompile(`((?i:\b(?:mysql\w*|mariadb[\w-]*)(?:\.exe)?)\b["']?(?:"[^"\n]*"|'[^'\n]*'|[^\n;|&"'])*?\s-p)(?:\\.|[^\s"'\;|&]|"[^"\n]*[^"\n,:{}\[\]\s][^"\n]*"|'[^'\n]*')+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(--pass(?:word|wd)\s+)(?:\\.|[^-\s"'\;|&]|"[^"\n]*[^"\n,:{}\[\]\s][^"\n]*"|'[^'\n]*')(?:\\.|[^\s"'\;|&]|"[^"\n]*[^"\n,:{}\[\]\s][^"\n]*"|'[^'\n]*')*`), "${1}[REDACTED]"},
	{regexp.MustCompile(`((?i:\b(?:curl|wget)(?:\.exe)?)\b["']?(?:"[^"\n]*"|'[^'\n]*'|[^\n;|&"'])*?(?:\s(?:-u|-U|--user|--proxy-user)(?:\s+|=)|\s-[uU])(?:"[^\s:"]*:|'[^\s:']*:))[^"'\n]*`), "${1}[REDACTED]"},
	{regexp.MustCompile(`((?i:\b(?:curl|wget)(?:\.exe)?)\b["']?(?:"[^"\n]*"|'[^'\n]*'|[^\n;|&"'])*?(?:\s(?:-u|-U|--user|--proxy-user)(?:\s+|=)|\s-[uU])(?:\\.|[^\s:"'\\])*:)(?:\\.|[^\s"'\;|&]|"[^"\n]*[^"\n,:{}\[\]\s][^"\n]*"|'[^'\n]*')+`), "${1}[REDACTED]"},
	// The same three in a JSON argv (docker inspect's Path and Args, an
	// image's Cmd, a healthcheck): a string naming the program, then in the
	// same array on the same line "-p<secret>", "--password", "<secret>" or
	// "-u", "user:<secret>".
	{regexp.MustCompile(`("(?:[^"\n]*[/\\])?(?i:mysql\w*|mariadb[\w-]*)(?:\.exe)?"[^\n\]]*?"-p)(?:\\.|[^"\\\n])+"`), "${1}[REDACTED]\""},
	{regexp.MustCompile(`("--pass(?:word|wd)"\s*,\s*")(?:\\.|[^-"\\\n])(?:\\.|[^"\\\n])*"`), "${1}[REDACTED]\""},
	{regexp.MustCompile(`("(?:[^"\n]*[/\\])?(?i:curl|wget)(?:\.exe)?"[^\n\]]*?"(?:(?:-u|-U|--user|--proxy-user)"\s*,\s*"|-[uU]|--(?:proxy-)?user=)(?:\\.|[^"\\\n:])*:)(?:\\.|[^"\\\n])+"`), "${1}[REDACTED]\""},
}

// MaskSecrets removes credentials from text that came off the host. Every
// Source applies it before data reaches a parser, a log, an LLM or a fixture.
//
// sudoers' NOPASSWD: and PASSWD: tags are not password assignments, but
// the key=value rule would take "PASSWD:ALL" for one; in sudoers syntax
// they are kept as they are so sudo rules keep their meaning. The root
// package's mask() does the same; keep the two in step.
func MaskSecrets(s string) string {
	for _, r := range secretRules {
		s = replaceOutsideSudoTags(s, r.re, r.repl)
	}
	return s
}

// replaceOutsideSudoTags is re.ReplaceAllString(s, repl) over the whole
// string, except that a match starting inside a sudoers NOPASSWD:/PASSWD:
// tag is left as it is (the password rule would otherwise take the tag for
// "passwd: <value>"). Every rule sees the full text, so nothing that spans
// a tag escapes.
func replaceOutsideSudoTags(s string, re *regexp.Regexp, repl string) string {
	var tags [][]int
	for _, m := range sudoTag.FindAllStringSubmatchIndex(s, -1) {
		tags = append(tags, m[2:4])
	}
	return replaceOutside(s, re, repl, tags)
}

// replaceOutside is re.ReplaceAllString(s, repl), except that a match
// starting inside one of tags is left as it is.
func replaceOutside(s string, re *regexp.Regexp, repl string, tags [][]int) string {
	if len(tags) == 0 {
		return re.ReplaceAllString(s, repl)
	}
	var b strings.Builder
	pos := 0
	for pos < len(s) {
		rest := s[pos:]
		m := re.FindStringSubmatchIndex(rest)
		if m == nil || m[1] == m[0] {
			break
		}
		start := pos + m[0]
		if t := tagAt(tags, start); t != nil {
			// Keep the tag itself, then look again right after it: what
			// follows the tag is masked like any other text.
			b.WriteString(s[pos:t[1]])
			pos = t[1]
			continue
		}
		b.WriteString(rest[:m[0]])
		b.Write(re.ExpandString(nil, repl, rest, m))
		pos += m[1]
	}
	b.WriteString(s[pos:])
	return b.String()
}

func tagAt(tags [][]int, i int) []int {
	for _, t := range tags {
		if i >= t[0] && i < t[1] {
			return t
		}
	}
	return nil
}

// sudoTag is a sudoers NOPASSWD: or PASSWD: tag where sudoers puts one:
// after a runas spec ")" or another tag, and before a command (ALL, an
// absolute path, "!" before a path or an upper-case name, or another
// tag; ALL and a name end there: ALL-x, !x are not). Group 1 is the tag.
// "PASSWD: x" or "X-PASSWD: x" elsewhere is not a tag and is masked as a
// secret would be.
// (A double-quoted pattern, so the rule-parity test, which reads
// back-quoted patterns, skips it.)
var sudoTag = regexp.MustCompile("(?m)(?:\\)|[A-Z]+:)[ \\t]*((?:NO)?PASSWD:)[ \\t]*(?:ALL(?:[ \\t,:;)]|$)|/|![ \\t]*(?:/|[A-Z][A-Z0-9_]*(?:[ \\t]*(?:[,:]|$)|=))|[A-Z]+:)")

// MaskSudoers is MaskSecrets for a sudoers file (/etc/sudoers, a file in
// /etc/sudoers.d, one they include): besides sudoTag's, it keeps the tags
// of a rule line ("user host = ..."; two words or more before its "=")
// where sudoers puts them:
//   - after its "=(run-as)" or a sudoers tag (SETENV:, NOEXEC:...),
//     before a command: an absolute path, "!" before one, sudoedit, or an
//     upper-case name ending there (an alias: then ",", ":" or the line's
//     end; an option: then "=");
//   - after its "=" with no run-as list, before ALL, an absolute path, "!"
//     before one, sudoedit or another tag (an upper-case name there stays
//     masked: it cannot be told from a secret).
//
// Any other text keeps MaskSecrets' masking, word for word.
func MaskSudoers(s string) string {
	for _, r := range secretRules {
		s = replaceOutside(s, r.re, r.repl, sudoersTags(s))
	}
	return s
}

var (
	sudoRuleLine = regexp.MustCompile(`^[ \t]*[^#\s=][^=\n]*[ \t][^=\s][^=\n]*=`)
	sudoRuleTag  = regexp.MustCompile("(?m)(?:=[ \\t]*\\([^)\\n]*\\)|\\b(?:NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT|NOPASSWD|PASSWD):)[ \\t]*((?:NO)?PASSWD:)[ \\t]*(?:/|![ \\t]*(?:/|[A-Z][A-Z0-9_]*(?:[ \\t]*(?:[,:]|$)|=))|sudoedit\\b|[A-Z][A-Z0-9_]*(?:[ \\t]*(?:[,:]|$)|=))|=[ \\t]*((?:NO)?PASSWD:)[ \\t]*(?:ALL(?:[ \\t,:]|$)|/|![ \\t]*(?:/|[A-Z][A-Z0-9_]*(?:[ \\t]*(?:[,:]|$)|=))|sudoedit\\b|[A-Z]+:)")
)

// sudoersTags are the tags MaskSudoers keeps in s: sudoTag's anywhere, and
// sudoRuleTag's in rule lines.
func sudoersTags(s string) [][]int {
	var tags [][]int
	for _, m := range sudoTag.FindAllStringSubmatchIndex(s, -1) {
		tags = append(tags, m[2:4])
	}
	off := 0
	for _, ln := range strings.SplitAfter(s, "\n") {
		if sudoRuleLine.MatchString(ln) {
			for _, m := range sudoRuleTag.FindAllStringSubmatchIndex(ln, -1) {
				for g := 2; g+1 < len(m); g += 2 { // the one group that matched
					if m[g] >= 0 {
						tags = append(tags, []int{off + m[g], off + m[g+1]})
						break
					}
				}
			}
		}
		off += len(ln)
	}
	return tags
}
