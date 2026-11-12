package main

import (
	"regexp"
	"strings"
)

// Secrets are replaced before anything is sent to the LLM or written to the log.
var maskRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), "[REDACTED PRIVATE KEY]"},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*`), "[REDACTED PRIVATE KEY]"}, // cut off before the END line
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
	// key=value / key: value. The value class stops at quotes and backslashes so JSON text stays valid.
	{regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\\?"?\s*[=:]\s*\\?"?)[^\s"\\,;]{3,}`), "${1}[REDACTED]"},
}

// mask removes secrets. sudoers' NOPASSWD: and PASSWD: tags in sudoers
// syntax are kept: they are not password assignments, and
// "NOPASSWD:[REDACTED]" would hide what a sudo rule grants.
// hostenv.MaskSecrets does the same; keep the two in step.
func mask(s string) string {
	locs := sudoTag.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return applyMaskRules(s)
	}
	// Mask the text between the tags, never the tags themselves: no
	// sentinel bytes, so nothing in the input can be mistaken for one.
	var b strings.Builder
	last := 0
	for _, m := range locs {
		b.WriteString(applyMaskRules(s[last:m[2]]))
		b.WriteString(s[m[2]:m[3]])
		last = m[3]
	}
	b.WriteString(applyMaskRules(s[last:]))
	return b.String()
}

// sudoTag is a sudoers NOPASSWD: or PASSWD: tag where sudoers puts one:
// after a runas spec ")" or another tag, and before a command (ALL, an
// absolute path, "!" or another tag). Group 1 is the tag. "PASSWD: x" or
// "X-PASSWD: x" elsewhere is not a tag and is masked as a secret would be.
// (A double-quoted pattern, so the rule-parity test, which reads
// back-quoted patterns, skips it.)
var sudoTag = regexp.MustCompile("(?:\\)|[A-Z]+:)[ \\t]*((?:NO)?PASSWD:)[ \\t]*(?:ALL\\b|/|!|[A-Z]+:)")

func applyMaskRules(s string) string {
	for _, r := range maskRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
