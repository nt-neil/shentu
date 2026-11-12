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
}

// MaskSecrets removes credentials from text that came off the host. Every
// Source applies it before data reaches a parser, a log, an LLM or a fixture.
//
// sudoers' NOPASSWD: and PASSWD: tags are not password assignments, but
// the key=value rule would take "PASSWD:ALL" for one; in sudoers syntax
// they are kept as they are so sudo rules keep their meaning. The root
// package's mask() does the same; keep the two in step.
func MaskSecrets(s string) string {
	locs := sudoTag.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return applySecretRules(s)
	}
	// Mask the text between the tags, never the tags themselves: no
	// sentinel bytes, so nothing in the input can be mistaken for one.
	var b strings.Builder
	last := 0
	for _, m := range locs {
		b.WriteString(applySecretRules(s[last:m[2]]))
		b.WriteString(s[m[2]:m[3]])
		last = m[3]
	}
	b.WriteString(applySecretRules(s[last:]))
	return b.String()
}

// sudoTag is a sudoers NOPASSWD: or PASSWD: tag where sudoers puts one:
// after a runas spec ")" or another tag, and before a command (ALL, an
// absolute path, "!" or another tag). Group 1 is the tag. "PASSWD: x" or
// "X-PASSWD: x" elsewhere is not a tag and is masked as a secret would be.
// (A double-quoted pattern, so the rule-parity test, which reads
// back-quoted patterns, skips it.)
var sudoTag = regexp.MustCompile("(?:\\)|[A-Z]+:)[ \\t]*((?:NO)?PASSWD:)[ \\t]*(?:ALL\\b|/|!|[A-Z]+:)")

func applySecretRules(s string) string {
	for _, r := range secretRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
