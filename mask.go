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

// mask keeps sudoers' upper-case NOPASSWD: and PASSWD: tags: they are not
// password assignments, and "NOPASSWD:[REDACTED]" would hide what a sudo
// rule grants. Real secrets (password: x, PASSWORD=x) are still masked.
// hostenv.MaskSecrets does the same; keep the two in step.
func mask(s string) string {
	shielded := sudoTag.MatchString(s)
	if shielded {
		s = sudoTag.ReplaceAllStringFunc(s, func(m string) string { return strings.Replace(m, "PASSWD", "PA"+maskShield+"SSWD", 1) })
	}
	for _, r := range maskRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	if shielded {
		s = strings.ReplaceAll(s, maskShield, "")
	}
	return s
}

// A double-quoted pattern, so hostenv's rule-parity test (back-quoted
// patterns) does not count it as a masking rule.
var sudoTag = regexp.MustCompile("\\b(?:NO)?PASSWD:")

const maskShield = "\x00\x01"
