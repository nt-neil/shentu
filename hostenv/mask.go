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
// sudoers' NOPASSWD: tag is not a password assignment, but the key=value
// rule would take "PASSWD:ALL" for one; it is shielded so sudo rules keep
// their meaning.
func MaskSecrets(s string) string {
	shielded := nopasswd.MatchString(s)
	if shielded {
		s = nopasswd.ReplaceAllStringFunc(s, func(m string) string { return "\x00" + m[:4] + "\x01" + m[4:] })
	}
	for _, r := range secretRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	if shielded {
		s = strings.NewReplacer("\x00", "", "\x01", "").Replace(s)
	}
	return s
}

var nopasswd = regexp.MustCompile(`(?i)\bno(?:passwd|password):`)
