package main

import (
	"strings"
	"testing"
)

func TestMaskKeepsSudoTags(t *testing.T) {
	secret := strings.Repeat("h2", 4) + "x9"
	for in, want := range map[string]string{
		"user ALL=(ALL) NOPASSWD:ALL":          "user ALL=(ALL) NOPASSWD:ALL",
		"ann ALL=(ALL) PASSWD: /usr/bin/apt":   "ann ALL=(ALL) PASSWD: /usr/bin/apt",
		"password: " + secret:                  "password: [REDACTED]",
		"PASSWORD=" + secret:                   "PASSWORD=[REDACTED]",
		"passwd: " + secret:                    "passwd: [REDACTED]",
		"PASSWD: " + secret:                    "PASSWD: [REDACTED]",
		"X-PASSWD: " + secret:                  "X-PASSWD: [REDACTED]",
		"(ALL) NOPASSWD:/x?password=" + secret: "(ALL) NOPASSWD:/x?password=[REDACTED]",
		"-----BEGIN RSA PRIVATE KEY-----\n" + secret + " (ALL) NOPASSWD: ALL\n-----END RSA PRIVATE KEY-----": "[REDACTED PRIVATE KEY]",
		"a\x00\x01b ALL=(ALL) NOPASSWD:ALL": "a\x00\x01b ALL=(ALL) NOPASSWD:ALL",
		// N-274-5, as hostenv's MaskSecrets (TestMaskKeepsNOPASSWD).
		"deploy ALL=NOPASSWD: /usr/bin/systemctl restart app": "deploy ALL=NOPASSWD: /usr/bin/systemctl restart app",
		"%deploy ALL=(root) NOPASSWD: DEPLOY":                 "%deploy ALL=(root) NOPASSWD: DEPLOY",
		"bob ALL=(root) NOPASSWD: sudoedit /etc/hosts":        "bob ALL=(root) NOPASSWD: sudoedit /etc/hosts",
		"deploy ALL=NOPASSWD: " + secret:                      "deploy ALL=NOPASSWD: [REDACTED]",
		"x=PASSWD: " + strings.ToUpper(secret):                "x=PASSWD: [REDACTED]",
		"(root) PASSWD: " + secret:                            "(root) PASSWD: [REDACTED]",
		"(x) PASSWD: " + strings.ToUpper(secret):              "(x) PASSWD: [REDACTED]",
		"FOO: PASSWD: " + strings.ToUpper(secret):             "FOO: PASSWD: [REDACTED]",
	} {
		if got := mask(in); got != want {
			t.Errorf("mask(%q) = %q, want %q", in, got, want)
		}
	}
}
