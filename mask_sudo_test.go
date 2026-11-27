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
		// N-274-6, as hostenv's MaskSecrets (TestMaskKeepsNOPASSWD).
		"ADMIN=PASSWD: !" + secret:                        "ADMIN=PASSWD: [REDACTED]",
		"x = PASSWD: /" + secret + "+=":                   "x = PASSWD: [REDACTED]",
		"x=PASSWD: ABC:" + secret:                         "x=PASSWD: [REDACTED]",
		"auth=(prod) PASSWD: " + strings.ToUpper(secret):  "auth=(prod) PASSWD: [REDACTED]",
		"=(x) PASSWD: P@" + secret:                        "=(x) PASSWD: [REDACTED]",
		"note MAIL: PASSWD: " + strings.ToUpper(secret):   "note MAIL: PASSWD: [REDACTED]",
		"EXEC: PASSWD: ABC." + secret:                     "EXEC: PASSWD: [REDACTED]",
		"PASSWORD=(a) PASSWD: " + strings.ToUpper(secret): "PASSWORD=[REDACTED] PASSWD: [REDACTED]",
		"(prod) PASSWD: !" + secret:                       "(prod) PASSWD: [REDACTED]",
		"FOO: PASSWD: ALL-" + secret:                      "FOO: PASSWD: [REDACTED]",
	} {
		if got := mask(in); got != want {
			t.Errorf("mask(%q) = %q, want %q", in, got, want)
		}
	}
}
