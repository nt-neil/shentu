package main

import (
	"errors"
	"strings"
	"testing"
)

// S-281-2: a tool's error goes to the model masked, as its result does.
func TestErrTextMasked(t *testing.T) {
	secret := strings.Join([]string{"tok", "Sekr", "1t", "Value"}, "")
	err := errors.New("request failed: https://api.example.test/v1?token=" + secret + " (status 401)")
	got := errText(err.Error())
	if strings.Contains(got, secret) || !strings.Contains(got, "token=[REDACTED]") {
		t.Errorf("errText = %q", got)
	}
}
