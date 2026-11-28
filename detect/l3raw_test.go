package detect

import (
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// The marker an attacker sends in a request and the error message echoes
// back: an unclosed private key BEGIN, which the secret mask takes to the
// line's end. Built at run time.
func pemMarker() string { return "-----BEGIN " + "RSA PRIVATE KEY-----" }

// Review 1 of #286 (inventory item 3): the error log and journald's
// messages are parsed as written. A request's text echoed before PHP's
// location used to be masked away with the location, so the sink lost its
// error-log evidence. Product path: ErrorEvents / entryEvent, Upgrade.
func TestL3ParsesErrorLogAsWritten(t *testing.T) {
	k := pemMarker()
	at := t0.Add(10 * time.Second)
	lines := map[string]string{
		"php":    "[16-Nov-2026 10:00:10 UTC] PHP Warning:  bad input " + k + " in /srv/www/app/x.php on line 12",
		"nginx":  "2026/11/16 10:00:10 [error] 77#0: *5 FastCGI sent in stderr: \"PHP message: PHP Warning:  bad input " + k + " in /srv/www/app/x.php on line 12\" while reading response header from upstream",
		"apache": "[Mon Nov 16 10:00:10.123456 2026] [php:error] [pid 9] [client 192.0.2.1:5] PHP Warning:  bad input " + k + " in /srv/www/app/x.php on line 12",
	}
	upgraded := func(es []ErrorEvent) bool {
		ev := Evidence{Baselines: steadyBaseline("GET /marker/:id", 30), Errors: es}
		a := l2("app/x.php", 12, t0)
		a.Severe, a.KEV = true, true
		return Upgrade(&a, "GET", ev) && a.ErrorEvidence
	}
	for name, l := range lines {
		es := ErrorEvents([]string{l}, true, "e.log", time.UTC)
		if len(es) != 1 || len(es[0].Frames) != 1 || es[0].Frames[0] != (Frame{"/srv/www/app/x.php", 12}) {
			t.Errorf("%s: frames %+v", name, es)
		}
		if !upgraded(es) {
			t.Errorf("%s: no error-log evidence for the sink", name)
		}
	}
	e, ok := entryEvent(hostenv.JournalEntry{Time: at, Unit: "php-fpm.service",
		Message: "PHP message: PHP Warning:  bad input " + k + " in /srv/www/app/x.php on line 12"}, true)
	if !ok || len(e.Frames) != 1 || e.Frames[0] != (Frame{"/srv/www/app/x.php", 12}) {
		t.Errorf("journal: %+v", e)
	}
	if !upgraded([]ErrorEvent{e}) {
		t.Error("journal: no error-log evidence for the sink")
	}
}
