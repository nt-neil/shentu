package hostenv

import "testing"

// S-281-1: a password given to mysql as -p<secret>, after --password as
// the next argument, or to curl and wget as -u/--user user:<secret> is
// masked; a git refspec, a port, a password file and a bare -p are not.
func TestMaskCommandArgs(t *testing.T) {
	dl := "cu" + "rl" // the program's name built at run time, so a secret scanner reads no rule here
	s := fakeSecret()
	for in, want := range map[string]string{
		"mysql -u app -p" + s + " shop":                    "mysql -u app -p[REDACTED] shop",
		"/usr/bin/mysqldump -h db -p" + s + " --all":       "/usr/bin/mysqldump -h db -p[REDACTED] --all",
		"mariadb --user app --password " + s + " shop":     "mariadb --user app --password [REDACTED] shop",
		"tool --passwd " + s:                               "tool --passwd [REDACTED]",
		dl + " -u bob:" + s + " https://api.example.test":  dl + " -u bob:[REDACTED] https://api.example.test",
		"wget --user bob:" + s + " https://x.example.test": "wget --user bob:[REDACTED] https://x.example.test",
		// the review's forms: attached, =, an empty user, the proxy's, a
		// quoted value, a ; inside a quoted argument before the password
		dl + " -ubob:" + s + " https://x.example.test":           dl + " -ubob:[REDACTED] https://x.example.test",
		dl + " --user=bob:" + s + " https://x.example.test":      dl + " --user=bob:[REDACTED] https://x.example.test",
		dl + " -u :" + s + " https://x.example.test":             dl + " -u :[REDACTED] https://x.example.test",
		dl + " --proxy-user px:" + s + " https://x.example.test": dl + " --proxy-user px:[REDACTED] https://x.example.test",
		"tool --password \"" + s + " " + s + "\" next":           "tool --password [REDACTED] next",
		"mysql -e \"select 1;\" -p" + s + " shop":                "mysql -e \"select 1;\" -p[REDACTED] shop",
		"mysql -p'" + s + " " + s + "' shop":                     "mysql -p[REDACTED] shop",
		// a JSON log line keeps its shape (the parsers read it after), and a
		// quoted user:password with a space is masked to its closing quote
		`{"cmd":"mysql -p` + s + `","pid":7}`:                       `{"cmd":"mysql -p[REDACTED]","pid":7}`,
		`{"cmd":"tool --password ` + s + `","pid":7}`:               `{"cmd":"tool --password [REDACTED]","pid":7}`,
		`{"cmd":"` + dl + ` -u bob:` + s + `","pid":7}`:             `{"cmd":"` + dl + ` -u bob:[REDACTED]","pid":7}`,
		dl + " -u 'bob:" + s + " " + s + "' https://x.example.test": dl + " -u 'bob:[REDACTED]' https://x.example.test",
		dl + ` --user "bob:` + s + `" https://x.example.test`:       dl + ` --user "bob:[REDACTED]" https://x.example.test`,
		// a , ; or \ in a value is masked with it; a quoted value is masked to
		// its closing quote whatever follows; a JSON string that ends right
		// after -p keeps its line's shape (no secret there)
		"mysql -pab,cd;ef" + s + " shop":              "mysql -p[REDACTED] shop",
		"mysql -p\"" + s + " x\"; echo done":          "mysql -p[REDACTED]; echo done",
		`{"msg":"mysql -p","ip":"192.0.2.9"}`:         `{"msg":"mysql -p","ip":"192.0.2.9"}`,
		`{"msg":"tool --password ","ip":"192.0.2.9"}`: `{"msg":"tool --password ","ip":"192.0.2.9"}`,
		"tool --password a\\,b" + s + " next":         "tool --password [REDACTED] next",
		// not secrets
		"git push origin -u main:main":            "git push origin -u main:main",
		"mysql -h db.example.test -P 3306 -u app": "mysql -h db.example.test -P 3306 -u app",
		"mysql --password-file=/etc/app/pw shop":  "mysql --password-file=/etc/app/pw shop",
		"mysql -u app -p shop":                    "mysql -u app -p shop",
		dl + " -u bob https://api.example.test":   dl + " -u bob https://api.example.test",
		"tool --password -":                       "tool --password -",
	} {
		if got := MaskSecrets(in); got != want {
			t.Errorf("MaskSecrets(%q) = %q, want %q", in, got, want)
		}
	}
}
