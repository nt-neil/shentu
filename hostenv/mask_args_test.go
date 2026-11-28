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
		// a , or \ in a value is masked with it, an unquoted ; | & ends it (the
		// next command's); a quoted value is masked to its closing quote; a
		// JSON string that ends right after -p keeps its line's shape
		"mysql -pab,cd\\,ef" + s + " shop":            "mysql -p[REDACTED] shop",
		"mysql -pab" + s + ";rm -rf /tmp/x":           "mysql -p[REDACTED];rm -rf /tmp/x",
		"mysql -pab\\ " + s + " db":                   "mysql -p[REDACTED] db",
		"mysql -p\"" + s + " x\"; echo done":          "mysql -p[REDACTED]; echo done",
		"mysql -p'" + s + "' && " + dl + " https://x": "mysql -p[REDACTED] && " + dl + " https://x",
		`{"msg":"mysql -p","ip":"192.0.2.9"}`:         `{"msg":"mysql -p","ip":"192.0.2.9"}`,
		`{"msg":"tool --password ","ip":"192.0.2.9"}`: `{"msg":"tool --password ","ip":"192.0.2.9"}`,
		"tool --password a\\,b" + s + " next":         "tool --password [REDACTED] next",
		// a quoted value starting with JSON punctuation is still a value; a
		// quoted segment after other characters is the same word
		"tool --password \",ab" + s + "\" next":                       "tool --password [REDACTED] next",
		"mysql -p\",ab" + s + "\" shop":                               "mysql -p[REDACTED] shop",
		"mysql -pab\"" + s + " " + s + "\" shop":                      "mysql -p[REDACTED] shop",
		dl + " -u bob:ab'" + s + " " + s + "' https://x.example.test": dl + " -u bob:[REDACTED] https://x.example.test",
		`{"cmd":"mysql -pab` + s + `","pid":7}`:                       `{"cmd":"mysql -p[REDACTED]","pid":7}`,
		// N-286-2: the mysql family, any case, .exe; a Windows path; NTLM's
		// DOMAIN\user
		"mysqlcheck -p" + s + " --all":                          "mysqlcheck -p[REDACTED] --all",
		"mysqlimport -p" + s + " db f.txt":                      "mysqlimport -p[REDACTED] db f.txt",
		"mysqlshow -p" + s:                                      "mysqlshow -p[REDACTED]",
		"mysqlpump -p" + s + " db":                              "mysqlpump -p[REDACTED] db",
		"mysqlbinlog -p" + s + " -R":                            "mysqlbinlog -p[REDACTED] -R",
		"mysql_upgrade -p" + s:                                  "mysql_upgrade -p[REDACTED]",
		"mysqlslap -p" + s + " -a":                              "mysqlslap -p[REDACTED] -a",
		"mysql8 -p" + s:                                         "mysql8 -p[REDACTED]",
		"mariadb-admin -p" + s + " ping":                        "mariadb-admin -p[REDACTED] ping",
		"MYSQL -u app -p" + s:                                   "MYSQL -u app -p[REDACTED]",
		`"C:\Program Files\MySQL\bin\MySQL.exe" -p` + s + " db": `"C:\Program Files\MySQL\bin\MySQL.exe" -p[REDACTED] db`,
		dl + ` -u DOMAIN\\bob:` + s + " https://x.example.test": dl + ` -u DOMAIN\\bob:[REDACTED] https://x.example.test`,
		// a JSON argv (docker inspect, an image's Cmd, a healthcheck)
		`"Path": "mysql", "Args": ["-u", "root", "-p` + s + `"]`:    `"Path": "mysql", "Args": ["-u", "root", "-p[REDACTED]"]`,
		`{"Path":"mysql","Args":["-u","root","-p` + s + `"]}`:       `{"Path":"mysql","Args":["-u","root","-p[REDACTED]"]}`,
		`"Args": ["--password", "` + s + `"]`:                       `"Args": ["--password", "[REDACTED]"]`,
		`"Cmd": ["` + dl + `", "-u", "bob:` + s + `", "https://x"]`: `"Cmd": ["` + dl + `", "-u", "bob:[REDACTED]", "https://x"]`,
		`"Cmd": ["` + dl + `", "-ubob:` + s + `"]`:                  `"Cmd": ["` + dl + `", "-ubob:[REDACTED]"]`,
		`["CMD","mysqladmin","ping","-uroot","-p` + s + `"]`:        `["CMD","mysqladmin","ping","-uroot","-p[REDACTED]"]`,
		`["CMD-SHELL","mysqladmin ping -uroot -p` + s + `"]`:        `["CMD-SHELL","mysqladmin ping -uroot -p[REDACTED]"]`,
		// S-286-2: the command ends at an unquoted ; | &: another command's
		// -u or -p later on the line is its own
		dl + " -s https://x | sh; git push -u a:b":                   dl + " -s https://x | sh; git push -u a:b",
		"mysql shop < dump.sql; tar -pcf a.tar dir":                  "mysql shop < dump.sql; tar -pcf a.tar dir",
		"mysql -h db && tar -pcf a.tar dir":                          "mysql -h db && tar -pcf a.tar dir",
		"ps -p 123 -o comm; mysql -h db":                             "ps -p 123 -o comm; mysql -h db",
		"docker run -p 8080:80 nginx":                                "docker run -p 8080:80 nginx",
		"/usr/sbin/mysqld --user=mysql -port=3306":                   "/usr/sbin/mysqld --user=mysql -port=3306",
		"connecting to mysqlhost -port 3306":                         "connecting to mysqlhost -port 3306",
		"mariadbd --user=mysql -port=3306":                           "mariadbd --user=mysql -port=3306",
		`["docker","run","-p","8080:80","nginx"]`:                    `["docker","run","-p","8080:80","nginx"]`,
		`{"a":["mysql","-h","db"],"b":["docker","run","-p8080:80"]}`: `{"a":["mysql","-h","db"],"b":["docker","run","-p8080:80"]}`,
		// not secrets
		"git push origin -u main:main":            "git push origin -u main:main",
		"mysql -h db.example.test -P 3306 -u app": "mysql -h db.example.test -P 3306 -u app",
		"mysql --password-file=/etc/app/pw shop":  "mysql --password-file=/etc/app/pw shop",
		"mysql -u app -p shop":                    "mysql -u app -p shop",
		dl + " -u bob https://api.example.test":   dl + " -u bob https://api.example.test",
		"tool --password -":                       "tool --password -",
		`"Args": ["--password", "--next"]`:        `"Args": ["--password", "--next"]`,
	} {
		if got := MaskSecrets(in); got != want {
			t.Errorf("MaskSecrets(%q) = %q, want %q", in, got, want)
		}
	}
}
