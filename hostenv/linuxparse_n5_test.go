package hostenv

import "testing"

// N5: an 8-field line with UID 0 is still an account.
func TestParsePasswdExtraField(t *testing.T) {
	got := ParsePasswd([]byte("root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh:extra\nshort:x:1:1\n"))
	if len(got) != 2 || got[1].Name != "toor" || got[1].UID != "0" || got[1].Shell != "/bin/sh" {
		t.Errorf("%+v", got)
	}
}
