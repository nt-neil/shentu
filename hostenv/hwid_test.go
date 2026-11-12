package hostenv

import (
	"strings"
	"testing"
)

// N3: MAC addresses, DUIDs and IAIDs are masked; times are not.
func TestMaskHardwareIDs(t *testing.T) {
	m := &Masker{}
	m.init()
	mac := "00:0c:29:59:f3:3f"
	in := "Nov 12 14:06:33 vm dhcpcd[1]: eth0: IAID 29:59:f3:3f\n" +
		"eth0: DUID 00:04:9a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9\n" +
		"link/ether " + strings.ToUpper(mac) + " brd ff:ff:ff:ff:ff:ff, again " + mac + ", win 00-0C-29-59-F3-3F\n"
	got := m.text(in, true, true)
	for _, leak := range []string{"29:59:f3:3f", "9a:1b:2c", "0c:29:59", "0C-29-59", "0C:29:59"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q left in:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "Nov 12 14:06:33") {
		t.Errorf("a time was masked:\n%s", got)
	}
	// One MAC, one placeholder, whatever its case.
	if strings.Count(got, m.hwID(mac)) != 2 {
		t.Errorf("MAC placeholders differ:\n%s", got)
	}
	if again := m.text(got, true, true); again != got {
		t.Errorf("masking twice changed it:\n%s\nfirst:\n%s", again, got)
	}
}
