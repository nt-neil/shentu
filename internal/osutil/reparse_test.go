package osutil

import (
	"strings"
	"testing"
)

// N-257-2: a deduplicated file (Windows Server Data Deduplication) is read;
// symlinks, junctions and mount points are refused; another tag is said.
func TestReparseKind(t *testing.T) {
	for _, c := range []struct {
		name       string
		attrs, tag uint32
		want       string
	}{
		{"plain file", 0x20, 0, ""},
		{"deduplicated", 0x20 | FileAttributeReparsePoint, ReparseTagDedup, ""},
		{"symlink", FileAttributeReparsePoint, 0xA000000C, "link"},
		{"junction", FileAttributeReparsePoint, 0xA0000003, "link"},
		{"tag but no attribute", 0x20, 0xA000000C, ""},
		{"cloud file", FileAttributeReparsePoint, 0x9000001A, "reparse point (tag 0x9000001a)"},
		{"hierarchical storage", FileAttributeReparsePoint, 0xC0000004, "reparse point (tag 0xc0000004)"},
	} {
		if got := ReparseKind(c.attrs, c.tag); got != c.want && !(c.want != "" && c.want != "link" && strings.HasPrefix(got, c.want)) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
