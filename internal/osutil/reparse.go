package osutil

import "fmt"

// Windows reparse points, as a no-follow open sees them.
const (
	FileAttributeReparsePoint = 0x400      // FILE_ATTRIBUTE_REPARSE_POINT
	reparseTagNameSurrogate   = 0x20000000 // the tag's bit for "another name of a file": symlink, junction, mount point
	ReparseTagDedup           = 0x80000013 // IO_REPARSE_TAG_DEDUP: Data Deduplication's optimized file, a regular file
)

// ReparseKind is what a file with these attributes and reparse tag
// (FILE_ATTRIBUTE_TAG_INFO) is to a no-follow open, as Go's os.Lstat reads
// it: "" a file to read (no reparse point, or a deduplicated one), "link" a
// name surrogate (symlink, junction, mount point: refused, never followed),
// else why it is not read as a regular file (another tag).
func ReparseKind(attrs, tag uint32) string {
	switch {
	case attrs&FileAttributeReparsePoint == 0, tag == ReparseTagDedup:
		return ""
	case tag&reparseTagNameSurrogate != 0:
		return "link"
	}
	return fmt.Sprintf("reparse point (tag %#x), not a regular file", tag)
}
