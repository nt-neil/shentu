package hostenv

import (
	"encoding/binary"
	"io/fs"
	"strings"
	"testing"
)

// VM acceptance of adff9e6, N4: a log or directory an ACL lets a named
// account write says so, naming the account, not the group bits (which
// are only the ACL's mask).
func TestLogTrustNamesACL(t *testing.T) {
	gid := func(n int) *int { return &n }
	www := []ACLEntry{{Tag: aclUserObj, Perm: 6}, {Tag: aclUser, Perm: 6, ID: 33}, {Tag: aclGroupObj, Perm: 4}, {Tag: aclMask, Perm: 6}, {Tag: aclOther, Perm: 0}}
	h := logHost()
	h.acle = map[string][]ACLEntry{"/var/log/nginx/access.log": www}
	h.st["/var/log/nginx/access.log"] = FileStat{Mode: 0o660, UID: 0}
	web := LinuxCollector{}.WebAccounts(h)
	_, why, detail := LogTrust(h, "/var/log/nginx/access.log", web)
	if why != ReasonUntrusted || !strings.Contains(detail, "ACL grants write to www-data (uid 33)") || strings.Contains(detail, "group or others") {
		t.Errorf("file: %q %q", why, detail)
	}
	// A directory of group adm (a member not a log account), an ACL for
	// www-data and a named group.
	h = logHost()
	h.files["/etc/group"] = "root:x:0:\nadm:x:4:syslog,bob\nwww-data:x:33:\nsyslog:x:104:\n"
	h.st["/var/log/nginx"] = FileStat{Mode: fs.ModeDir | 0o775, UID: 0, GID: gid(4)}
	h.st["/var/log/nginx/access.log"] = FileStat{Mode: 0o640, UID: 0}
	h.acle = map[string][]ACLEntry{"/var/log/nginx": {{Tag: aclUserObj, Perm: 7}, {Tag: aclUser, Perm: 7, ID: 33}, {Tag: aclGroupObj, Perm: 5},
		{Tag: aclGroup, Perm: 7, ID: 4242}, {Tag: aclUser, Perm: 5, ID: 1000}, {Tag: aclMask, Perm: 7}, {Tag: aclOther, Perm: 5}}}
	web = LinuxCollector{}.WebAccounts(h)
	_, why, detail = LogTrust(h, "/var/log/nginx/access.log", web)
	if why == "" || !strings.Contains(detail, "ACL grants write to www-data (uid 33), gid 4242") || strings.Contains(detail, "uid 1000") || strings.Contains(detail, "not a log group") {
		t.Errorf("directory: %q %q", why, detail)
	}
	// The mask takes write away: no grant named, the group bits judged.
	h.acle["/var/log/nginx"] = []ACLEntry{{Tag: aclUserObj, Perm: 7}, {Tag: aclUser, Perm: 7, ID: 33}, {Tag: aclGroupObj, Perm: 5}, {Tag: aclMask, Perm: 5}, {Tag: aclOther, Perm: 5}}
	if _, _, detail = LogTrust(h, "/var/log/nginx/access.log", web); strings.Contains(detail, "ACL grants") {
		t.Errorf("masked: %q", detail)
	}
}

// The xattr's layout (acl_ea_header, acl_ea_entry: little-endian).
func TestParseACL(t *testing.T) {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range []ACLEntry{{Tag: aclUserObj, Perm: 6, ID: 0xffffffff}, {Tag: aclUser, Perm: 6, ID: 33}, {Tag: aclMask, Perm: 6, ID: 0xffffffff}} {
		b = binary.LittleEndian.AppendUint16(b, e.Tag)
		b = binary.LittleEndian.AppendUint16(b, e.Perm)
		b = binary.LittleEndian.AppendUint32(b, e.ID)
	}
	es, err := parseACL(b)
	if err != nil || len(es) != 3 || es[1] != (ACLEntry{Tag: aclUser, Perm: 6, ID: 33}) {
		t.Errorf("%v %+v", err, es)
	}
	for _, bad := range [][]byte{nil, b[:3], b[:9], append(binary.LittleEndian.AppendUint32(nil, 1), b[4:]...)} {
		if _, err := parseACL(bad); err == nil {
			t.Errorf("%x parsed", bad)
		}
	}
}
