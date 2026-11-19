package hostenv

import (
	"io/fs"
	"strings"
	"testing"
)

// Review 1 of #97: a directory whose ACL lets a web account write is
// web_user_writable (S-2); a log others may write, ACL or not, says so (S-3).
func TestACLReasonWebAndOthers(t *testing.T) {
	gid := func(n int) *int { return &n }
	h := logHost()
	h.files["/etc/group"] = "root:x:0:\nadm:x:4:syslog,bob\nwww-data:x:33:\nsyslog:x:104:\n"
	h.st["/var/log/nginx"] = FileStat{Mode: fs.ModeDir | 0o775, UID: 0, GID: gid(4)}
	h.st["/var/log/nginx/access.log"] = FileStat{Mode: 0o640, UID: 0}
	h.acle = map[string][]ACLEntry{"/var/log/nginx": {{Tag: aclUserObj, Perm: 7}, {Tag: aclUser, Perm: 7, ID: 33}, {Tag: aclGroupObj, Perm: 5}, {Tag: aclMask, Perm: 7}, {Tag: aclOther, Perm: 5}}}
	web := LinuxCollector{}.WebAccounts(h)
	if _, why, detail := LogTrust(h, "/var/log/nginx/access.log", web); why != ReasonWebUserWritable || !strings.Contains(detail, "ACL grants write to www-data (uid 33)") {
		t.Errorf("directory, ACL for www-data: %q %q", why, detail)
	}
	h.acle["/var/log/nginx"] = []ACLEntry{{Tag: aclUserObj, Perm: 7}, {Tag: aclGroup, Perm: 7, ID: 4242}, {Tag: aclGroupObj, Perm: 5}, {Tag: aclMask, Perm: 7}, {Tag: aclOther, Perm: 5}}
	if _, why, detail := LogTrust(h, "/var/log/nginx/access.log", web); why != ReasonUnverified || !strings.Contains(detail, "ACL grants write to gid 4242") {
		t.Errorf("directory, ACL for another group: %q %q", why, detail)
	}
	h = logHost()
	h.acle = map[string][]ACLEntry{"/var/log/nginx/access.log": {{Tag: aclUserObj, Perm: 6}, {Tag: aclUser, Perm: 6, ID: 1000}, {Tag: aclGroupObj, Perm: 4}, {Tag: aclMask, Perm: 6}, {Tag: aclOther, Perm: 6}}}
	h.st["/var/log/nginx/access.log"] = FileStat{Mode: 0o666, UID: 0}
	web = LinuxCollector{}.WebAccounts(h)
	if _, why, detail := LogTrust(h, "/var/log/nginx/access.log", web); why != ReasonUntrusted || !strings.Contains(detail, "ACL grants write to uid 1000") || !strings.Contains(detail, "others") {
		t.Errorf("file, ACL and others: %q %q", why, detail)
	}
}
