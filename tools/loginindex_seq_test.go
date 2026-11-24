package tools

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// strictness: verified 0, nothing against it 1, refused 2
func strictRank(v bool, code BlockCode) int {
	switch {
	case v && code == BlockOK:
		return 0
	case code == BlockOK:
		return 1
	}
	return 2
}

// both checks ip with the index and with the whole read of the same journal.
func both(ip string) (index, whole int) {
	KeepLoginIndex = true
	iv, icode, _ := check(ip)
	KeepLoginIndex = false
	wv, wcode, _ := check(ip)
	KeepLoginIndex = true
	return strictRank(iv, icode), strictRank(wv, wcode)
}

// S-222-2: the journal vacuumed up to an entry with the time of the one
// after it. The index tells them apart by their numbers, as the whole read
// (which sees only what is left) does: an address's event vacuumed is not
// seen, a forged one vacuumed does not refuse, and an event left at the
// first entry's own time is seen. On integ, times alone took the one
// vacuumed as still there.
func TestLoginIndexSameTimeVacuumed(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	at := now.Add(-3 * time.Hour)
	for _, c := range []struct {
		name  string
		build func(j *fakeJournal)
		ip    string
		want  int
	}{
		{"own event vacuumed", func(j *fakeJournal) {
			j.failed(at, "203.0.113.10")
			j.add(at, "sshd", 0, "Server listening on 0.0.0.0 port 22.")
		}, "203.0.113.10", 1},
		{"forged event vacuumed", func(j *fakeJournal) {
			j.forged(at, "203.0.113.30")
			j.add(at, "sshd", 0, "Server listening on 0.0.0.0 port 22.")
		}, "203.0.113.30", 1},
		{"own event left, of the first entry's time", func(j *fakeJournal) {
			j.add(at, "sshd", 0, "Server listening on 0.0.0.0 port 22.")
			j.add(at, "sshd", 0, "Server listening on :: port 22.")
			j.failed(at, "203.0.113.10")
		}, "203.0.113.10", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			j := &fakeJournal{}
			c.build(j)
			n := now
			withIndex(t, j, &n)
			wholeRead(t, j, n)
			check(c.ip) // the index built
			j.vacuum(1)
			if i, w := both(c.ip); i != c.want || w != c.want {
				t.Errorf("index %d, whole read %d, want %d (0 verified, 1 nothing, 2 refused)", i, w, c.want)
			}
		})
	}
}

// tiedJournal is a journal of a few distinct times, many entries sharing
// each: where times alone cannot tell what a vacuum took.
func tiedJournal(rng *rand.Rand, j *fakeJournal, now time.Time, ips []string, later bool) {
	writers := []struct {
		comm string
		uid  int
	}{{"sshd", 0}, {"sshd-session", 0}, {"logger", 1000}, {"logger", 0}}
	times := []time.Time{now.Add(-5*time.Hour - 30*time.Minute), now.Add(-30 * time.Hour), now.Add(-100*time.Hour - 30*time.Minute)}
	if later { // written after the first ones (a journal made anew goes on in time)
		times = []time.Time{now.Add(-4*time.Hour - 30*time.Minute), now.Add(-3 * time.Hour), now.Add(-90 * time.Minute)}
	}
	k0 := 1 + rng.Intn(10)
	for k := k0; k > 0; k-- {
		w := writers[rng.Intn(len(writers))]
		ip := ips[rng.Intn(len(ips))]
		msg := "Failed password for root from " + ip + " port 22 ssh2"
		switch rng.Intn(8) {
		case 0:
			msg = "Server listening on 0.0.0.0 port 22."
		case 1:
			msg = "Failed password for invalid user " + strings.Repeat("z", 1<<20) + " from " + ip + " port 22 ssh2"
		}
		j.add(times[rng.Intn(len(times))], w.comm, w.uid, msg)
	}
	if !later {
		j.inTimeOrder()
		return
	}
	// numbered on, in time order among themselves: numbers never change
	j.mu.Lock()
	defer j.mu.Unlock()
	add := j.entries[len(j.entries)-k0:]
	sort.SliceStable(add, func(a, b int) bool { return add[a].at.Before(add[b].at) })
	for i := range add {
		add[i].seq = j.seq - len(add) + 1 + i
	}
}

// The index and the whole read agree on journals of tied times vacuumed
// anywhere (one sequence: numbers known). With the journal made anew in
// between (another seqnum_id), or an index saved before numbers were kept,
// times decide: then the index may be stricter, never less strict.
func TestLoginIndexSeqAgreesWithWholeRead(t *testing.T) {
	ips := []string{"203.0.113.10", "203.0.113.11"}
	now := time.Now().Truncate(time.Second)
	for _, mode := range []string{"one sequence", "journal made anew", "index of before"} {
		t.Run(mode, func(t *testing.T) {
			rng := rand.New(rand.NewSource(20261125))
			differ, wider, vacuumed := 0, 0, 0
			for n := 0; n < 300; n++ {
				j := &fakeJournal{}
				tiedJournal(rng, j, now, ips, false)
				d, _ := withIndex(t, j, &now)
				wholeRead(t, j, now)
				check(ips[0]) // the index built
				switch mode {
				case "journal made anew":
					j.sid = "fedcba9876543210fedcba9876543210"
					tiedJournal(rng, j, now, ips, true) // in another sequence, numbered on
					check(ips[0])
				case "index of before":
					stripSeqs(t, d)
				}
				if len(j.entries) > 1 {
					j.vacuum(1 + rng.Intn(len(j.entries)-1))
					vacuumed++
				}
				for _, ip := range ips {
					i, w := both(ip)
					if i != w {
						differ++
					}
					if i < w {
						wider++
						if wider <= 5 {
							t.Errorf("journal %d, %s: index %d less strict than the whole read %d", n, ip, i, w)
						}
					}
				}
			}
			if mode == "one sequence" && differ > 0 {
				t.Errorf("%d answers differ", differ)
			}
			if vacuumed < 200 {
				t.Errorf("only %d journals vacuumed", vacuumed)
			}
			t.Logf("%s: %d answers differ, %d less strict", mode, differ, wider)
		})
	}
}

// stripSeqs makes the saved index one of before numbers were kept.
func stripSeqs(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, LoginIndexFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		if strings.HasSuffix(k, "_seq") || strings.HasSuffix(k, "_seq_id") || k == "seq_id" {
			delete(m, k)
		}
	}
	addrs, _ := m["addrs"].(map[string]any)
	for _, a := range addrs {
		am, _ := a.(map[string]any)
		delete(am, "last_seq")
		delete(am, "forged_last_seq")
	}
	b, _ = json.Marshal(m)
	if strings.Contains(string(b), "_seq") {
		t.Fatalf("not stripped: %s", b)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An index of before (no numbers) at the first entry's own time: its
// event is not seen, its forged one refuses (each the strict side), and
// nothing panics.
func TestLoginIndexOldFormatSameTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	at := now.Add(-3 * time.Hour)
	j := &fakeJournal{}
	j.failed(at, "203.0.113.10")
	j.forged(at, "203.0.113.30")
	d, _ := withIndex(t, j, &now)
	wholeRead(t, j, now)
	check("203.0.113.10")
	stripSeqs(t, d)
	x := loadLoginIndex(d, now)
	if x == nil || x.Addrs["203.0.113.10"] == nil || x.Addrs["203.0.113.10"].LastSeq != 0 || x.JournalFromSeq != 0 {
		t.Fatalf("old index: %+v", x)
	}
	x.JournalFrom = at // the journal starts at their time, numbers unknown
	if seen, err := x.indexedLogins([]byte{203, 0, 113, 10}, now); seen || err != nil {
		t.Errorf("own event at JournalFrom: seen %v %v, want not seen (the strict side)", seen, err)
	}
	if _, err := x.indexedLogins([]byte{203, 0, 113, 30}, now); codeOf(err) != BlockUnverified {
		t.Errorf("forged event at JournalFrom: %v, want refused", err)
	}
}
