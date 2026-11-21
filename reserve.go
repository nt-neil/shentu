package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/nt-neil/shentu/internal/osutil"
)

// Shared reservations (phase 4, R1). Each dispatch, from the bot, shentu
// chat or the patrol's automatic incident check, reserves its whole token
// cap in state_dir/reservations.json before it starts and releases it when
// it ends. The budget checks count the reservations of the others: two
// processes that dispatch at once no longer each see the month's room as
// their own. A reservation left by a process that died expires after
// reserveTTL. A file that cannot be trusted or read stops the dispatch
// (fail closed). Only with [budget] monthly_tokens: without a token limit
// there is nothing to share.
//
// The bound: a model call goes ahead only while the month's use plus the
// others' reservations is under the limit, so the others' whole caps fit in
// it, and only the caller's own dispatch can run past it. Together they
// overspend the monthly token limit by about one dispatch's cap
// (dispatchTokenCap) plus the answer in progress (a commander's answer is
// checked when it starts, then runs its steps), never by one cap per
// process.
//
// What a dispatch in progress has already spent is in log.jsonl and would
// be in its reservation too: a reservation knows its dispatch and when it
// started, and the checks take what that dispatch has logged since off it,
// from the same read of the log as the month's use (S-R-2, usageWithOthers).
// When that cannot be matched, the reservation counts in full.

const (
	reservationsFile = "reservations.json"
	reservationsLock = "reservations.lock"
)

// reserveTTL is how long a reservation lives: longer than any dispatch runs.
func reserveTTL() time.Duration { return dispatchTimeout + 5*time.Minute }

var errReservations = errors.New("the shared AI budget reservations cannot be trusted")

type reservation struct {
	ID      string    `json:"id"`
	Tokens  int       `json:"tokens"`
	Cost    float64   `json:"cost,omitempty"` // what it may cost, with [agents] prices set (R2)
	Expires time.Time `json:"expires"`
	// S-R-2: the dispatch it is for and when it started; what that dispatch
	// has logged since is in log.jsonl already, so the others count only
	// the rest of its reservation.
	Dispatch string    `json:"dispatch,omitempty"`
	Started  time.Time `json:"started,omitempty"`
}

type reservations struct {
	V     int           `json:"v"`
	Items []reservation `json:"items"`
}

// withReservations runs f on the reservations under their lock and saves
// what f leaves, dropping the expired ones. A link, a file of another user
// or one others may read or write, or one that does not parse, is an error.
func withReservations(cfg *Config, now time.Time, f func(*reservations)) error {
	dir := cfg.StateDir
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: state_dir is not an absolute path", errReservations)
	}
	lp := filepath.Join(dir, reservationsLock)
	lf, err := osutil.OpenNoFollow(lp, os.O_RDWR|os.O_CREATE, 0o600, true)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", errReservations, lp, err)
	}
	defer lf.Close()
	if st, err := lf.Stat(); err != nil || !trusted(st, false) {
		return fmt.Errorf("%w: %s (it must be a 0600 file of this service's user; move it aside to reset it)", errReservations, lp)
	}
	if err := osutil.Lock(lf); err != nil {
		return err
	}
	p := filepath.Join(dir, reservationsFile)
	var r reservations
	switch f, err := osutil.OpenNoFollow(p, os.O_RDONLY, 0, true); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("%w: %s: %v", errReservations, p, err)
	default:
		st, serr := f.Stat()
		b, rerr := io.ReadAll(f)
		f.Close()
		if serr != nil || !trusted(st, false) || rerr != nil {
			return fmt.Errorf("%w: %s (it must be a 0600 file of this service's user; move it aside to reset it)", errReservations, p)
		}
		if len(b) > 0 && (json.Unmarshal(b, &r) != nil || r.V != 1) {
			return fmt.Errorf("%w: %s does not parse (move it aside to reset it)", errReservations, p)
		}
	}
	if negativeReservation(r) { // S-R-6: not dropped quietly, like a file that does not parse
		return fmt.Errorf("%w: %s holds a negative reservation (move it aside to reset it)", errReservations, p)
	}
	var keep []reservation
	for _, it := range r.Items {
		if now.Before(it.Expires) {
			keep = append(keep, it)
		}
	}
	r.V, r.Items = 1, keep
	f(&r)
	b, _ := json.Marshal(r)
	return writeAtomic(p, b)
}

// reserve reserves tokens for a dispatch and returns its id and a release.
// Without a monthly token limit it reserves nothing.
func reserve(cfg *Config, tokens int, cost float64, now time.Time) (id string, release func(), err error) {
	return reserveFor(cfg, tokens, cost, "", now)
}

// reserveFor is reserve for the dispatch with that id (S-R-2), "" for none.
func reserveFor(cfg *Config, tokens int, cost float64, dispatch string, now time.Time) (id string, release func(), err error) {
	if cfg.Budget.MonthlyTokens <= 0 {
		return "", func() {}, nil
	}
	b := make([]byte, 6)
	rand.Read(b)
	id = hex.EncodeToString(b)
	err = withReservations(cfg, now, func(r *reservations) {
		r.Items = append(r.Items, reservation{ID: id, Tokens: tokens, Cost: cost, Expires: now.Add(reserveTTL()), Dispatch: dispatch, Started: now})
	})
	if err != nil {
		return "", func() {}, err
	}
	return id, func() {
		err := withReservations(cfg, time.Now(), func(r *reservations) {
			var keep []reservation
			for _, it := range r.Items {
				if it.ID != id {
					keep = append(keep, it)
				}
			}
			r.Items = keep
		})
		if err != nil { // it holds its tokens until it expires: fail closed, but said
			fmt.Fprintf(os.Stderr, "shentu: warning: the AI budget reservation %s could not be released (%v); it counts until it expires in %d minutes at most\n", id, err, int(reserveTTL().Minutes()))
		}
	}, nil
}

// peekReserved is the tokens and cost the live reservations hold, read without the
// lock and without writing (the file is replaced atomically): for the
// budget line, which `sudo shentu budget` prints as another user, who must
// not create the lock file.
func peekReserved(cfg *Config, now time.Time) (int, float64, error) {
	p := filepath.Join(cfg.StateDir, reservationsFile)
	f, err := osutil.OpenNoFollow(p, os.O_RDONLY, 0, true)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return 0, 0, err
	}
	var r reservations
	if len(b) > 0 && (json.Unmarshal(b, &r) != nil || r.V != 1) {
		return 0, 0, fmt.Errorf("%s does not parse", p)
	}
	if negativeReservation(r) {
		return 0, 0, fmt.Errorf("%s holds a negative reservation", p)
	}
	n, c := 0, 0.0
	for _, it := range r.Items {
		if now.Before(it.Expires) {
			n += it.Tokens
			c += it.Cost
		}
	}
	return n, c, nil
}

// negativeReservation: an item holds less than nothing, which no
// dispatch writes; the file is then not trusted (S-R-6).
func negativeReservation(r reservations) bool {
	for _, it := range r.Items {
		if it.Tokens < 0 || it.Cost < 0 {
			return true
		}
	}
	return false
}

// othersReserved is the tokens and the cost the live reservations hold,
// but self's.
func othersReserved(cfg *Config, self string, now time.Time) (tokens int, cost float64, err error) {
	if cfg.Budget.MonthlyTokens <= 0 {
		return 0, 0, nil
	}
	err = withReservations(cfg, now, func(r *reservations) {
		for _, it := range r.Items {
			if it.ID != self {
				tokens, cost = tokens+it.Tokens, cost+it.Cost
			}
		}
	})
	return tokens, cost, err
}

type spentUse struct {
	tokens int
	cost   float64
}

// monthUse is the month's use and what the others' reservations hold of the
// rest, from one read of each (S-R-2).
type monthUse struct {
	cost         float64
	tokens       int
	othersTokens int
	othersCost   float64
}

// usageWithOthers reads the reservations (all but self's) under their
// lock, then log.jsonl once: the month's use and, in the same pass, what
// each reserved dispatch has logged since its reservation started. That
// part is in the month's use already, so it is taken off the reservation,
// down to 0 at most (S-R-2). A reservation without its dispatch's id or
// started in the future counts in full. An untrusted reservation file is
// an errReservations error; a log that cannot be read, its error.
func usageWithOthers(cfg *Config, self string, now time.Time) (monthUse, error) {
	var items []reservation
	err := withReservations(cfg, now, func(r *reservations) {
		for _, it := range r.Items {
			if it.ID != self {
				items = append(items, it)
			}
		}
	})
	if err != nil {
		return monthUse{}, err
	}
	started := map[string]time.Time{}
	for _, it := range items {
		if len(it.Dispatch) == 12 && !it.Started.IsZero() && !it.Started.After(now) {
			started[it.Dispatch] = it.Started
		}
	}
	var u monthUse
	var spent map[string]spentUse
	u.cost, u.tokens, _, spent, err = monthScan(cfg.StateDir, now, started)
	if err != nil {
		return monthUse{}, err
	}
	for _, it := range items {
		s := spentUse{}
		if _, ok := started[it.Dispatch]; ok {
			s = spent[it.Dispatch]
		}
		u.othersTokens += max(0, it.Tokens-s.tokens)
		u.othersCost += max(0, it.Cost-s.cost)
	}
	return u, nil
}

// dispatchCost is what a dispatch may cost at most: its whole token cap at
// the dearer of the [agents] prices; 0 when they are not set.
func dispatchCost(cfg *Config) float64 {
	price := max(cfg.Agents.PricePerMTokIn, cfg.Agents.PricePerMTokOut)
	if price <= 0 {
		return 0
	}
	return float64(dispatchTokenCap) / 1e6 * price
}
