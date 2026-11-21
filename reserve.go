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
// overspend the monthly token limit by at most one dispatch's cap
// (dispatchTokenCap), never by one cap per process.

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
	Expires time.Time `json:"expires"`
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
	var keep []reservation
	for _, it := range r.Items {
		if now.Before(it.Expires) && it.Tokens >= 0 {
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
func reserve(cfg *Config, tokens int, now time.Time) (id string, release func(), err error) {
	if cfg.Budget.MonthlyTokens <= 0 {
		return "", func() {}, nil
	}
	b := make([]byte, 6)
	rand.Read(b)
	id = hex.EncodeToString(b)
	err = withReservations(cfg, now, func(r *reservations) {
		r.Items = append(r.Items, reservation{ID: id, Tokens: tokens, Expires: now.Add(reserveTTL())})
	})
	if err != nil {
		return "", func() {}, err
	}
	return id, func() {
		withReservations(cfg, time.Now(), func(r *reservations) {
			var keep []reservation
			for _, it := range r.Items {
				if it.ID != id {
					keep = append(keep, it)
				}
			}
			r.Items = keep
		})
	}, nil
}

// peekReserved is the tokens the live reservations hold, read without the
// lock and without writing (the file is replaced atomically): for the
// budget line, which `sudo shentu budget` prints as another user, who must
// not create the lock file.
func peekReserved(cfg *Config, now time.Time) (int, error) {
	p := filepath.Join(cfg.StateDir, reservationsFile)
	f, err := osutil.OpenNoFollow(p, os.O_RDONLY, 0, true)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return 0, err
	}
	var r reservations
	if len(b) > 0 && (json.Unmarshal(b, &r) != nil || r.V != 1) {
		return 0, fmt.Errorf("%s does not parse", p)
	}
	n := 0
	for _, it := range r.Items {
		if now.Before(it.Expires) && it.Tokens >= 0 {
			n += it.Tokens
		}
	}
	return n, nil
}

// othersReserved is the tokens the live reservations hold, but self's.
func othersReserved(cfg *Config, self string, now time.Time) (int, error) {
	if cfg.Budget.MonthlyTokens <= 0 {
		return 0, nil
	}
	n := 0
	err := withReservations(cfg, now, func(r *reservations) {
		for _, it := range r.Items {
			if it.ID != self {
				n += it.Tokens
			}
		}
	})
	return n, err
}
