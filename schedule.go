package main

import (
	"context"
	"math/rand/v2"
	"time"
)

// The patrol schedule of the Windows service, the same as the systemd
// timers in packaging/: a patrol every 30 minutes (plus up to a minute of
// jitter) and the daily report at 09:00 local time.
const (
	patrolEvery  = 30 * time.Minute
	patrolJitter = time.Minute
	dailyHour    = 9
)

// nextDaily is the next hour:00 local time strictly after now.
func nextDaily(now time.Time, hour int) time.Time {
	t := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if !t.After(now) {
		t = t.AddDate(0, 0, 1)
	}
	return t
}

// runSchedule calls run(false) every `every` (plus jitter) and run(true) at
// each daily time, until ctx ends. The first patrol starts after first,
// so a restarting service does not patrol in a loop. run's errors go to
// logf; the schedule keeps going.
func runSchedule(ctx context.Context, first, every, jitter time.Duration, daily func(time.Time) time.Time,
	run func(daily bool) error, logf func(string, ...any)) {
	now := time.Now()
	nextPatrol, nextDay := now.Add(first), daily(now)
	for {
		at, isDaily := nextPatrol, false
		if !nextDay.After(nextPatrol) {
			at, isDaily = nextDay, true
		}
		t := time.NewTimer(time.Until(at))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if err := run(isDaily); err != nil {
			logf("patrol (daily %v): %v", isDaily, err)
		}
		now = time.Now()
		if isDaily {
			nextDay = daily(now)
		} else {
			var j time.Duration
			if jitter > 0 {
				j = rand.N(jitter)
			}
			nextPatrol = now.Add(every + j)
		}
	}
}
