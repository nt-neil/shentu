package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNextDaily(t *testing.T) {
	loc := time.FixedZone("UTC+8", 8*3600)
	for _, c := range []struct{ now, want time.Time }{
		{time.Date(2026, 11, 12, 8, 59, 0, 0, loc), time.Date(2026, 11, 12, 9, 0, 0, 0, loc)},
		{time.Date(2026, 11, 12, 9, 0, 0, 0, loc), time.Date(2026, 11, 13, 9, 0, 0, 0, loc)},
		{time.Date(2026, 12, 31, 23, 0, 0, 0, loc), time.Date(2027, 1, 1, 9, 0, 0, 0, loc)},
	} {
		if got := nextDaily(c.now, 9); !got.Equal(c.want) {
			t.Errorf("nextDaily(%v) = %v, want %v", c.now, got, c.want)
		}
	}
}

func TestRunSchedule(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var runs []bool
	dailyAt := time.Now().Add(55 * time.Millisecond)
	daily := func(now time.Time) time.Time {
		if now.Before(dailyAt) {
			return dailyAt
		}
		return now.Add(time.Hour)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSchedule(ctx, 10*time.Millisecond, 20*time.Millisecond, 0, daily, func(d bool) error {
			mu.Lock()
			runs = append(runs, d)
			mu.Unlock()
			return nil
		}, t.Logf)
	}()
	time.Sleep(120 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runSchedule must return when the context ends")
	}
	mu.Lock()
	defer mu.Unlock()
	patrols, dailies := 0, 0
	for _, d := range runs {
		if d {
			dailies++
		} else {
			patrols++
		}
	}
	if dailies != 1 || patrols < 3 {
		t.Errorf("runs %v: want one daily report and several patrols", runs)
	}
}
