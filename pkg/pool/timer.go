package pool

import (
	"sync"
	"time"
)

var (
	timerPool = sync.Pool{}
)

// GetTimer gets a timer from the pool and resets it to the given duration.
func GetTimer(d time.Duration) *time.Timer {
	timer, ok := timerPool.Get().(*time.Timer)
	if !ok {
		return time.NewTimer(d)
	}

	// If Reset returns true, the timer was still active.
	// Instead of panicking, we stop it and create a fresh one to be safe.
	if !timer.Stop() {
		// Drain the channel if necessary
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
	return timer
}

// ReleaseTimer stops the timer, drains its channel, and returns it to the pool.
func ReleaseTimer(timer *time.Timer) {
	if timer == nil {
		return
	}

	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timerPool.Put(timer)
}

// ResetAndDrainTimer stops the timer, drains the channel, and starts it again with new duration.
func ResetAndDrainTimer(timer *time.Timer, d time.Duration) {
	if timer == nil {
		return
	}

	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}
