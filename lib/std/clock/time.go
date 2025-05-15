package clock

import "time"

func init() {
	activeClock = newStdClock()
}

var activeClock Clock

type Time = time.Time
type Duration = time.Duration

// DoWithClock temporarily sets the shim as the clock and runs the given function. After the function is run, the clock
// is returned to its original state.
func DoWithClock(shim Clock, fn func() error) error {
	defer func(c Clock) { activeClock = c }(activeClock)
	activeClock = shim
	return fn()
}

// Clock is our shim interface to the time package.
type Clock interface {
	Now() Time
	Since(t Time) time.Duration
	Until(t Time) time.Duration
	After(t Duration) <-chan Time
	NewTimer(d Duration) Timer
	NewTicker(d Duration) Ticker
}

type Timer interface {
	Stop() bool
	Reset(d Duration) bool
	Chan() <-chan Time
}

type Ticker interface {
	Stop()
	Reset(d Duration)
	Chan() <-chan Time
}

func Now() Time {
	return activeClock.Now()
}

func Since(t Time) time.Duration {
	return activeClock.Since(t)
}

func Until(t Time) time.Duration {
	return activeClock.Until(t)
}

func After(t Duration) <-chan Time {
	return activeClock.After(t)
}

func NewTimer(d Duration) Timer {
	return activeClock.NewTimer(d)
}

func NewTicker(d Duration) Ticker {
	return activeClock.NewTicker(d)
}
