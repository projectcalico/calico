package time

import "time"

func init() {
	activeClock = newStdClock()
}

var activeClock Clock

type (
	Time = time.Time

	Duration = time.Duration
)

const (
	Minute      = time.Minute
	Hour        = time.Hour
	Second      = time.Second
	Millisecond = time.Millisecond
	Microsecond = time.Microsecond
	Nanosecond  = time.Nanosecond

	RFC3339Nano = time.RFC3339Nano
	RFC3339     = time.RFC3339
	RFC1123     = time.RFC1123
	RFC1123Z    = time.RFC1123Z
	RFC822      = time.RFC822
	RFC822Z     = time.RFC822Z
	RFC850      = time.RFC850
	Kitchen     = time.Kitchen
	Stamp       = time.Stamp
)

// DoWithClock temporarily sets the shim as the time and runs the given function. After the function is run, the time
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
	Sleep(d Duration)
	Unix(sec int64, nsec int64) Time
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

func Sleep(d Duration) {
	activeClock.Sleep(d)
}

func Unix(sec int64, nsec int64) Time {
	return activeClock.Unix(sec, nsec)
}

func Parse(layout, value string) (Time, error) {
	return time.Parse(layout, value)
}
