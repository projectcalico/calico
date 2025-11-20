package time

import "time"

func init() {
	activeClock = newStdClock()
}

var activeClock Clock

type (
	Time = time.Time

	Duration = time.Duration

	Weekday = time.Weekday

	Month = time.Month

	Location = time.Location
)

const (
	Sunday    Weekday = time.Sunday
	Monday    Weekday = time.Monday
	Tuesday   Weekday = time.Tuesday
	Wednesday Weekday = time.Wednesday
	Thursday  Weekday = time.Thursday
	Friday    Weekday = time.Friday
	Saturday  Weekday = time.Saturday

	January   Month = time.January
	February  Month = time.February
	March     Month = time.March
	April     Month = time.April
	May       Month = time.May
	June      Month = time.June
	July      Month = time.July
	August    Month = time.August
	September Month = time.September
	October   Month = time.October
	November  Month = time.November
	December  Month = time.December
)

const (
	Day         = 24 * time.Hour
	Hour        = time.Hour
	Minute      = time.Minute
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
	DateOnly    = time.DateOnly
	DateTime    = time.DateTime
	UnixDate    = time.UnixDate
)

var (
	UTC   = time.UTC
	Local = time.Local
)

// DoWithClock temporarily sets the shim as the time and runs the given function. After the function is run, the time
// is returned to its original state.
func DoWithClock(shim Clock, fn func() error) error {
	defer func(c Clock) { activeClock = c }(activeClock)
	activeClock = shim
	return fn()
}

type CleanUpRegisterable interface {
	Cleanup(func())
}

// ShimClockForTestingT temporarily sets the shim as the time and runs the given function for a test and when the test
// is done, the time is returned to its original state.
func ShimClockForTestingT(t CleanUpRegisterable, shim Clock) {
	original := activeClock
	activeClock = shim

	t.Cleanup(func() {
		activeClock = original
	})
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

func Date(year int, month Month, day, hour, min, sec, nsec int, loc *Location) Time {
	return time.Date(year, month, day, hour, min, sec, nsec, loc)
}

func FixedZone(name string, offset int) *Location {
	return time.FixedZone(name, offset)
}

func ParseDuration(s string) (Duration, error) {
	return time.ParseDuration(s)
}

func ParseInLocation(layout, value string, loc *Location) (Time, error) {
	return time.ParseInLocation(layout, value, loc)
}
