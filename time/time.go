package time

import (
	"time"
)

// Time is our shim interface to the time package.
type Time interface {
	Now() time.Time
	Since(t time.Time) time.Duration
}

func NewRealTime() Time {
	return &realTime{}
}

// realTime is the real implementation of timeIface, which calls through to the real time package.
type realTime struct{}

func (realTime) Now() time.Time {
	return time.Now()
}

func (realTime) Since(t time.Time) time.Duration {
	return time.Since(t)
}
