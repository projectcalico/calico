package timeutil

import "time"

func init() {
	stdTime = NewStdTime()
}

var stdTime Interface

func SetTimeInterface(tInf Interface) {
	stdTime = tInf
}

type Time = time.Time
type Duration = time.Duration

// Interface is our shim interface to the time package.
type Interface interface {
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
	return stdTime.Now()
}

func Since(t Time) time.Duration {
	return stdTime.Since(t)
}

func Until(t Time) time.Duration {
	return stdTime.Until(t)
}

func After(t Duration) <-chan Time {
	return stdTime.After(t)
}

func NewTimer(d Duration) Timer {
	return stdTime.NewTimer(d)
}

func NewTicker(d Duration) Ticker {
	return stdTime.NewTicker(d)
}
