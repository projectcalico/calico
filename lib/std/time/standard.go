package time

import "time"

type stdClock struct{}

func newStdClock() Clock {
	return &stdClock{}
}

func (std *stdClock) Now() Time {
	return time.Now()
}

func (std *stdClock) Since(t Time) time.Duration {
	return time.Since(t)
}

func (std *stdClock) Until(t Time) time.Duration {
	return time.Until(t)
}

func (std *stdClock) After(t Duration) <-chan Time {
	return time.After(t)
}

func (std *stdClock) NewTimer(d Duration) Timer {
	return &stdTimer{Timer: time.NewTimer(d)}
}

func (std *stdClock) NewTicker(d Duration) Ticker {
	return &stdTicker{Ticker: time.NewTicker(d)}
}
func (std *stdClock) Sleep(d Duration) {
	time.Sleep(d)
}

func (std *stdClock) Unix(sec int64, nsec int64) Time {
	return time.Unix(sec, nsec)
}

type stdTicker struct {
	*time.Ticker
}

func (ticker *stdTicker) Chan() <-chan Time {
	return ticker.C
}

type stdTimer struct {
	*time.Timer
}

func (s stdTimer) Chan() <-chan Time {
	return s.C
}
