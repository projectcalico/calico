package asyncutil

import (
	"time"

	"github.com/sirupsen/logrus"
)

type RetryTimer interface {
	Close()
	Run(func()) (bool, error)
}

type retryRateLimiter struct {
	input  chan Command[func(), bool]
	notify <-chan time.Time
}

func NewRetryRateLimiter(maxTime time.Duration, waitDuration time.Duration, maxCount int) RetryTimer {
	input := make(chan Command[func(), bool])
	notify := make(chan time.Time, 1)
	callsMade := make(chan time.Time, maxCount)
	var callFuncChan <-chan time.Time
	var checkCalls <-chan time.Time

	type delayedCall struct {
		f func()
		t time.Time
	}

	go func() {
		defer close(notify)
		var calls []delayedCall
		for {
			select {
			case cmd, ok := <-input:
				// Shutdown signal.
				if !ok {
					logrus.Debug("Received shutdown signal, exiting.")
					return
				}

				if len(calls) >= maxCount {
					logrus.Debug("Rate limiter is full, dropping call.")
					cmd.Return(false)
					continue
				}

				calls = append(calls, delayedCall{f: cmd.Get(), t: time.Now()})

				if callFuncChan == nil {
					callFuncChan = time.After(waitDuration)
				}

				if checkCalls == nil {
					checkCalls = time.After(maxTime)
				}

				cmd.Return(WriteNoWait(callsMade, time.Now()))
				logrus.Debugf("Outstanding calls: %d", len(callsMade))
			case <-callFuncChan:
				// Call the function on the channel, there's guaranteed to be at least one.
				calls[0].f()
				calls = calls[1:]
				if len(calls) > 0 {
					callFuncChan = time.After(waitDuration)
				} else {
					callFuncChan = nil
				}
			case <-checkCalls:
				checkCalls = nil
				for {
					if next, has := ReadNoWait(callsMade); has {
						diff := time.Now().Sub(next)
						if !next.IsZero() && diff > maxTime {
							checkCalls = time.After(diff)
							break
						}
						continue
					}
					break
				}
			}
		}
	}()

	return &retryRateLimiter{input: input, notify: notify}
}

func (rt *retryRateLimiter) Notify() <-chan time.Time {
	return rt.notify
}

func (rt *retryRateLimiter) Run(f func()) (bool, error) {
	cmd, resultCh := NewCommand[func(), bool](f)
	rt.input <- cmd
	r := <-resultCh
	return r.Result()
}

func (rt *retryRateLimiter) Close() {
	close(rt.input)
}
