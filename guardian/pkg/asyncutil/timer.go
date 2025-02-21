package asyncutil

import (
	"github.com/sirupsen/logrus"
	"time"
)

type RetryTimer interface {
	Sig() (bool, error)
	Close()
	Next() <-chan time.Time
}

type retryTimer struct {
	input chan Command[any, bool]
	next  <-chan time.Time
}

func NewRetryTimer(maxTime time.Duration, waitDur time.Duration, maxCount int) RetryTimer {
	input := make(chan Command[any, bool])
	times := make(chan time.Time, maxCount)
	nextTime := make(chan time.Time, 1)

	var check <-chan time.Time
	go func() {
		defer close(nextTime)
		for {
			select {
			case cmd, ok := <-input:
				// Shutdown signal.
				if !ok {
					logrus.Debug("Received shutdown signal, exiting.")
					return
				}

				if check == nil {
					WriteNoWait(nextTime, time.Now())
					check = time.After(waitDur)
				}

				// If the channel is full then that indicates that we have reached max copacity within the
				// time period, so we return false.
				cmd.Return(WriteNoWait(times, time.Now()))
			case <-check:
				WriteNoWait(nextTime, time.Now())
				// Initially set the channel to nil so it "pauses" reading from it. It will be set to a non nil value
				// if there are any times on the times channel that haven't expired.
				check = nil
				for {
					if next, has := ReadNoWait(times); has {
						diff := time.Now().Sub(next)
						if !next.IsZero() && diff > maxTime {
							check = time.After(waitDur)
							break
						}
						continue
					}
					break
				}
			}
		}
	}()

	return &retryTimer{input, nextTime}
}

func (rt *retryTimer) Sig() (bool, error) {
	cmd, resultCh := NewCommand[any, bool](nil)
	rt.input <- cmd
	r := <-resultCh
	return r.Result()
}

func (rt *retryTimer) Next() <-chan time.Time {
	return rt.next
}

func (rt *retryTimer) Close() {
	close(rt.input)
}
