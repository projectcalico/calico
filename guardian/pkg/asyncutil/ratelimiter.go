package asyncutil

import (
	"errors"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

type FuncCallRateLimiter[P any, V any] interface {
	Close()
	Run(P) <-chan Result[V]
}

type retryRateLimiter[P any, V any] struct {
	pChan chan Command[P, V]
}

func NewFunctionCallRateLimiter[P any, V any](waitDuration time.Duration, windowDuration time.Duration, maxCalls int, f func(P) (V, error)) FuncCallRateLimiter[P, V] {
	var callTimestamps []time.Time
	pChan := make(chan Command[P, V], 100)
	var lastTimestamp time.Time
	go func() {
		for {
			select {
			case cmd, ok := <-pChan:
				if !ok {
					logrus.Debug("Received shutdown signal, exiting...")
					return
				}

				validCalls := make([]time.Time, 0, maxCalls)
				for _, t := range callTimestamps {
					if time.Now().Sub(t) <= windowDuration {
						validCalls = append(validCalls, t)
					}
				}
				callTimestamps = validCalls

				if len(callTimestamps) > maxCalls {
					cmd.ReturnError(ErrRateLimitExceeded)
					continue
				}

				if !lastTimestamp.IsZero() && time.Now().Sub(lastTimestamp) < waitDuration {
					<-time.After(waitDuration)
				}

				// Call the function.
				v, err := f(cmd.Get())
				lastTimestamp = time.Now()
				if err != nil {
					cmd.ReturnError(err)
				} else {
					cmd.Return(v)
				}

				callTimestamps = append(callTimestamps, time.Now())
			}
		}
	}()

	return &retryRateLimiter[P, V]{pChan: pChan}
}

func (rl *retryRateLimiter[P, V]) Run(p P) <-chan Result[V] {
	cmd, resultChan := NewCommand[P, V](p)
	rl.pChan <- cmd
	return resultChan
}

func (rl *retryRateLimiter[P, V]) Close() {
	close(rl.pChan)
}
