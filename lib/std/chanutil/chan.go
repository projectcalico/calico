package chanutil

import (
	"context"
	"errors"
	"time"
)

var ErrChannelClosed = errors.New("context canceled")

// Read reads from the given channel and blocks until either an object is pulled off the channel, the context
// is done, or the channel is closed.
func Read[E any](ctx context.Context, ch <-chan E) (E, error) {
	select {
	case <-ctx.Done():
		var d E
		return d, ctx.Err()
	case v, ok := <-ch:
		var err error
		if !ok {
			err = errors.New("channel closed")
		}
		return v, err
	}
}

func ReadWithDeadline[E any](ctx context.Context, ch <-chan E, duration time.Duration) (E, error) {
	var def E

	select {
	case <-ctx.Done():
		return def, ctx.Err()
	case v, ok := <-ch:
		if !ok {
			return def, ErrChannelClosed
		}
		return v, nil
	case <-time.After(duration):
		return def, errors.New("timed out")
	}
}
