package chanutil

import (
	"context"
	"errors"
	"time"
)

var ErrChannelClosed = errors.New("channel closed")
var ErrDeadlineExceeded = errors.New("deadline exceeded")

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
			err = ErrChannelClosed
		}
		return v, err
	}
}

// ReadWithDeadline is similar to Read but adds the extra convenience of allowing a duration to be specified which defines
// the deadline that the channel has to read data.
//
// The same thing could be done with Read using context.Deadline but it requires managing more contexts and cancel functions,
// which can be tedious when managing multiple channels in this manner.
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
		return def, ErrDeadlineExceeded
	}
}
