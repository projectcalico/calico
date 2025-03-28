// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package chanutil

import (
	"context"
	"errors"
	"time"
)

var (
	ErrChannelClosed    = errors.New("channel closed")
	ErrDeadlineExceeded = errors.New("deadline exceeded")
)

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

// Write writes to the given channel and blocks until either the object is written to the channel, or the context is
// closed.
func Write[E any](ctx context.Context, ch chan E, v E) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ch <- v:
		return nil
	}
}

// WriteNonBlocking writes to the given channel in a non-blocking manner. It return true if the write was successful,
// and false otherwise.
func WriteNonBlocking[E any](ch chan<- E, v E) bool {
	select {
	case ch <- v:
		return true
	default:
		return false
	}
}

// WriteWithDeadline is similar to Write but adds the extra convenience of allowing a duration to be specified which defines
// the deadline that the channel has to write data.
//
// The same thing could be done with Write using context.Deadline but it requires managing more contexts and cancel functions,
// which can be tedious when managing multiple channels in this manner.
func WriteWithDeadline[E any](ctx context.Context, ch chan E, v E, duration time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ch <- v:
		return nil
	case <-time.After(duration):
		return ErrDeadlineExceeded
	}
}
