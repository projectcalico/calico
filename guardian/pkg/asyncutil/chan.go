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

package asyncutil

import (
	"context"
	"errors"
)

// ReadWithContext reads from the given channel and blocks until either an object is pulled off the channel, the context
// is done, or the channel is closed.
func ReadWithContext[S any](ctx context.Context, ch <-chan S) (S, error) {
	select {
	case <-ctx.Done():
		var d S
		return d, ctx.Err()
	case v, ok := <-ch:
		var err error
		if !ok {
			err = errors.New("channel closed")
		}
		return v, err
	}
}

// WriteNoWait writes the given value to the given channel but doesn't wait to do so if the channel is full. If the
// channel is full then it returns and the return value will be false.
func WriteNoWait[R any](c chan R, o R) bool {
	select {
	case c <- o:
		return true
	default:
		return false
	}
}

// ReadNoWait reads a value off the channel if there is one. If the channel is empty, it returns. The second return value
// says whether a values were read off the channel or if it was empty.
func ReadNoWait[R any](c <-chan R) (R, bool) {
	select {
	case v := <-c:
		return v, true
	default:
		var v R
		return v, false
	}
}

// ReadAll reads all the values off the channel and returns them as an array. It doesn't wait for the channel to be
// closed to return.
func ReadAll[R any](c <-chan R) []R {
	var out []R
	for {
		select {
		case v, ok := <-c:
			if !ok {
				return out
			}
			out = append(out, v)
		default:
			return out
		}
	}
}

// Clear removes all items from the channel and returns. It doesn't wait for the channel to close to return.
func Clear[R any](c chan R) {
	for {
		select {
		case <-c:
		default:
			return
		}
	}
}
