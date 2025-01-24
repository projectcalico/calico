// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package _chan

import (
	"context"
	"fmt"
	"time"
)

// ReadBatch reads a maximum elements of `maxBatchSize` from the given channel and returns that batch as a list of
// elements.
func ReadBatch[V any](ch chan V, maxBatchSize int) []V {
	var batch []V

loop:
	for i := 0; i < maxBatchSize; i++ {
		select {
		case v, ok := <-ch:
			if !ok {
				break loop
			}

			batch = append(batch, v)
		default:
			break loop
		}
	}

	return batch
}

// ReadWithTimeout takes in a context and a read only channel and blocks until either the context is cancelled or the channel receives.
func ReadWithTimeout[S any](ctx context.Context, ch <-chan S, duration time.Duration) (S, bool) {
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	return ReadWithContext[S](ctx, ch)
}

// ReadWithContext takes in a context and a read only channel and blocks until either the context is cancelled or the channel receives.
func ReadWithContext[S any](ctx context.Context, ch <-chan S) (S, bool) {
	select {
	case <-ctx.Done():
		var d S
		return d, true
	case v := <-ch:
		return v, false
	}
}

// ReadWithContextAndCheckClosedChannel takes in a context and a read only channel, and blocks until either the context is cancelled or the
// channel receives. It checks for whether the channel is closed or not, and expects that the channel is closed before the context is
// cancelled. If the context is cancelled early, then we return an error.
func ReadWithContextAndCheckClosedChannel[S any](ctx context.Context, ch <-chan S) (S, bool, error) {
	select {
	case <-ctx.Done():
		var d S
		return d, true, fmt.Errorf("context closed early")
	case v, ok := <-ch:
		if !ok {
			return v, true, nil
		}
		return v, false, nil
	}
}

// ReadNoWait takes in a read only channel and does not block.
func ReadNoWait[S any](ch <-chan S) S {
	select {
	case v := <-ch:
		return v
	default:
		var v S
		return v
	}
}

func WriteNoWait[R any](c chan R, o R) {
	select {
	case c <- o:
	default:
	}
}

// WriteWithContext takes in a channel, a type, and a context and attempts to write the type onto the channel. It waits
// until it either writes the type to the channel or context.Done receives (in which case true is returned). The return
// type signals whether the context.Done received or not.
func WriteWithContext[R any](ctx context.Context, c chan<- R, o R) bool {
	select {
	case c <- o:
	case <-ctx.Done():
		return true
	}
	return false
}

func WriteWithTimeout[R any](parentCtx context.Context, timeout time.Duration, c chan<- R, o R) bool {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	select {
	case c <- o:
	case <-ctx.Done():
		return true
	}
	return false
}

// ReadAll reads all items from the channel and returns them as a list. It keeps reading until the channel is closed.
func ReadAll[T any](ch chan T) []T {
	var result []T
	for item := range ch {
		result = append(result, item)
	}
	return result
}
