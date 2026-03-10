// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package utils

import (
	log "github.com/sirupsen/logrus"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"
)

const defaultMaxRetries = 5

// RetryWorkqueue wraps a rate-limiting workqueue to provide retry-with-backoff for controllers
// that use a channel-based event loop rather than the standard K8s worker pattern. Failed items
// are requeued with exponential backoff up to maxRetries, then dropped.
//
// Use Retry() to feed back into the event loop: items are rate-limited by the workqueue and
// delivered to the Retry() channel when ready for reprocessing.
type RetryWorkqueue[T comparable] struct {
	queue      workqueue.TypedRateLimitingInterface[T]
	retryChan  chan T
	maxRetries int
	name       string
}

// NewRetryWorkqueue creates a RetryWorkqueue with the default controller rate limiter and max retries.
func NewRetryWorkqueue[T comparable](name string) *RetryWorkqueue[T] {
	return &RetryWorkqueue[T]{
		queue:      workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[T]()),
		retryChan:  make(chan T, BatchUpdateSize),
		maxRetries: defaultMaxRetries,
		name:       name,
	}
}

// Run starts the feeder goroutine that pulls items from the workqueue (after rate-limited delay)
// and sends them to the Retry() channel. Call this once at the start of the event loop goroutine.
// The goroutine exits when ShutDown is called.
func (r *RetryWorkqueue[T]) Run() {
	go func() {
		for {
			key, quit := r.queue.Get()
			if quit {
				return
			}
			r.retryChan <- key
			r.queue.Done(key)
		}
	}()
}

// ShutDown shuts down the underlying workqueue. Must be called when the controller stops.
func (r *RetryWorkqueue[T]) ShutDown() {
	r.queue.ShutDown()
}

// Retry returns a channel that delivers items ready for reprocessing after their rate-limited delay.
// Read from this channel in the controller's select loop.
func (r *RetryWorkqueue[T]) Retry() <-chan T {
	return r.retryChan
}

// Enqueue adds an item to the workqueue for immediate processing (subject to dedup). Use this
// from informer event handlers to feed items into the processing loop.
func (r *RetryWorkqueue[T]) Enqueue(key T) {
	r.queue.Add(key)
}

// HandleErr handles the result of processing an item. On success (err==nil), it clears the retry
// counter. On failure, it requeues with rate-limited backoff up to maxRetries, then drops the item.
func (r *RetryWorkqueue[T]) HandleErr(err error, key T) {
	if err == nil {
		r.queue.Forget(key)
		return
	}
	if r.queue.NumRequeues(key) < r.maxRetries {
		log.WithError(err).WithFields(log.Fields{"controller": r.name, "key": key}).Warn("Error processing item, will retry")
		r.queue.AddRateLimited(key)
		return
	}
	r.queue.Forget(key)
	log.WithError(err).WithFields(log.Fields{"controller": r.name, "key": key}).Error("Dropping item after max retries")
	uruntime.HandleError(err)
}
