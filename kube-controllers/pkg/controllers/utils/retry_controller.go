// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

func NewRetryController(w func() time.Duration, r, s func()) *RetryController {
	return &RetryController{
		whenFn:    w,
		retryFn:   r,
		successFn: s,
	}
}

// RetryController is a helper structure for managing a retry with a backoff mechanism. Note that the retry function
// is called asynchronously, so should use a channel to communicate back with the main loop. This is intentional, to allow
// for scheduled retries without sleeping on the main goroutine, otherwise blocking work.
type RetryController struct {
	sync.Mutex
	retryPending bool

	// whenFn is a function that returns a time to wait before the next retry.
	whenFn func() time.Duration

	// retryFn is the function to call after a retry timer pops.
	retryFn func()

	// successFn is the function to call on success.
	successFn func()
}

func (c *RetryController) ScheduleRetry() {
	// We keep at most one retry pending.
	if c.pending() {
		logrus.Debug("Retry is already pending")
		return
	}

	// Schedule a retry.
	c.mark()
	go c.scheduledRetry(c.whenFn())
}

func (c *RetryController) Success() {
}

func (c *RetryController) scheduledRetry(wait time.Duration) {
	// Wait the retry duration, then kick the channel.
	logrus.WithField("wait", wait).Info("Scheduling retry")
	<-time.After(wait)
	logrus.Debug("Scheduled retry popped")
	c.clear()
	c.retryFn()
}

func (c *RetryController) pending() bool {
	c.Lock()
	defer c.Unlock()
	return c.retryPending
}

func (c *RetryController) clear() {
	c.Lock()
	defer c.Unlock()
	c.retryPending = false
}

func (c *RetryController) mark() {
	c.Lock()
	defer c.Unlock()
	c.retryPending = true
}
