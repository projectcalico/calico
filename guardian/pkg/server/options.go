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

package server

import (
	"time"
)

// Option is a common format for New() options
type Option func(*server) error

// WithProxyTargets sets the proxying targets, can be used multiple times to add
// to a union of target.
func WithProxyTargets(tgts []Target) Option {
	return func(c *server) error {
		c.targets = append(c.targets, tgts...)
		return nil
	}
}

// WithConnectionRetryAttempts sets the number of times the client should retry opening or accepting a connection over
// the tunnel before failing permanently.
func WithConnectionRetryAttempts(connRetryAttempts int) Option {
	return func(c *server) error {
		c.connRetryAttempts = connRetryAttempts
		return nil
	}
}

// WithConnectionRetryInterval sets the interval that the client should wait before retrying to open or accept a connection
// over the tunnel after failing.
func WithConnectionRetryInterval(connRetryInterval time.Duration) Option {
	return func(c *server) error {
		c.connRetryInterval = connRetryInterval
		return nil
	}
}
