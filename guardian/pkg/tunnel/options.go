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

package tunnel

import (
	"errors"
	"net/url"
	"time"
)

// Option is a common format for New() options
type Option func(*tunnel) error

type DialerOption func(*sessionDialer) error

// WithDialerKeepAliveSettings sets the Keep Alive settings for the tunnel.
func WithDialerKeepAliveSettings(enable bool, intervalDuration time.Duration) DialerOption {
	return func(dialer *sessionDialer) error {
		dialer.keepAliveEnable = enable
		dialer.keepAliveInterval = intervalDuration
		return nil
	}
}

func WithDialerTimeout(dialTimeout time.Duration) DialerOption {
	return func(dialer *sessionDialer) error {
		dialer.timeout = dialTimeout
		return nil
	}
}

func WithDialerRetryAttempts(retryAttempts int) DialerOption {
	return func(dialer *sessionDialer) error {
		dialer.retryAttempts = retryAttempts
		return nil
	}
}

func WithDialerRetryInterval(retryInterval time.Duration) DialerOption {
	return func(dialer *sessionDialer) error {
		dialer.retryInterval = retryInterval
		return nil
	}
}

func WithDialerHTTPProxyURL(httpProxyURL *url.URL) DialerOption {
	return func(dialer *sessionDialer) error {
		if dialer.tlsConfig == nil {
			return errors.New("WithHTTPProxyURL: TLS dialer is required to use HTTP proxy")
		}
		dialer.httpProxyURL = httpProxyURL
		return nil
	}
}
