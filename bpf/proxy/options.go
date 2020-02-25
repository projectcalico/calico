// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
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

package proxy

import (
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// Option defines Proxy options
type Option func(Proxy) error

func makeOption(f func(*proxy) error) Option {
	return func(P Proxy) error {
		p, ok := P.(*proxy)
		if !ok {
			return errors.Errorf("option used on a wrong type")
		}

		return f(p)
	}

}

// WithMinSyncPeriod sets the minimum duration between two attempts to sync with
// the dataplane
func WithMinSyncPeriod(min time.Duration) Option {
	return makeOption(func(p *proxy) error {
		p.minDPSyncPeriod = min
		log.Infof("proxy.WithMinSyncPeriod(%s)", min)
		return nil
	})
}

// WithImmediateSync triggers sync with dataplane on immediately on every update
func WithImmediateSync() Option {
	return WithMinSyncPeriod(0)
}
