// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

// NewHealthAggregator creates a HealthAggregator for Guardian and starts
// serving on the given port if enabled. A single "guardian" reporter is
// registered and immediately marked live and ready — Guardian's health
// is determined by whether the HTTP endpoint is reachable.
func NewHealthAggregator(enabled bool, port int) *health.HealthAggregator {
	ha := health.NewHealthAggregator()
	ha.RegisterReporter("guardian", &health.HealthReport{Live: true, Ready: true}, 0)
	ha.Report("guardian", &health.HealthReport{Live: true, Ready: true})
	ha.ServeHTTP(enabled, "", port)
	return ha
}
