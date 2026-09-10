// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package common

import (
	"os"
	"strings"
)

// MetricsEnabled returns true when the operator metrics endpoint is enabled via METRICS_ENABLED=true.
func MetricsEnabled() bool {
	return strings.EqualFold(os.Getenv("METRICS_ENABLED"), "true")
}

// MetricsTLSEnabled returns true when the operator metrics endpoint should use mTLS (METRICS_SCHEME=https).
func MetricsTLSEnabled() bool {
	return strings.EqualFold(os.Getenv("METRICS_SCHEME"), "https")
}
