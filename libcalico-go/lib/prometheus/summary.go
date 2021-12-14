// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.
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

package prometheus

import "github.com/prometheus/client_golang/prometheus"

var DefObjectives = map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001}

// NewSummary creates a new prometheus summary and defaults the Objectives to DefObjectives if no objectives are defined
func NewSummary(opts prometheus.SummaryOpts) prometheus.Summary {
	if opts.Objectives == nil {
		opts.Objectives = DefObjectives
	}

	return prometheus.NewSummary(opts)
}
