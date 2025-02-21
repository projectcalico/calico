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

package v1

type StatisticsParams struct {
	// StartTime range for statistics, in seconds since the epoch. Also supports
	// times relative to Now() represented using negative numbers.
	StartTimeGt int64 `urlQuery:"startTimeGt"`
	StartTimeLt int64 `urlQuery:"startTimeLt"`

	// Type is the type of statistic to return. e.g., packets, bytes, etc.
	Type string `urlQuery:"type"`

	// Configure statistics aggregation.
	// - Policy: each StatisticsResult will contain statistics for a particular policy.
	// - PolicyRule: each StatisticsResult will contain statistics for a particular policy rule.
	GroupBy string `urlQuery:"groupBy"`

	// Set to true to return time series data. Otherwise, aggregate data is returned.
	TimeSeries bool `urlQuery:"timeSeries"`

	// Configur filtering of statistics.
	Namespace string `urlQuery:"namespace"`
	Tier      string `urlQuery:"tier"`
	Name      string `urlQuery:"name"`
	Action    string `urlQuery:"action"`
	Kind      string `urlQuery:"kind"`
}

type StatisticsResponse struct {
	Policy *PolicyHit

	GroupBy   string
	Type      string
	Direction string

	AllowedIn  []int64
	AllowedOut []int64
	DeniedIn   []int64
	DeniedOut  []int64
	PassedIn   []int64
	PassedOut  []int64

	X []int64
}

type PolicyHit struct {
	Kind        string
	Namespace   string
	Name        string
	Tier        string
	Action      string
	PolicyIndex int64
	RuleIndex   int64
	Trigger     *PolicyHit
}
