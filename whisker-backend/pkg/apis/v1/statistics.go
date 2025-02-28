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
	Policy *PolicyHit `json:"policy"`

	GroupBy   string `json:"groupBy"`
	Type      string `json:"type"`
	Direction string `json:"direction"`

	AllowedIn  []int64 `json:"allowedIn"`
	AllowedOut []int64 `json:"allowedOut"`
	DeniedIn   []int64 `json:"deniedIn"`
	DeniedOut  []int64 `json:"deniedOut"`
	PassedIn   []int64 `json:"passedIn"`
	PassedOut  []int64 `json:"passedOut"`

	X []int64 `json:"x"`
}

type PolicyHit struct {
	Kind        string     `json:"kind"`
	Namespace   string     `json:"namespace"`
	Name        string     `json:"name"`
	Tier        string     `json:"tier"`
	Action      string     `json:"action"`
	PolicyIndex int64      `json:"policyIndex"`
	RuleIndex   int64      `json:"ruleIndex"`
	Trigger     *PolicyHit `json:"trigger"`
}
