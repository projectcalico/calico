// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routetable

// RouteMetric represents the kernel's metric or priority field.  Two
// routes with the same CIDR can co-exist if they have different metrics.
// The matching route with the lowest metric is chosen.
type RouteMetric int

// These constants define metrics for our various routing tables
const (
	RoutingMetricLocalWorkloads         RouteMetric = 0
	RoutingMetricSameSubnetWorkloads    RouteMetric = 20
	RoutingMetricVXLANTunneledWorkloads RouteMetric = 30
	RoutingMetricIPAMBlockDrop          RouteMetric = 100
)
