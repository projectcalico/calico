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

// RouteMetric represents the kernel's metric AKA priority field.  Two
// routes with the same CIDR can co-exist if they have different metrics.
// The matching route with the lowest metric wins.
type RouteMetric int

// These constants define metrics for our various RouteTables, which
// share the main kernel routing table.  It's not ideal that we have more
// than one RouteTable pointing at the same kernel table(!) but giving
// each a different priority means that they can't clobber each other's
// routes, and that the eventual outcome is deterministic.
//
// We give local workloads the lowest metric, so local "cali" interface
// routes will be preferred, even if there's a conflicting remote or block
// route.
//
// "Same subnet" routes are preferred over tunnel routes since they're
// faster (but in practice the VXLAN manager avoids conflicts anyway).
//
// IPAM block blackhole routes are given a high metric so that the
// blackhole route for a /32 block doesn't conflict with a (potentially
// borrowed) workload route.
const (
	RoutingMetricLocalWorkloads         RouteMetric = 0
	RoutingMetricSameSubnetWorkloads    RouteMetric = 20
	RoutingMetricVXLANTunneledWorkloads RouteMetric = 30
	RoutingMetricIPAMBlockDrop          RouteMetric = 100
)
