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

//go:generate stringer -type=RouteClass

// RouteClass is a string type used to identify the different groups of routes
// that we program.  It is used as a tie-breaker when there are conflicting
// routes for the same CIDR.
type RouteClass int

const (
	RouteClassLocalWorkload RouteClass = iota
	RouteClassBPFSpecial
	RouteClassWireguard
	RouteClassVXLANSameSubnet
	RouteClassVXLANTunnel
	RouteClassIPAMBlockDrop

	RouteClassTODO
	RouteClassMax
)
