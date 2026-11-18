// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package dataplanedefs

import (
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// The main loop passes these interface monitor events to managers' OnUpdate
// alongside the datastore's protobuf messages.

type IfaceInSync struct{}

type IfaceStateUpdate struct {
	Name  string
	State ifacemonitor.State
	Index int
}

func NewIfaceStateUpdate(name string, state ifacemonitor.State, index int) *IfaceStateUpdate {
	return &IfaceStateUpdate{
		Name:  name,
		State: state,
		Index: index,
	}
}

type IfaceAddrsUpdate struct {
	Name  string
	Addrs set.Set[string]
}

func NewIfaceAddrsUpdate(name string, ips ...string) *IfaceAddrsUpdate {
	return &IfaceAddrsUpdate{
		Name:  name,
		Addrs: set.FromArray(ips),
	}
}
