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

// Package dataplanedefs defines the contract between the Linux dataplane's
// main loop and its managers, so that a manager can live outside the
// dataplane package.
//
// It must not import any package that imports it; low-level packages that
// need a manager's names import that manager's *defs package instead.
package dataplanedefs

import (
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routerule"
	"github.com/projectcalico/calico/felix/routetable"
)

type Manager interface {
	// OnUpdate is called for each protobuf message from the datastore.  May either directly
	// send updates to the IPSets and generictables.Table objects (which will queue the updates
	// until the main loop instructs them to act) or (for efficiency) may wait until
	// a call to CompleteDeferredWork() to flush updates to the dataplane.
	OnUpdate(protoBufMsg any)
	// Called before the main loop flushes updates to the dataplane to allow for batched
	// work to be completed.
	CompleteDeferredWork() error
}

type ManagerWithRouteTables interface {
	Manager
	GetRouteTableSyncers() []routetable.SyncerInterface
}

type ManagerWithRouteRules interface {
	Manager
	GetRouteRules() []RouteRules
}

type RouteRules interface {
	SetRule(rule *routerule.Rule)
	RemoveRule(rule *routerule.Rule)
	QueueResync()
	Apply() error
}

type UpdateBatchResolver interface {
	// Opportunity for a manager component to resolve state that depends jointly on the updates
	// that it has seen since the preceding CompleteDeferredWork call.  Processing here can
	// include passing resolved state to other managers.  It should not include any actual
	// dataplane updates yet.  (Those should be actioned in CompleteDeferredWork.)
	ResolveUpdateBatch() error
}

// Table is a shim interface for generictables.Table.
type Table interface {
	UpdateChain(chain *generictables.Chain)
	UpdateChains([]*generictables.Chain)
	RemoveChains([]*generictables.Chain)
	RemoveChainByName(name string)
}

type HEPListener interface {
	OnHEPUpdate(hostIfaceToEpMap map[string]*proto.HostEndpoint)
}

// AllInterfaces is the interface name that we use to mean "all interfaces".  This is
// intentionally longer than IFNAMSIZ (16) characters, so that it can't possibly match a
// real interface name.
const AllInterfaces = "any-interface-at-all"

const MaxCleanupRetries = 5
