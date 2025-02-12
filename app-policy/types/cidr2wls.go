// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package types

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	ftypes "github.com/projectcalico/calico/felix/types"
)

type IPToEndpointsIndex interface {
	Keys(k ip.Addr) []proto.WorkloadEndpointID
	Get(k ip.Addr) []*proto.WorkloadEndpoint
	Update(k ip.Addr, v *proto.WorkloadEndpointUpdate)
	Delete(k ip.Addr, v *proto.WorkloadEndpointRemove)
}

type wlMap map[ftypes.WorkloadEndpointID]*proto.WorkloadEndpoint

func NewIPToEndpointsIndex() IPToEndpointsIndex {
	return &IPToEndpointsIndexer{
		make(map[ip.Addr]wlMap),
	}
}

type IPToEndpointsIndexer struct {
	store map[ip.Addr]wlMap
}

func (index *IPToEndpointsIndexer) Keys(k ip.Addr) (res []proto.WorkloadEndpointID) {
	for item := range index.store[k] {
		res = append(res, *ftypes.WorkloadEndpointIDToProto(item))
	}
	return
}

func (index *IPToEndpointsIndexer) Get(k ip.Addr) (res []*proto.WorkloadEndpoint) {
	log.Trace("before get: ", index.printKeys())
	for _, item := range index.store[k] {
		res = append(res, item)
	}
	return
}

func (index *IPToEndpointsIndexer) printKeys() []string {
	res := []string{}
	for entry := range index.store {
		res = append(res, entry.String())
	}
	return res
}

func (index *IPToEndpointsIndexer) Update(k ip.Addr, v *proto.WorkloadEndpointUpdate) {
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Trace("before update: ", index.printKeys())
		defer log.Trace("after update: ", index.printKeys())
	}
	if _, ok := index.store[k]; !ok {
		index.store[k] = make(wlMap)
	}

	id := ftypes.ProtoToWorkloadEndpointID(v.Id)
	index.store[k][id] = v.Endpoint
}

func (index *IPToEndpointsIndexer) Delete(k ip.Addr, v *proto.WorkloadEndpointRemove) {
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Trace("before delete: ", index.printKeys())
		defer log.Trace("after delete: ", index.printKeys())
	}
	if _, ok := index.store[k]; !ok {
		return
	}
	id := ftypes.ProtoToWorkloadEndpointID(v.Id)
	delete(index.store[k], id)
	if len(index.store[k]) == 0 {
		delete(index.store, k)
	}
}
