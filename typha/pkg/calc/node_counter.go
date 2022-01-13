// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package calc

import (
	"fmt"
	"sync"

	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func NewNodeCounter(sink api.SyncerCallbacks) *NodeCounter {
	return &NodeCounter{
		sink:    sink,
		nodeMap: map[string]bool{},
	}
}

type NodeCounter struct {
	sync.Mutex
	sink    api.SyncerCallbacks
	inSync  bool
	nodeMap map[string]bool
}

func (c *NodeCounter) OnStatusUpdated(status api.SyncStatus) {
	if status == api.InSync {
		c.Lock()
		c.inSync = true
		c.Unlock()
	}
	c.sink.OnStatusUpdated(status)
}

func (c *NodeCounter) OnUpdates(updates []api.Update) {
	for _, update := range updates {
		switch k := update.Key.(type) {
		case model.ResourceKey:
			if k.Kind == v3.KindNode {
				name := k.Name
				switch update.UpdateType {
				case api.UpdateTypeKVNew:
					c.setNode(name)
				case api.UpdateTypeKVDeleted:
					c.deleteNode(name)
				}
			}
		}
	}
	c.sink.OnUpdates(updates)
}

func (c *NodeCounter) GetNumNodes() (int, error) {
	c.Lock()
	defer c.Unlock()
	if !c.inSync {
		return 0, fmt.Errorf("Node counter not yet in sync")
	}
	return len(c.nodeMap), nil
}

func (c *NodeCounter) setNode(node string) {
	c.Lock()
	defer c.Unlock()
	c.nodeMap[node] = true
}

func (c *NodeCounter) deleteNode(node string) {
	c.Lock()
	defer c.Unlock()
	delete(c.nodeMap, node)
}
