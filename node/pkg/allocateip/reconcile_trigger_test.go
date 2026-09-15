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

// Regression for updates that arrive after a reconcile has read its Node snapshot.
package allocateip

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	felixconfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type triggerTestClient struct {
	client.Interface
	nodes client.NodeInterface
	pools client.IPPoolInterface
}

type triggerTestIPAM struct{ ipam.Interface }

func (triggerTestIPAM) ReleaseByHandle(context.Context, string) error { return nil }
func (c triggerTestClient) IPAM() ipam.Interface                      { return triggerTestIPAM{} }

func (c triggerTestClient) Nodes() client.NodeInterface     { return c.nodes }
func (c triggerTestClient) IPPools() client.IPPoolInterface { return c.pools }

type triggerTestNodes struct {
	client.NodeInterface
	get func(context.Context) (*internalapi.Node, error)
}

func (n triggerTestNodes) Get(ctx context.Context, _ string, _ options.GetOptions) (*internalapi.Node, error) {
	return n.get(ctx)
}

type triggerTestPools struct {
	client.IPPoolInterface
	list func(context.Context) (*api.IPPoolList, error)
}

func (p triggerTestPools) List(ctx context.Context, _ options.ListOptions) (*api.IPPoolList, error) {
	return p.list(ctx)
}

func triggerTestNodeUpdate(labels map[string]string) bapi.Update {
	return bapi.Update{KVPair: model.KVPair{
		Key:   model.ResourceKey{Kind: internalapi.KindNode, Name: "test-node"},
		Value: &internalapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node", Labels: labels}},
	}, UpdateType: bapi.UpdateTypeKVUpdated}
}

func TestChangeDuringReconcileQueuesAnotherPass(t *testing.T) {
	var gets atomic.Int32
	var lists atomic.Int32
	enteredList := make(chan struct{})
	releaseList := make(chan struct{})
	secondGet := make(chan struct{})
	c := triggerTestClient{
		nodes: triggerTestNodes{get: func(context.Context) (*internalapi.Node, error) {
			if gets.Add(1) == 2 {
				close(secondGet)
			}
			return &internalapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node", Labels: map[string]string{"rack": "one"}}}, nil
		}},
		pools: triggerTestPools{list: func(ctx context.Context) (*api.IPPoolList, error) {
			if lists.Add(1) == 1 {
				close(enteredList)
				select {
				case <-releaseList:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return &api.IPPoolList{}, nil
		}},
	}
	r := newReconciler("test-node", nil, c, felixconfig.New())
	r.OnUpdates([]bapi.Update{triggerTestNodeUpdate(map[string]string{"rack": "one"})})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("reconcile loop failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("reconcile loop did not stop")
		}
	}()
	go func() { done <- r.run(ctx) }()
	r.OnStatusUpdated(bapi.InSync)
	select {
	case <-enteredList: // The first reconcile has already read its Node snapshot.
	case <-time.After(5 * time.Second):
		t.Fatal("initial reconciliation did not reach IPPool.List")
	}
	r.OnUpdates([]bapi.Update{triggerTestNodeUpdate(map[string]string{"rack": "two"})})
	close(releaseList)
	select {
	case <-secondGet:
	case <-time.After(2 * time.Second):
		t.Errorf("change after Node.Get was discarded; only %d reconcile(s)", gets.Load())
	}
}
