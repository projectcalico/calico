// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package utils_test

import (
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func TestIPAMFeedAppliesPoolsBlocksAndReservations(t *testing.T) {
	feed := utils.NewIPAMFeed()
	feed.OnUpdate(poolUpdate("p", "10.0.0.0/24", nil))
	feed.OnUpdate(blockUpdate("10.0.0.0/26", "host:node-a", 1))
	feed.OnUpdate(reservationUpdate("r", "10.0.0.128/28"))

	counts := mustSummarize(t, feed, "p")
	if counts.InUse != 1 || counts.Reserved.Int64() != 16 || counts.BlocksInUse != 1 {
		t.Fatalf("got InUse=%d Reserved=%s BlocksInUse=%d, want 1, 16, 1", counts.InUse, counts.Reserved, counts.BlocksInUse)
	}

	feed.OnUpdate(bapi.Update{KVPair: model.KVPair{Key: model.ResourceKey{Kind: apiv3.KindIPReservation, Name: "r"}}})
	feed.OnUpdate(bapi.Update{KVPair: model.KVPair{Key: blockKey("10.0.0.0/26")}})
	counts = mustSummarize(t, feed, "p")
	if counts.InUse != 0 || counts.Reserved.Int64() != 0 || counts.BlocksInUse != 0 {
		t.Fatalf("after deletes got InUse=%d Reserved=%s BlocksInUse=%d, want all 0", counts.InUse, counts.Reserved, counts.BlocksInUse)
	}

	feed.OnUpdate(bapi.Update{KVPair: model.KVPair{Key: model.ResourceKey{Kind: apiv3.KindIPPool, Name: "p"}}})
	if _, ok := feed.Tracker().Summarize("p"); ok {
		t.Fatal("pool still tracked after its delete")
	}
}

func TestIPAMFeedKeepsATerminatingPool(t *testing.T) {
	feed := utils.NewIPAMFeed()
	feed.OnUpdate(poolUpdate("p", "10.0.0.0/24", ptr.To(metav1.Now())))
	feed.OnUpdate(blockUpdate("10.0.0.0/26", "host:node-a", 1))

	if counts := mustSummarize(t, feed, "p"); counts.InUse != 1 {
		t.Fatalf("Terminating pool InUse = %d, want its block's 1", counts.InUse)
	}
}

func TestIPAMFeedJudgesStaleAffinityByTheNodesItHasSeen(t *testing.T) {
	feed := utils.NewIPAMFeed()
	feed.OnUpdate(poolUpdate("p", "10.0.0.0/24", nil))
	feed.OnUpdate(blockUpdate("10.0.0.0/26", "host:node-a", 1))
	if stale := mustSummarize(t, feed, "p").StaleAffinity; stale != 1 {
		t.Fatalf("StaleAffinity before node-a = %d, want 1", stale)
	}

	nodeKey := model.ResourceKey{Kind: internalapi.KindNode, Name: "node-a"}
	feed.OnUpdate(bapi.Update{KVPair: model.KVPair{Key: nodeKey, Value: &internalapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}}})
	if stale := mustSummarize(t, feed, "p").StaleAffinity; stale != 0 {
		t.Fatalf("StaleAffinity with node-a = %d, want 0", stale)
	}

	feed.OnUpdate(bapi.Update{KVPair: model.KVPair{Key: nodeKey}})
	if stale := mustSummarize(t, feed, "p").StaleAffinity; stale != 1 {
		t.Fatalf("StaleAffinity after node-a's delete = %d, want 1", stale)
	}
}

func TestIPAMFeedIgnoresAValueOfTheWrongType(t *testing.T) {
	feed := utils.NewIPAMFeed()
	feed.OnUpdate(bapi.Update{KVPair: model.KVPair{
		Key:   model.ResourceKey{Kind: apiv3.KindIPPool, Name: "p"},
		Value: &apiv3.IPReservation{},
	}})
	if _, ok := feed.Tracker().Summarize("p"); ok {
		t.Fatal("a value of the wrong type created a pool")
	}
}

func mustSummarize(t *testing.T, feed *utils.IPAMFeed, pool string) *accounting.Counts {
	t.Helper()
	counts, ok := feed.Tracker().Summarize(pool)
	if !ok {
		t.Fatalf("pool %s not tracked", pool)
	}
	return counts
}

func poolUpdate(name, cidr string, deletedAt *metav1.Time) bapi.Update {
	return bapi.Update{KVPair: model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindIPPool, Name: name},
		Value: &apiv3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: name, DeletionTimestamp: deletedAt},
			Spec:       apiv3.IPPoolSpec{CIDR: cidr, BlockSize: 26},
		},
	}}
}

func reservationUpdate(name, cidr string) bapi.Update {
	return bapi.Update{KVPair: model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindIPReservation, Name: name},
		Value: &apiv3.IPReservation{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       apiv3.IPReservationSpec{ReservedCIDRs: []string{cidr}},
		},
	}}
}

func blockKey(cidr string) model.BlockKey {
	return model.BlockKey{CIDR: model.PrefixFromIPNet(cnet.MustParseCIDR(cidr))}
}

// blockUpdate is a block with its first allocated addresses held by pods on the affine node.
func blockUpdate(cidr, affinity string, allocated int) bapi.Update {
	ipNet := cnet.MustParseCIDR(cidr)
	block := &model.AllocationBlock{CIDR: ipNet, Affinity: &affinity}
	block.Allocations = make([]*int, block.NumAddresses())
	for i := range allocated {
		block.Allocations[i] = ptr.To(0)
	}
	block.Attributes = []model.AllocationAttribute{{
		HandleID: ptr.To("h"),
		ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNode: "node-a",
			model.IPAMBlockAttributePod:  "pod",
		},
	}}
	return bapi.Update{KVPair: model.KVPair{Key: blockKey(cidr), Value: block}}
}
