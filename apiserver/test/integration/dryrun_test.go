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

package integration

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// TestServerSideDryRun checks that a server-side dry run gets the same validation as
// a real write, from the Calico client and from the backing CRD, and that a dry run
// that passes persists nothing.
func TestServerSideDryRun(t *testing.T) {
	client, shutdownServer := getFreshAPIServerAndClient(t, func() runtime.Object {
		return &v3.BGPPeer{}
	})
	defer shutdownServer()

	ctx := context.Background()
	dryRunCreate := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}
	dryRunUpdate := metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}}

	t.Run("create rejected by the Calico validator", func(t *testing.T) {
		pools := client.ProjectcalicoV3().IPPools()
		bad := &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "dryrun-bad-pool"},
			Spec:       v3.IPPoolSpec{CIDR: "10.0.0.0/33"},
		}
		if _, err := pools.Create(ctx, bad, dryRunCreate); !apierrors.IsInvalid(err) {
			t.Fatalf("dry-run create of a /33 pool: want Invalid, got %v", err)
		}

		good := &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: "dryrun-good-pool"},
			Spec:       v3.IPPoolSpec{CIDR: "10.10.0.0/16"},
		}
		if _, err := pools.Create(ctx, good, dryRunCreate); err != nil {
			t.Fatalf("dry-run create of a valid pool: %v", err)
		}
		if _, err := pools.Get(ctx, good.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("dry-run create persisted the pool: want NotFound, got %v", err)
		}
	})

	t.Run("create rejected by the backing CRD", func(t *testing.T) {
		if os.Getenv("DATASTORE_TYPE") != "kubernetes" {
			t.Skip("only the Kubernetes datastore has CRD validation rules")
		}
		peers := client.ProjectcalicoV3().BGPPeers()

		// The Calico validator accepts this; only a CEL rule on the CRD rejects it.
		bad := &v3.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "dryrun-bad-peer"},
			Spec: v3.BGPPeerSpec{
				PeerSelector: "all()",
				ASNumber:     numorstring.ASNumber(64512),
			},
		}
		_, err := peers.Create(ctx, bad, dryRunCreate)
		if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "asNumber must be empty when peerSelector is set") {
			t.Fatalf("dry-run create of a peer with peerSelector and asNumber: want the CRD's Invalid error, got %v", err)
		}

		good := &v3.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "dryrun-good-peer"},
			Spec: v3.BGPPeerSpec{
				PeerIP:   "10.0.0.1",
				ASNumber: numorstring.ASNumber(64512),
			},
		}
		if _, err := peers.Create(ctx, good, dryRunCreate); err != nil {
			t.Fatalf("dry-run create of a valid peer: %v", err)
		}
		if _, err := peers.Get(ctx, good.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("dry-run create persisted the peer: want NotFound, got %v", err)
		}
	})

	t.Run("update", func(t *testing.T) {
		sets := client.ProjectcalicoV3().GlobalNetworkSets()
		orig, err := sets.Create(ctx, &v3.GlobalNetworkSet{
			ObjectMeta: metav1.ObjectMeta{Name: "dryrun-set"},
			Spec:       v3.GlobalNetworkSetSpec{Nets: []string{"10.0.0.0/24"}},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("creating the network set: %v", err)
		}
		defer func() {
			if err := sets.Delete(ctx, orig.Name, metav1.DeleteOptions{}); err != nil {
				t.Errorf("deleting the network set: %v", err)
			}
		}()

		bad := orig.DeepCopy()
		bad.Spec.Nets = []string{"10.0.0.0/33"}
		if _, err := sets.Update(ctx, bad, dryRunUpdate); !apierrors.IsInvalid(err) {
			t.Fatalf("dry-run update to a /33 net: want Invalid, got %v", err)
		}

		good := orig.DeepCopy()
		good.Spec.Nets = []string{"10.1.0.0/24"}
		if _, err := sets.Update(ctx, good, dryRunUpdate); err != nil {
			t.Fatalf("dry-run update to a valid net: %v", err)
		}

		stored, err := sets.Get(ctx, orig.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("getting the network set: %v", err)
		}
		if !reflect.DeepEqual(stored.Spec.Nets, orig.Spec.Nets) {
			t.Fatalf("dry-run updates changed the stored nets: want %v, got %v", orig.Spec.Nets, stored.Spec.Nets)
		}
	})
}
