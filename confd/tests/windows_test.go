// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"context"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// TestWindowsPeerings checks that the Windows peerings template renders mesh, global and
// node-specific peers, and is re-rendered when the set of BGPPeers or route reflector nodes
// changes.
func TestWindowsPeerings(t *testing.T) {
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be, withWindowsTemplates())
			ctx := context.Background()

			// Step 1: mesh plus one global peer.
			cleanup := applyResources(t, be, "mock_data/calicoctl/windows_peerings/input.yaml")
			t.Cleanup(cleanup)
			d.expectOutput("windows_peerings/step1")

			// Step 2: add a node-specific peer for this node.
			nodePeer := apiv3.NewBGPPeer()
			nodePeer.Name = "node-peer"
			nodePeer.Spec.Node = "kube-master"
			nodePeer.Spec.PeerIP = "10.225.0.6"
			nodePeer.Spec.ASNumber = numorstring.ASNumber(65516)
			_, err := be.calicoClient.BGPPeers().Create(ctx, nodePeer, options.SetOptions{})
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = be.calicoClient.BGPPeers().Delete(ctx, "node-peer", options.DeleteOptions{})
			})
			d.expectOutput("windows_peerings/step2")

			// Step 3: remove the global peer.
			_, err = be.calicoClient.BGPPeers().Delete(ctx, "global-peer", options.DeleteOptions{})
			require.NoError(t, err)
			d.expectOutput("windows_peerings/step3")

			// Step 4: make another node a route reflector.  It is no longer a mesh peer.
			setRouteReflectorClusterID(t, be, "kube-node-1", "224.0.0.1")
			d.expectOutput("windows_peerings/step4")

			// Step 5: make this node a route reflector.  It then has no mesh peers at all.
			setRouteReflectorClusterID(t, be, "kube-master", "224.0.0.1")
			d.expectOutput("windows_peerings/step5")
		})
	}
}

func setRouteReflectorClusterID(t *testing.T, be *datastoreBackend, nodeName, clusterID string) {
	t.Helper()
	ctx := context.Background()
	node, err := be.calicoClient.Nodes().Get(ctx, nodeName, options.GetOptions{})
	require.NoError(t, err)
	node.Spec.BGP.RouteReflectorClusterID = clusterID
	_, err = be.calicoClient.Nodes().Update(ctx, node, options.SetOptions{})
	require.NoError(t, err)
}
