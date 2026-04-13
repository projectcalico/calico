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
	"fmt"
	"path/filepath"
	"testing"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func TestSourceAddrGracefulRestart(t *testing.T) {
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be, withNodeName("node1"), withoutBlockAffinities())
			ctx := context.Background()

			// Step 1: create nodes and a peering on a local subnet.
			// Expect a "direct" peering with source address set.
			cleanup := applyResources(t, be, "mock_data/calicoctl/sourceaddr_gracefulrestart/input.yaml")
			t.Cleanup(cleanup)
			d.expectOutput("sourceaddr_gracefulrestart/step1")

			// Step 2: update the peering to omit source address.
			peer, err := be.calicoClient.BGPPeers().Get(ctx, "bgppeer-1", options.GetOptions{})
			require.NoError(t, err)
			peer.Spec.SourceAddress = apiv3.SourceAddressNone
			_, err = be.calicoClient.BGPPeers().Update(ctx, peer, options.SetOptions{})
			require.NoError(t, err)
			d.expectOutput("sourceaddr_gracefulrestart/step2")

			// Step 3: add a max restart time.
			peer, err = be.calicoClient.BGPPeers().Get(ctx, "bgppeer-1", options.GetOptions{})
			require.NoError(t, err)
			peer.Spec.MaxRestartTime = &metav1.Duration{Duration: 10 * time.Second}
			_, err = be.calicoClient.BGPPeers().Update(ctx, peer, options.SetOptions{})
			require.NoError(t, err)
			d.expectOutput("sourceaddr_gracefulrestart/step3")
		})
	}
}

// TestNodeMeshBGPPassword tests the node-mesh password lifecycle:
// secret creation, update, key change to unreferenced key, and deletion.
func TestNodeMeshBGPPassword(t *testing.T) {
	for _, be := range activeBackends {
		if be.ctrlClient == nil {
			continue // KDD-only: needs K8s API for Secrets
		}
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be, withoutBlockAffinities())
			ctx := context.Background()

			cleanup := applyResources(t, be, "mock_data/calicoctl/mesh_password/input.yaml")
			t.Cleanup(cleanup)

			// Step 1: no secret yet → peerings have no password.
			d.expectOutput("mesh/password/step1")

			// Step 2: create the secret with key "a".
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "my-secrets-1", Namespace: "kube-system"},
				StringData: map[string]string{"a": "password-a"},
			}
			_, err := be.k8sClientset.CoreV1().Secrets("kube-system").Create(ctx, secret, metav1.CreateOptions{})
			require.NoError(t, err)
			d.expectOutput("mesh/password/step2")

			// Step 3: update the password.
			secret, err = be.k8sClientset.CoreV1().Secrets("kube-system").Get(ctx, "my-secrets-1", metav1.GetOptions{})
			require.NoError(t, err)
			secret.Data = nil
			secret.StringData = map[string]string{"a": "new-password-a"}
			_, err = be.k8sClientset.CoreV1().Secrets("kube-system").Update(ctx, secret, metav1.UpdateOptions{})
			require.NoError(t, err)
			d.expectOutput("mesh/password/step3")

			// Step 4: change secret to an unreferenced key → password disappears.
			secret, err = be.k8sClientset.CoreV1().Secrets("kube-system").Get(ctx, "my-secrets-1", metav1.GetOptions{})
			require.NoError(t, err)
			secret.Data = nil
			secret.StringData = map[string]string{"b": "password-b"}
			_, err = be.k8sClientset.CoreV1().Secrets("kube-system").Update(ctx, secret, metav1.UpdateOptions{})
			require.NoError(t, err)
			d.expectOutput("mesh/password/step1")

			// Step 5: delete the secret → still no password.
			err = be.k8sClientset.CoreV1().Secrets("kube-system").Delete(ctx, "my-secrets-1", metav1.DeleteOptions{})
			require.NoError(t, err)
			d.expectOutput("mesh/password/step1")

			// Secret already deleted by step 5; explicitly clean up only if
			// the test failed before reaching step 5.
			t.Cleanup(func() {
				_ = be.k8sClientset.CoreV1().Secrets("kube-system").Delete(ctx, "my-secrets-1", metav1.DeleteOptions{})
			})
		})
	}
}

// TestBGPPeerPassword tests per-peer password lifecycle via Secret references:
// secret creation with partial keys, full keys, deletion, update, and key removal.
func TestBGPPeerPassword(t *testing.T) {
	for _, be := range activeBackends {
		if be.ctrlClient == nil {
			continue // KDD-only: needs K8s API for Secrets
		}
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be, withNodeName("node1"), withoutBlockAffinities())
			ctx := context.Background()

			cleanup := applyResources(t, be, "mock_data/calicoctl/password/input.yaml")
			t.Cleanup(cleanup)

			// Step 1: no secrets → no passwords on any peering.
			d.expectOutput("password/step1")

			// Step 2: create my-secrets-1 with only key "b".
			secret1 := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "my-secrets-1", Namespace: "kube-system"},
				StringData: map[string]string{"b": "password-b"},
			}
			_, err := be.k8sClientset.CoreV1().Secrets("kube-system").Create(ctx, secret1, metav1.CreateOptions{})
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = be.k8sClientset.CoreV1().Secrets("kube-system").Delete(ctx, "my-secrets-1", metav1.DeleteOptions{})
			})
			d.expectOutput("password/step2")

			// Step 3: update my-secrets-1 to include both keys, and create my-secrets-2.
			secret1, err = be.k8sClientset.CoreV1().Secrets("kube-system").Get(ctx, "my-secrets-1", metav1.GetOptions{})
			require.NoError(t, err)
			secret1.Data = nil
			secret1.StringData = map[string]string{"b": "password-b", "a": "password-a"}
			_, err = be.k8sClientset.CoreV1().Secrets("kube-system").Update(ctx, secret1, metav1.UpdateOptions{})
			require.NoError(t, err)

			secret2 := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "my-secrets-2", Namespace: "kube-system"},
				StringData: map[string]string{"c": "password-c"},
			}
			_, err = be.k8sClientset.CoreV1().Secrets("kube-system").Create(ctx, secret2, metav1.CreateOptions{})
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = be.k8sClientset.CoreV1().Secrets("kube-system").Delete(ctx, "my-secrets-2", metav1.DeleteOptions{})
			})
			d.expectOutput("password/step3")

			// Step 4: delete my-secrets-2 → password-c disappears.
			err = be.k8sClientset.CoreV1().Secrets("kube-system").Delete(ctx, "my-secrets-2", metav1.DeleteOptions{})
			require.NoError(t, err)
			d.expectOutput("password/step4")

			// Step 5: change passwords in my-secrets-1.
			secret1, err = be.k8sClientset.CoreV1().Secrets("kube-system").Get(ctx, "my-secrets-1", metav1.GetOptions{})
			require.NoError(t, err)
			secret1.Data = nil
			secret1.StringData = map[string]string{"b": "new-password-b", "a": "new-password-a"}
			_, err = be.k8sClientset.CoreV1().Secrets("kube-system").Update(ctx, secret1, metav1.UpdateOptions{})
			require.NoError(t, err)
			d.expectOutput("password/step5")

			// Step 6: remove key "a" from my-secrets-1 → new-password-a disappears.
			secret1, err = be.k8sClientset.CoreV1().Secrets("kube-system").Get(ctx, "my-secrets-1", metav1.GetOptions{})
			require.NoError(t, err)
			secret1.Data = nil
			secret1.StringData = map[string]string{"b": "new-password-b"}
			_, err = be.k8sClientset.CoreV1().Secrets("kube-system").Update(ctx, secret1, metav1.UpdateOptions{})
			require.NoError(t, err)
			d.expectOutput("password/step6")
		})
	}
}

// TestBGPPasswordDeadlock is a regression test for a deadlock that occurred
// when iterating through many BGPPeers with password references. The deadlock
// required the iteration to take >100ms, so we create many nodes/peers.
func TestBGPPasswordDeadlock(t *testing.T) {
	for _, be := range activeBackends {
		if be.ctrlClient == nil {
			continue // KDD-only: needs K8s API for Secrets
		}
		t.Run(be.name, func(t *testing.T) {
			ctx := context.Background()
			scale := 99

			// Disable node-to-node mesh so the golden file (which only expects
			// the explicit peer) matches.
			meshOff := false
			bgpCfg := &apiv3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       apiv3.BGPConfigurationSpec{NodeToNodeMeshEnabled: &meshOff},
			}
			_, err := be.calicoClient.BGPConfigurations().Create(ctx, bgpCfg, options.SetOptions{})
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = be.calicoClient.BGPConfigurations().Delete(ctx, "default", options.DeleteOptions{})
			})

			// Create the secret first (confd needs it to render passwords).
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "my-secrets-1", Namespace: "kube-system"},
				StringData: map[string]string{"a": "password-a"},
			}
			_, err = be.k8sClientset.CoreV1().Secrets("kube-system").Create(ctx, secret, metav1.CreateOptions{})
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = be.k8sClientset.CoreV1().Secrets("kube-system").Delete(ctx, "my-secrets-1", metav1.DeleteOptions{})
			})

			// Use a distinct prefix to avoid collisions with other tests that
			// share the envtest API server (e.g. TestNodeDeletion also uses "node1").
			prefix := "dl-node"

			// Create all K8s nodes first, then update with Calico BGP spec and
			// create BGPPeers. Batching by resource type reduces the number of
			// watch-event round-trips compared to the interleaved approach.
			for i := 1; i <= scale; i++ {
				k8sNode := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   fmt.Sprintf("%s%d", prefix, i),
						Labels: map[string]string{"node": "yes"},
					},
				}
				_, err := be.k8sClientset.CoreV1().Nodes().Create(ctx, k8sNode, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			for i := 1; i <= scale; i++ {
				nodeName := fmt.Sprintf("%s%d", prefix, i)
				ip := fmt.Sprintf("10.24.0.%d/24", i)

				cNode, err := be.calicoClient.Nodes().Get(ctx, nodeName, options.GetOptions{})
				require.NoError(t, err)
				cNode.Spec.BGP = &internalapi.NodeBGPSpec{IPv4Address: ip}
				cNode.Labels["node"] = "yes"
				_, err = be.calicoClient.Nodes().Update(ctx, cNode, options.SetOptions{})
				require.NoError(t, err)
			}

			for i := 1; i <= scale; i++ {
				nodeName := fmt.Sprintf("%s%d", prefix, i)
				peerName := fmt.Sprintf("dl-bgppeer-%d", i)

				peer := &apiv3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: peerName},
					Spec: apiv3.BGPPeerSpec{
						Node:     nodeName,
						PeerIP:   "10.24.0.2",
						ASNumber: 64512,
						Password: &apiv3.BGPPassword{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "my-secrets-1"},
								Key:                  "a",
							},
						},
					},
				}
				_, err := be.calicoClient.BGPPeers().Create(ctx, peer, options.SetOptions{})
				require.NoError(t, err)
			}

			t.Cleanup(func() {
				for i := 1; i <= scale; i++ {
					_, _ = be.calicoClient.BGPPeers().Delete(ctx, fmt.Sprintf("dl-bgppeer-%d", i), options.DeleteOptions{})
					_, _ = be.calicoClient.Nodes().Delete(ctx, fmt.Sprintf("%s%d", prefix, i), options.DeleteOptions{})
					_ = be.k8sClientset.CoreV1().Nodes().Delete(ctx, fmt.Sprintf("%s%d", prefix, i), metav1.DeleteOptions{})
				}
			})

			// Start confd. The original bash test used Typha, but the deadlock
			// is in the confd client's lock ordering, not the Typha path.
			// Use dl-node1 as the confd node so the golden file (which expects
			// a single peer to 10.24.0.2) still matches.
			d := startConfdDaemon(t, be, withNodeName(prefix+"1"), withoutBlockAffinities())
			d.expectOutput("password-deadlock")
		})
	}
}

func TestLocalBGPPeer(t *testing.T) {
	for _, be := range activeBackends {
		if be.ctrlClient == nil {
			continue // KDD-only: needs K8s API for endpoint-status
		}
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be, withoutBlockAffinities(), withEndpointStatus(map[string]string{
				"pod1": `{"ifaceName":"cali97e1defe654","ipv4Nets":["192.168.162.134/32"],"ipv6Nets":["fd00:10:244:0:586d:4461:e980:a284/128"],"bgpPeerName":"test-global-peer-with-filter"}`,
				"pod2": `{"ifaceName":"cali97e1defe656","ipv4Nets":["192.168.162.136/32"],"ipv6Nets":["fd00:10:244:0:586d:4461:e980:a286/128"],"bgpPeerName":"test-node-peer-with-filter"}`,
			}))

			cleanup := applyResources(t, be, "mock_data/calicoctl/local_bgp_peer/input.yaml")
			t.Cleanup(cleanup)
			d.expectOutput("explicit_peering/local_bgp_peer")
		})
	}
}

// TestIdlePeers verifies that overlapping global and node-specific peerings
// are correctly deduplicated, even after repeated node resource updates.
func TestIdlePeers(t *testing.T) {
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be, withNodeName("node1"), withoutBlockAffinities())
			ctx := context.Background()

			cleanup := applyResources(t, be, "mock_data/calicoctl/idle_peers/input.yaml")
			t.Cleanup(cleanup)

			// Both peers match node2, but should deduplicate to 1 peering.
			d.expectPeeringCount(1)

			// Repeatedly touch node1 to trigger recomputation; count must stay at 1.
			for i := 0; i < 10; i++ {
				node, err := be.calicoClient.Nodes().Get(ctx, "node1", options.GetOptions{})
				require.NoError(t, err)
				_, err = be.calicoClient.Nodes().Update(ctx, node, options.SetOptions{})
				require.NoError(t, err)
				time.Sleep(250 * time.Millisecond)
				d.expectPeeringCount(1)
			}
		})
	}
}

func TestNodeDeletion(t *testing.T) {
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be, withNodeName("node1"), withoutBlockAffinities())
			ctx := context.Background()

			cleanup := applyResources(t, be, "mock_data/calicoctl/node_deletion/input.yaml")
			t.Cleanup(cleanup)

			// 4 nodes with peerSelector: has(node) → node1 sees 3 peers.
			d.expectPeeringCount(3)

			// Delete node3 → node1 should see 2 peers.
			if be.k8sClientset != nil {
				// KDD: delete the K8s node directly. The Calico client's
				// Node.Delete does WorkloadEndpoint GC that doesn't work in
				// envtest, but all we need is for confd to see the node
				// disappear.
				err := be.k8sClientset.CoreV1().Nodes().Delete(ctx, "node3", metav1.DeleteOptions{})
				require.NoError(t, err)
			} else {
				_, err := be.calicoClient.Nodes().Delete(ctx, "node3", options.DeleteOptions{})
				require.NoError(t, err)
			}
			d.expectPeeringCount(2)
		})
	}
}

func TestBGPFilterDeletion(t *testing.T) {
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be)

			// Step 1: apply resources and verify output with filter active.
			cleanup := applyResources(t, be, "mock_data/calicoctl/bgpfilter/filter_deletion/input.yaml")
			d.expectOutput("bgpfilter/filter_deletion/step1")

			// Step 2: delete the BGPFilter, verify output updates.
			ctx := context.Background()
			_, err := be.calicoClient.BGPFilter().Delete(ctx, "test-filter", options.DeleteOptions{})
			require.NoError(t, err, "deleting BGPFilter test-filter")
			d.expectOutput("bgpfilter/filter_deletion/step2")

			cleanup()
		})
	}
}

// TestDaemonModeRendering verifies that confd's watch/re-render loop correctly
// picks up resource changes for representative scenarios that are otherwise only
// tested in oneshot mode. A single long-lived confd instance processes a
// sequence of apply → verify → cleanup cycles, exercising the same code path as
// the old shell suite's execute_tests_daemon function. KDD mode runs through
// Typha to match the old test topology.
func TestDaemonModeRendering(t *testing.T) {
	meshScenarios := []string{
		"mesh/bgp-export",
		"mesh/ipip-always",
		"mesh/communities",
		"mesh/restart-time",
	}
	explicitScenarios := []string{
		"explicit_peering/global",
		"explicit_peering/selectors",
		"explicit_peering/route_reflector",
	}
	filterScenarios := []string{
		"bgpfilter/single_filter/global_peer",
	}

	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be)

			for _, sc := range meshScenarios {
				runDaemonScenario(t, d, be, sc)
			}
			for _, sc := range explicitScenarios {
				runDaemonScenario(t, d, be, sc)
			}
			for _, sc := range filterScenarios {
				runDaemonScenario(t, d, be, sc)
			}
		})
	}
}

// runDaemonScenario applies resources for a single scenario, verifies that
// confd renders the expected output, then cleans up all resources so the next
// scenario starts from a clean state.
func runDaemonScenario(t *testing.T, d *confdDaemon, be *datastoreBackend, goldenDir string) {
	t.Helper()

	inputPath := filepath.Join("mock_data", "calicoctl", goldenDir, "input.yaml")
	cleanup := applyResources(t, be, inputPath)
	d.expectOutput(goldenDir)
	cleanup()
}
