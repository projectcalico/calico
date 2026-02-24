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

package bgp

import (
	"context"
	"fmt"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("BGPPeer"),
	describe.WithCategory(describe.Networking),
	describe.WithSerial(),
	"BGP password",
	func() {
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var server1 *conncheck.Server
		var client1 *conncheck.Client
		var restoreBGPConfig func()

		f := utils.NewDefaultFramework("bgp-password")

		ginkgo.BeforeEach(func() {
			checker = conncheck.NewConnectionTester(f)

			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to create API client")

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred(), "failed to clean datastore")

			// We need a minimum of two nodes for BGP peering tests.
			utils.RequireNodeCount(f, 2)

			// Verify BGP is enabled via the Installation resource.
			installation := &v1.Installation{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, installation)
			Expect(err).NotTo(HaveOccurred(), "Error querying Installation resource")
			Expect(installation.Spec.CalicoNetwork).NotTo(BeNil(), "CalicoNetwork is not configured in the Installation")
			Expect(installation.Spec.CalicoNetwork.BGP).NotTo(BeNil(), "BGP is not enabled in the cluster")
			Expect(*installation.Spec.CalicoNetwork.BGP).To(Equal(v1.BGPEnabled), "BGP is not enabled in the cluster")

			// Ensure full mesh BGP is functioning before each test.
			restoreBGPConfig = ensureInitialBGPConfig(cli)

			// Deploy server and client on different nodes to verify cross-node traffic.
			server1 = conncheck.NewServer("server", f.Namespace,
				conncheck.WithServerLabels(map[string]string{"role": "server"}),
				conncheck.WithServerPodCustomizer(conncheck.AvoidEachOther),
			)
			client1 = conncheck.NewClient("client", f.Namespace,
				conncheck.WithClientCustomizer(conncheck.AvoidEachOther),
			)
			checker.AddServer(server1)
			checker.AddClient(client1)
			checker.Deploy()

			// Verify initial connectivity via full mesh.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()
		})

		ginkgo.AfterEach(func() {
			checker.Stop()
			restoreBGPConfig()
		})

		// Verifies that BGP peers establish and carry traffic when configured with
		// matching passwords via secret references, and that mismatched passwords
		// prevent BGP sessions from establishing.
		ginkgo.It("should enforce BGP password authentication", func() {
			ctx := context.Background()
			calicoNS := utils.CalicoNamespace(f)

			// Create a shared secret and RBAC so calico-node can read the password.
			ginkgo.By("Creating a BGP password secret and RBAC")
			createBGPSecret(f, "bgp-password", calicoNS, "correct-horse")
			createSecretRBAC(f, "bgp-password", calicoNS)

			// Create a selector-based BGPPeer that peers all nodes with password auth.
			ginkgo.By("Creating a password-protected BGPPeer for all nodes")
			peer := &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "password-peer"},
				Spec: v3.BGPPeerSpec{
					NodeSelector: "all()",
					PeerSelector: "all()",
					Password: &v3.BGPPassword{
						SecretKeyRef: &corev1.SecretKeySelector{
							Key:                  "password",
							LocalObjectReference: corev1.LocalObjectReference{Name: "bgp-password"},
						},
					},
				},
			}
			err := cli.Create(ctx, peer)
			Expect(err).NotTo(HaveOccurred(), "failed to create password-protected BGPPeer")
			ginkgo.DeferCleanup(func() {
				if err := cli.Delete(context.Background(), peer); err != nil && !errors.IsNotFound(err) {
					framework.Logf("WARNING: failed to delete BGPPeer %s: %v", peer.Name, err)
				}
			})

			// Disable full mesh so only the password-protected peers are active.
			disableFullMesh(cli)

			// Verify traffic flows through password-authenticated peers.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()

			// --- Phase 2: Password mismatch should prevent peering. ---

			// Delete the working peer. With full mesh still disabled, only the
			// per-node peers we create next will be active.
			ginkgo.By("Removing the working peer for mismatch test")
			err = cli.Delete(ctx, peer)
			Expect(err).NotTo(HaveOccurred(), "failed to delete password-protected BGPPeer")

			// Get two nodes for explicit per-node peering with different passwords.
			nodes := &corev1.NodeList{}
			err = cli.List(ctx, nodes)
			Expect(err).NotTo(HaveOccurred(), "failed to list nodes")
			Expect(len(nodes.Items)).To(BeNumerically(">=", 2), "need at least 2 nodes")
			node0 := nodes.Items[0]
			node1 := nodes.Items[1]
			node0IP := nodeInternalIP(&node0)
			node1IP := nodeInternalIP(&node1)

			// Create two secrets with different passwords.
			ginkgo.By("Creating two secrets with different passwords")
			createBGPSecret(f, "bgp-secret-0", calicoNS, "alpha")
			createBGPSecret(f, "bgp-secret-1", calicoNS, "beta")
			createSecretRBAC(f, "bgp-secret-0", calicoNS)
			createSecretRBAC(f, "bgp-secret-1", calicoNS)

			// Create explicit per-node peers with mismatched passwords.
			ginkgo.By("Creating per-node BGPPeers with mismatched passwords")
			createBGPPeerWithPassword(cli, "mismatch-peer-0", node0.Name, node1IP, "bgp-secret-0")
			createBGPPeerWithPassword(cli, "mismatch-peer-1", node1.Name, node0IP, "bgp-secret-1")

			// Verify that the BGP sessions do not establish due to password mismatch.
			// We use CalicoNodeStatus to check per-peer session state rather than
			// exec'ing into calico-node pods, since CalicoNodeStatus is the user-facing
			// API for observing BGP state.
			ginkgo.By("Verifying BGP sessions stay non-established due to password mismatch")
			expectBGPPeerNotEstablished(cli, node0.Name, node1IP)
			expectBGPPeerNotEstablished(cli, node1.Name, node0IP)
		})
	},
)

// createBGPSecret creates a Secret containing a BGP password and registers cleanup.
func createBGPSecret(f *framework.Framework, name, namespace, password string) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		StringData: map[string]string{
			"password": password,
		},
	}
	_, err := f.ClientSet.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to create secret %s", name)

	ginkgo.DeferCleanup(func() {
		err := f.ClientSet.CoreV1().Secrets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			framework.Logf("WARNING: failed to delete secret %s: %v", name, err)
		}
	})
}

// createSecretRBAC creates a Role and RoleBinding allowing calico-node to read the named secret.
func createSecretRBAC(f *framework.Framework, secretName, namespace string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:         []string{"watch", "list", "get"},
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{secretName},
			},
		},
	}
	_, err := f.ClientSet.RbacV1().Roles(namespace).Create(context.Background(), role, metav1.CreateOptions{})
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to create Role for secret %s", secretName)
	ginkgo.DeferCleanup(func() {
		err := f.ClientSet.RbacV1().Roles(namespace).Delete(context.Background(), secretName, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			framework.Logf("WARNING: failed to delete Role %s: %v", secretName, err)
		}
	})

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-node",
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     secretName,
		},
	}
	_, err = f.ClientSet.RbacV1().RoleBindings(namespace).Create(context.Background(), binding, metav1.CreateOptions{})
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to create RoleBinding for secret %s", secretName)
	ginkgo.DeferCleanup(func() {
		err := f.ClientSet.RbacV1().RoleBindings(namespace).Delete(context.Background(), secretName, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			framework.Logf("WARNING: failed to delete RoleBinding %s: %v", secretName, err)
		}
	})
}

// createBGPPeerWithPassword creates a per-node BGPPeer with password authentication
// and registers cleanup.
func createBGPPeerWithPassword(cli ctrlclient.Client, name, node, peerIP, secretName string) {
	peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.BGPPeerSpec{
			Node:     node,
			PeerIP:   peerIP,
			ASNumber: 64512,
			Password: &v3.BGPPassword{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "password",
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
				},
			},
		},
	}
	err := cli.Create(context.Background(), peer)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to create BGPPeer %s", name)
	ginkgo.DeferCleanup(func() {
		if err := cli.Delete(context.Background(), peer); err != nil && !errors.IsNotFound(err) {
			framework.Logf("WARNING: failed to delete BGPPeer %s: %v", name, err)
		}
	})
}

// expectBGPPeerNotEstablished verifies via CalicoNodeStatus that the BGP session
// from nodeName to peerIP is not Established, and remains so for a sustained period.
func expectBGPPeerNotEstablished(cli ctrlclient.Client, nodeName, peerIP string) {
	status := &v3.CalicoNodeStatus{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Spec: v3.CalicoNodeStatusSpec{
			Node:                nodeName,
			Classes:             []v3.NodeStatusClassType{v3.NodeStatusClassTypeBGP},
			UpdatePeriodSeconds: ptr.To[uint32](1),
		},
	}
	err := cli.Create(context.Background(), status)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to create CalicoNodeStatus for node %s", nodeName)
	defer func() {
		err := cli.Delete(context.Background(), status)
		if err != nil && !errors.IsNotFound(err) {
			framework.Logf("WARNING: failed to delete CalicoNodeStatus for node %s: %v", nodeName, err)
		}
	}()

	// Wait for the specific peer to appear in the status report as non-established.
	EventuallyWithOffset(1, func() error {
		if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: nodeName}, status); err != nil {
			return fmt.Errorf("failed to get CalicoNodeStatus for node %s: %w", nodeName, err)
		}
		for _, peer := range status.Status.BGP.PeersV4 {
			if peer.PeerIP == peerIP {
				if peer.State == v3.BGPSessionStateEstablished {
					return fmt.Errorf("peer %s on node %s is unexpectedly Established", peerIP, nodeName)
				}
				// Found the peer and it's not established — this is the expected state.
				return nil
			}
		}
		return fmt.Errorf("peer %s not yet reported in CalicoNodeStatus for node %s (peers: %v)",
			peerIP, nodeName, status.Status.BGP.PeersV4)
	}, "30s", "1s").Should(Succeed(), "peer %s on node %s should appear as non-established", peerIP, nodeName)

	// Verify the peer stays non-established over a sustained period.
	ConsistentlyWithOffset(1, func() error {
		if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: nodeName}, status); err != nil {
			return nil // Transient error, don't fail Consistently
		}
		for _, peer := range status.Status.BGP.PeersV4 {
			if peer.PeerIP == peerIP && peer.State == v3.BGPSessionStateEstablished {
				return fmt.Errorf("peer %s on node %s unexpectedly became Established", peerIP, nodeName)
			}
		}
		return nil
	}, "10s", "1s").Should(Succeed(), "peer %s on node %s should remain non-established", peerIP, nodeName)
}

// nodeInternalIP returns the first InternalIP address of a node.
func nodeInternalIP(node *corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	framework.Failf("no InternalIP found for node %s", node.Name)
	return ""
}
