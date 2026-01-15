// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
)

// DESCRIPTION: This test only verifies bgp password via birdcl output
// It picks two worker nodes and set bgppeer with correct password
// and verifies that all is as expected by looking at birdcl ouput.
// Then it configures bgppeers with different password and
// verifies that all is as expected by looking at birdcl output.

// Once the bgppeers are configured, k8s apiserver will likely lose
// connectivity with the Calico apiserver (by not having a route anymore - since
// the peering is only between the worker nodes).
// That is the reason why after configuring/verifying bgpconfiguration
// and bgppeers, we delete the crd version of the resource instead of corresponding projectcalico.org/v3
// resource.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Networking),
	describe.WithSerial(),
	describe.WithFeature("BGP"),
	"BGP password tests",
	func() {
		var nodeNames []string
		var nodeIPs []string
		var cli ctrlclient.Client
		var calicoNamespace string
		var restoreBGPConfig func()

		const peer0Name string = "peer0"
		const peer1Name string = "peer1"
		const bgpSecret0Name string = "bgp-secret0"
		const bgpSecret1Name string = "bgp-secret1"

		f := utils.NewDefaultFramework("bgp-password")

		BeforeEach(func() {
			// We need a minimum of two nodes for BGP peering tests.
			utils.RequireNodeCount(f, 2)

			// Get two ready schedulable nodes.
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(context.TODO(), f.ClientSet, 10)
			Expect(err).ShouldNot(HaveOccurred())
			if len(nodes.Items) == 0 {
				Fail("No schedulable nodes exist, can't continue test.")
			}
			nodesInfo := utils.GetNodesInfo(f, nodes, false)
			nodeNames = nodesInfo.GetNames()
			nodeIPs = nodesInfo.GetIPv4s()

			if !birdIsRunning(f, nodeNames[0]) {
				e2eskipper.Skipf("Skipping BGP Password test because BIRD is not running")
			}

			calicoNamespace = utils.CalicoNamespace(f)

			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			// Ensure full-mesh BGP is functioning before each test.
			restoreBGPConfig = ensureInitialBGPConfig(cli)

			// Check if peer has been established.
			waitForBGPEstablishedForNode(cli, nodeNames[0])
			waitForBGPEstablishedForNode(cli, nodeNames[1])

			addCalicoNodeRbacForSecret(f, bgpSecret0Name, calicoNamespace)
			addCalicoNodeRbacForSecret(f, bgpSecret1Name, calicoNamespace)
		})

		AfterEach(func() {
			restoreBGPConfig()

			// Clean up the RBAC we created.

			// Ensure peering has been restored.
			waitForBGPEstablishedForNode(cli, nodeNames[0])
			waitForBGPEstablishedForNode(cli, nodeNames[1])

			removeCalicoNodeRbacForSecret(f, bgpSecret0Name, calicoNamespace)
			removeCalicoNodeRbacForSecret(f, bgpSecret1Name, calicoNamespace)
		})

		It("should require a BGP password if given", func() {
			By("creating two secrets with same password")
			createSecret(f, bgpSecret0Name, calicoNamespace, "password0")
			createSecret(f, bgpSecret1Name, calicoNamespace, "password0")

			By("Configure explicit peering between two nodes with same password")
			createBGPPeer(cli, peer0Name, nodeNames[0], nodeIPs[1], bgpSecret0Name)
			createBGPPeer(cli, peer1Name, nodeNames[1], nodeIPs[0], bgpSecret1Name)

			// Disable full mesh so that node peering connection would not stay Idle.
			disableFullMesh(cli)

			// BGP should be established on both nodes.
			waitForBGPEstablishedForNode(cli, nodeNames[0])
			waitForBGPEstablishedForNode(cli, nodeNames[1])

			restoreBGPConfig()

			By("Creating a secret with a different password")
			createSecret(f, bgpSecret1Name, calicoNamespace, "password1")

			By("Set bgp peers with different password")
			createBGPPeer(cli, peer0Name, nodeNames[0], nodeIPs[1], bgpSecret0Name)
			createBGPPeer(cli, peer1Name, nodeNames[1], nodeIPs[0], bgpSecret1Name)

			// Disable full mesh so that node peering connection would not stay Idle.
			disableFullMesh(cli)

			By("Checking bgp peer sessions stay in Connect because of password mismatch")
			Eventually(func() bool {
				return checkPeerForCalicoNode(f, nodeNames[0], nodeIPs[1], "Connect")
			}, "10s", "1s").Should(BeTrue())
			Eventually(func() bool {
				return checkPeerForCalicoNode(f, nodeNames[1], nodeIPs[0], "Connect")
			}, "10s", "1s").Should(BeTrue())

			Consistently(func() bool {
				return checkPeerForCalicoNode(f, nodeNames[0], nodeIPs[1], "Connect")
			}, "5s", "1s").Should(BeTrue())
			Consistently(func() bool {
				return checkPeerForCalicoNode(f, nodeNames[1], nodeIPs[0], "Connect")
			}, "5s", "1s").Should(BeTrue())
		})
	},
)

func createSecret(f *framework.Framework, secretName, secretNamespace, password string) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretNamespace,
			Name:      secretName,
		},
		StringData: map[string]string{
			"password": password,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := f.ClientSet.CoreV1().Secrets(secretNamespace).Create(ctx, secret, metav1.CreateOptions{})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	DeferCleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := f.ClientSet.CoreV1().Secrets(secretNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	})
}

// Get calico-node pod.
func getCalicoNodePod(f *framework.Framework, nodeName string) *v1.Pod {
	// Get calico-node pods.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	podList, err := f.ClientSet.CoreV1().Pods(metav1.NamespaceAll).List(
		ctx,
		metav1.ListOptions{
			FieldSelector: fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName}).String(),
			LabelSelector: labels.SelectorFromSet(map[string]string{"k8s-app": "calico-node"}).String(),
		},
	)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(podList.Items)).To(Equal(1))
	return &(podList.Items[0])
}

func addCalicoNodeRbacForSecret(f *framework.Framework, secretName, secretNamespace string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := f.ClientSet.RbacV1().Roles(secretNamespace).Create(ctx, role, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-node",
				Namespace: secretNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     secretName,
		},
	}

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = f.ClientSet.RbacV1().RoleBindings(secretNamespace).Create(ctx, binding, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func removeCalicoNodeRbacForSecret(f *framework.Framework, secretName, secretNamespace string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := f.ClientSet.RbacV1().RoleBindings(secretNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = f.ClientSet.RbacV1().Roles(secretNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func birdIsRunning(f *framework.Framework, nodeName string) bool {
	// Get calico-node pod.
	pod := getCalicoNodePod(f, nodeName)

	// Try to run birdcl.
	output, err := kubectl.RunKubectl(pod.Namespace,
		"exec",
		"--",
		"birdcl",
		"-s", "/var/run/calico/bird.ctl",
		"show",
		"protocol")
	logrus.WithError(err).Infof("birdcl error, output %s", output)

	return err == nil
}

// Check peering status.
// If peering is established, keyWord to check is Established.
// If peering duplicated, keyWord to check is Idle.
// If peering with mismatched password, keyWord to check is Connect.
func checkPeerForCalicoNode(f *framework.Framework, nodeName string, peerIP string, keyWord string) bool {
	// Get calico-node pod.
	pod := getCalicoNodePod(f, nodeName)

	// Run birdcl.
	output, err := kubectl.RunKubectl(pod.Namespace,
		"exec",
		pod.Name,
		"--",
		"birdcl",
		"-s", "/var/run/calico/bird.ctl",
		"show",
		"protocol")
	Expect(err).NotTo(HaveOccurred())
	logrus.Infof("output is %s", output)

	// Extract birdcl output.
	ipString := strings.Replace(peerIP, ".", "_", -1)

	// Check if bgp session status with keyWord.
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, ipString) && strings.Contains(line, keyWord) {
			logrus.Infof("BGP session found keyWord with peer. < %s >", line)
			return true
		}
	}

	return false
}

// Set bgp peer resources.
func createBGPPeer(cli ctrlclient.Client, name, node, peerIP, secret string) {
	as, err := numorstring.ASNumberFromString("64512")
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	peer := v3.NewBGPPeer()
	peer.Name = name
	peer.Spec = v3.BGPPeerSpec{
		Node:     node,
		PeerIP:   peerIP,
		ASNumber: as,
		Password: &v3.BGPPassword{
			SecretKeyRef: &v1.SecretKeySelector{
				Key:                  "password",
				LocalObjectReference: v1.LocalObjectReference{Name: secret},
			},
		},
	}
	err = cli.Create(context.Background(), peer)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	DeferCleanup(func() {
		err := cli.Delete(context.Background(), peer)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	})
}
