// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package utils

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	nodeBgpIpv4IPIPTunnelAddrAnnotation  = "projectcalico.org/IPv4IPIPTunnelAddr"
	nodeBgpIpv4VXLANTunnelAddrAnnotation = "projectcalico.org/IPv4VXLANTunnelAddr"
	nodeBgpIpv6VXLANTunnelAddrAnnotation = "projectcalico.org/IPv6VXLANTunnelAddr"
)

func RequireNodeCount(f *framework.Framework, count int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nodes, err := f.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Error listing nodes")

	// Count the number of ready nodes.
	numReady := 0
	for _, node := range nodes.Items {
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
				numReady++
			}
		}
	}

	gomega.ExpectWithOffset(1, numReady).To(gomega.BeNumerically(">=", count), "Test requires at least %d nodes, found %d", count, numReady)
}

type NodesInfoGetter interface {
	GetNames() []string
	GetCalicoNames() []string

	// GetIPs and GetTunnelIPs are aligned with GetNames, with "" where a node has
	// no address in the family.
	GetIPs(f IPFamily) []string
	GetTunnelIPs(f IPFamily) []string
}

type nodesInfo struct {
	nodeNames       []string
	calicoNodeNames []string
	internalIPs     [][]string
	ips             map[IPFamily][]string
	tunnelIPs       map[IPFamily][]string
}

func (n *nodesInfo) GetNames() []string {
	return n.nodeNames
}

func (n *nodesInfo) GetCalicoNames() []string {
	return n.calicoNodeNames
}

func (n *nodesInfo) GetIPs(f IPFamily) []string {
	return n.ips[f]
}

func (n *nodesInfo) GetTunnelIPs(f IPFamily) []string {
	return n.tunnelIPs[f]
}

// checkFamilies checks only the first count nodes, the ones a spec targets:
// other nodes in the cluster don't affect the checks, so they shouldn't fail them.
func (n *nodesInfo) checkFamilies(families []IPFamily, count int) error {
	if len(n.nodeNames) < count {
		return fmt.Errorf("need %d nodes, have %d (%v)", count, len(n.nodeNames), n.nodeNames)
	}
	var missing []string
	for i := 0; i < count; i++ {
		for _, f := range families {
			if n.ips[f][i] == "" {
				missing = append(missing, fmt.Sprintf("node %s has no %s InternalIP (has %v), but the cluster's IP pools include %s", n.nodeNames[i], f, n.internalIPs[i], f))
			}
		}
	}
	if len(missing) > 0 {
		return errors.New(strings.Join(missing, "; "))
	}
	return nil
}

// GetNodesInfo extracts node information from a Kubernetes NodeList and returns
// a NodesInfoGetter interface that provides access to node details.
func GetNodesInfo(f *framework.Framework, nodes *corev1.NodeList, masterOK bool) NodesInfoGetter {
	return getNodesInfo(f, nodes, masterOK)
}

func getNodesInfo(f *framework.Framework, nodes *corev1.NodeList, masterOK bool) *nodesInfo {
	info := &nodesInfo{
		ips:       map[IPFamily][]string{},
		tunnelIPs: map[IPFamily][]string{},
	}
	for _, node := range nodes.Items {
		addrs := getNodeAddresses(&node, corev1.NodeInternalIP)
		if len(addrs) == 0 {
			framework.Failf("node %s failed to report a valid ip address\n", node.Name)
		}

		if !masterOK && checkNodeIsMaster(f, addrs) {
			logrus.Infof("Skip using master node %s", node.Name)
			continue
		}

		// By default, Calico node name is host name, e.g. ip-10-0-0-108.
		// Kubernetes node name could be different (ip-10-0-0-108.us-west-2.compute.internal) if cloud provider is aws.
		hostNames := getNodeAddresses(&node, corev1.NodeHostName)
		if len(hostNames) == 0 {
			framework.Failf("node %s failed to report a valid host name\n", node.Name)
		}

		info.addNode(node.Name, hostNames[0], addrs, node.Annotations)
	}
	return info
}

func (n *nodesInfo) addNode(name, calicoName string, internalIPs []string, annotations map[string]string) {
	n.nodeNames = append(n.nodeNames, name)
	n.calicoNodeNames = append(n.calicoNodeNames, calicoName)
	n.internalIPs = append(n.internalIPs, internalIPs)
	for _, f := range allIPFamilies {
		n.ips[f] = append(n.ips[f], firstOfFamily(internalIPs, f))
		n.tunnelIPs[f] = append(n.tunnelIPs[f], nodeTunnelIP(annotations, f))
	}
}

func firstOfFamily(ips []string, f IPFamily) string {
	for _, ip := range ips {
		if fam, ok := FamilyOf(ip); ok && fam == f {
			return ip
		}
	}
	return ""
}

// AwaitReadySchedulableNodesInfo polls until at least minCount ready and
// schedulable nodes are available, then returns their NodesInfo. masterOK
// controls whether the control-plane node is eligible (see GetNodesInfo).
//
// It retries rather than asserting once because a node can be *transiently*
// unschedulable. For example, a HostEndpoint datapath test reprogramming the
// BPF dataplane on a host interface briefly flaps calico-node readiness, which
// re-adds the node.kubernetes.io/network-unavailable:NoSchedule taint; a
// GetBoundedReadySchedulableNodes call landing in that window then reports too
// few nodes. A one-shot node-count precondition races that recovery and fails
// spuriously — use this helper for any multi-node requirement instead.
func AwaitReadySchedulableNodesInfo(f *framework.Framework, minCount int, masterOK bool) NodesInfoGetter {
	return awaitReadySchedulableNodes(f, minCount, masterOK, 2)
}

func awaitReadySchedulableNodes(f *framework.Framework, minCount int, masterOK bool, offset int) *nodesInfo {
	var info *nodesInfo
	gomega.EventuallyWithOffset(offset, func(g gomega.Gomega) {
		// Keep the per-attempt timeout well under the polling interval so a slow
		// or erroring List doesn't eat the whole Eventually budget in one attempt.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Bound generously so we still clear minCount after any master node is
		// filtered out.
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, minCount+4)
		g.Expect(err).NotTo(gomega.HaveOccurred(), "failed to list schedulable nodes")
		info = getNodesInfo(f, nodes, masterOK)
		g.Expect(len(info.GetNames())).To(gomega.BeNumerically(">=", minCount),
			"require at least %d ready schedulable nodes, found %d", minCount, len(info.GetNames()))
	}).WithTimeout(60 * time.Second).WithPolling(5 * time.Second).Should(gomega.Succeed())
	return info
}

// FamilyNodes is the first n ready, schedulable nodes, each with an address in
// every IP family the cluster's IP pools give pods. Slices are indexed by node.
type FamilyNodes struct {
	Families    []IPFamily
	Names       []string
	CalicoNames []string
	IPs         map[IPFamily][]string
	TunnelIPs   map[IPFamily][]string
}

// AwaitFamilyNodes fails the spec if the IP pools can't be read or one of the n
// nodes has no address in a pool family.
func AwaitFamilyNodes(f *framework.Framework, cli ctrlclient.Client, n int) FamilyNodes {
	info := awaitReadySchedulableNodes(f, n, false, 2)
	families, err := PoolFamilies(cli)
	framework.ExpectNoError(err)
	framework.ExpectNoError(info.checkFamilies(families, n))
	nodes := FamilyNodes{
		Families:    families,
		Names:       info.GetNames()[:n],
		CalicoNames: info.GetCalicoNames()[:n],
		IPs:         map[IPFamily][]string{},
		TunnelIPs:   map[IPFamily][]string{},
	}
	for _, fam := range families {
		nodes.IPs[fam] = info.GetIPs(fam)[:n]
		nodes.TunnelIPs[fam] = info.GetTunnelIPs(fam)[:n]
	}
	return nodes
}

// nodeTunnelIP prefers IPIP for IPv4; IPIP has no IPv6 form.
func nodeTunnelIP(annotations map[string]string, f IPFamily) string {
	keys := []string{nodeBgpIpv4IPIPTunnelAddrAnnotation, nodeBgpIpv4VXLANTunnelAddrAnnotation}
	if f == IPv6 {
		keys = []string{nodeBgpIpv6VXLANTunnelAddrAnnotation}
	}
	for _, k := range keys {
		if ip, ok := annotations[k]; ok {
			return ip
		}
	}
	return ""
}

func getNodeAddresses(node *corev1.Node, addressType corev1.NodeAddressType) (ips []string) {
	for j := range node.Status.Addresses {
		nodeAddress := &node.Status.Addresses[j]
		if nodeAddress.Type == addressType {
			ips = append(ips, nodeAddress.Address)
		}
	}
	return
}

func checkNodeIsMaster(f *framework.Framework, ips []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpnts, err := f.ClientSet.CoreV1().Endpoints("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if err != nil {
		framework.Failf("Get endpoints for service kubernetes failed (%s)", err)
	}
	if len(endpnts.Subsets) == 0 {
		framework.Failf("Endpoint has no subsets, cannot determine node addresses.")
	}

	hasIP := func(endpointIP string) bool {
		return slices.Contains(ips, endpointIP)
	}

	for _, ss := range endpnts.Subsets {
		for _, e := range ss.Addresses {
			if hasIP(e.IP) {
				return true
			}
		}
	}

	return false
}
