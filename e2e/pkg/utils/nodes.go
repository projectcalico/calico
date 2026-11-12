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
	GetIPv4s() []string
	GetIPv6s() []string
	GetCalicoNames() []string

	// GetIPs and GetTunnelIPs are aligned with GetNames, with "" where a node has
	// no address in the family. GetIPv4s/GetIPv6s drop those blanks, so their
	// indices only line up with GetNames on clusters where every node has one.
	GetIPs(f IPFamily) []string
	GetTunnelIPs(f IPFamily) []string

	Families() ([]IPFamily, error)
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

func (n *nodesInfo) GetIPv4s() []string {
	return nonEmpty(n.ips[IPv4])
}

func (n *nodesInfo) GetIPv6s() []string {
	return nonEmpty(n.ips[IPv6])
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

// Families errors when only some nodes have a family: on a dual-stack lane that
// is a broken node, and testing fewer families would hide it.
func (n *nodesInfo) Families() ([]IPFamily, error) {
	var families []IPFamily
	var missing []string
	for _, f := range allIPFamilies {
		have := 0
		for _, ip := range n.ips[f] {
			if ip != "" {
				have++
			}
		}
		if have == 0 {
			continue
		}
		families = append(families, f)
		for i, ip := range n.ips[f] {
			if ip == "" {
				missing = append(missing, fmt.Sprintf("%s has no %s InternalIP (has %v)", n.nodeNames[i], f, n.internalIPs[i]))
			}
		}
	}
	if len(families) == 0 {
		return nil, fmt.Errorf("no node has a parseable InternalIP: nodes %v, InternalIPs %v", n.nodeNames, n.internalIPs)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("nodes disagree on IP families %v: %s", families, strings.Join(missing, "; "))
	}
	return families, nil
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// GetNodesInfo extracts node information from a Kubernetes NodeList and returns
// a NodesInfoGetter interface that provides access to node details.
func GetNodesInfo(f *framework.Framework, nodes *corev1.NodeList, masterOK bool) NodesInfoGetter {
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
	var info NodesInfoGetter
	gomega.EventuallyWithOffset(1, func(g gomega.Gomega) {
		// Keep the per-attempt timeout well under the polling interval so a slow
		// or erroring List doesn't eat the whole Eventually budget in one attempt.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Bound generously so we still clear minCount after any master node is
		// filtered out.
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, minCount+4)
		g.Expect(err).NotTo(gomega.HaveOccurred(), "failed to list schedulable nodes")
		info = GetNodesInfo(f, nodes, masterOK)
		g.Expect(len(info.GetNames())).To(gomega.BeNumerically(">=", minCount),
			"require at least %d ready schedulable nodes, found %d", minCount, len(info.GetNames()))
	}).WithTimeout(60 * time.Second).WithPolling(5 * time.Second).Should(gomega.Succeed())
	return info
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
