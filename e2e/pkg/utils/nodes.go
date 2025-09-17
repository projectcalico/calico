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
	"net"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	nodeBgpIpv4IPIPTunnelAddrAnnotation  = "projectcalico.org/IPv4IPIPTunnelAddr"
	nodeBgpIpv4VXLANTunnelAddrAnnotation = "projectcalico.org/IPv4VXLANTunnelAddr"
)

type NodesInfoGetter interface {
	GetNames() []string
	GetIPv4s() []string
	GetIPv6s() []string
	GetCalicoNames() []string
	GetTunnelIPs() []string
}

// nodesInfo implements the NodesInfoGetter interface
type nodesInfo struct {
	nodeNames       []string
	nodeIPv4s       []string
	nodeIPv6s       []string
	calicoNodeNames []string
	tunnelIPs       []string
}

func (n *nodesInfo) GetNames() []string {
	return n.nodeNames
}

func (n *nodesInfo) GetIPv4s() []string {
	return n.nodeIPv4s
}

func (n *nodesInfo) GetIPv6s() []string {
	return n.nodeIPv6s
}

func (n *nodesInfo) GetCalicoNames() []string {
	return n.calicoNodeNames
}

func (n *nodesInfo) GetTunnelIPs() []string {
	return n.tunnelIPs
}

// GetNodesInfo extracts node information from a Kubernetes NodeList and returns
// a NodesInfoGetter interface that provides access to node details.
func GetNodesInfo(f *framework.Framework, nodes *corev1.NodeList, masterOK bool) NodesInfoGetter {
	// By default, Calico node name is host name, e.g. ip-10-0-0-108.
	// Kubernetes node name could be different (ip-10-0-0-108.us-west-2.compute.internal) if cloud provider is aws.
	var nodeNames, nodeIPv4s, nodeIPv6s, calicoNodeNames, tunnelIPs []string
	for _, node := range nodes.Items {
		addrs := getNodeAddresses(&node, corev1.NodeInternalIP)
		if len(addrs) == 0 {
			framework.Failf("node %s failed to report a valid ip address\n", node.Name)
		}

		if !masterOK && checkNodeIsMaster(f, addrs) {
			logrus.Infof("Skip using master node %s", node.Name)
			continue
		}

		hostNames := getNodeAddresses(&node, corev1.NodeHostName)
		if len(hostNames) == 0 {
			framework.Failf("node %s failed to report a valid host name\n", node.Name)
		}

		nodeNames = append(nodeNames, node.Name)

		// Separate IPv4 and IPv6 addresses
		for _, addr := range addrs {
			if net.ParseIP(addr).To4() == nil && net.ParseIP(addr) != nil {
				nodeIPv6s = append(nodeIPv6s, addr)
			} else {
				nodeIPv4s = append(nodeIPv4s, addr)
			}
		}

		calicoNodeNames = append(calicoNodeNames, hostNames[0])
		tunnelIPs = append(tunnelIPs, getNodeTunnelIP(&node))
	}
	return &nodesInfo{
		nodeNames:       nodeNames,
		nodeIPv4s:       nodeIPv4s,
		nodeIPv6s:       nodeIPv6s,
		calicoNodeNames: calicoNodeNames,
		tunnelIPs:       tunnelIPs,
	}
}

func getNodeTunnelIP(node *corev1.Node) string {
	if ip, ok := node.Annotations[nodeBgpIpv4IPIPTunnelAddrAnnotation]; ok {
		return ip
	}
	if ip, ok := node.Annotations[nodeBgpIpv4VXLANTunnelAddrAnnotation]; ok {
		return ip
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
		for _, ip := range ips {
			if ip == endpointIP {
				return true
			}
		}
		return false
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
