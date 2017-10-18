// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package resources

import (
	"fmt"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
)

// K8sNodeToCalico converts a Kubernetes format node, with Calico annotations, to a Calico Node.
func K8sNodeToCalico(node *kapiv1.Node) (*model.KVPair, error) {
	kvp := model.KVPair{
		Key: model.ResourceKey{
			Name: node.Name,
			Kind: apiv2.KindNode,
		},
		Revision: node.ObjectMeta.ResourceVersion,
	}

	calicoNode := apiv2.NewNode()
	calicoNode.ObjectMeta.Name = node.Name
	calicoNode.ObjectMeta.Namespace = node.Namespace
	calicoNode.ObjectMeta.Labels = node.Labels
	calicoNode.Spec = apiv2.NodeSpec{
		BGP: &apiv2.NodeBGPSpec{},
	}
	annotations := node.ObjectMeta.Annotations
	ipString, ok := annotations[nodeBgpIpv4AddrAnnotation]
	if ok {
		ip := net.ParseIP(ipString)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse projectcalico.org/IPv4Address: %s", ipString)
		}

		calicoNode.Spec.BGP.IPv4Address = ipString
	}

	ipString, ok = annotations[nodeBgpIpv6AddrAnnotation]
	if ok {
		ip := net.ParseIP(ipString)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse projectcalico.org/IPv6Address: %s", ipString)
		}

		calicoNode.Spec.BGP.IPv6Address = ipString
	}

	asnString, ok := annotations[nodeBgpAsnAnnotation]
	if ok {
		asn, err := numorstring.ASNumberFromString(asnString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse projectcalico.org/ASNumber: %s", err)
		}

		calicoNode.Spec.BGP.ASNumber = &asn
	}

	calicoNode.Spec.BGP.IPv4IPIPTunnelAddr = getTunIp(node)

	kvp.Value = calicoNode

	return &kvp, nil
}

// mergeCalicoK8sNode takes a k8s node and a Calico node and push the values from the Calico
// node into the k8s node.
func mergeCalicoK8sNode(calicoNode *apiv2.Node, k8sNode *kapiv1.Node) (*kapiv1.Node, error) {
	// If the Annotations map is nil, initialize it so we can populate it
	// with Calico annotations.
	if k8sNode.Annotations == nil {
		k8sNode.Annotations = map[string]string{}
	}

	if calicoNode.Spec.BGP == nil {
		// If it is a empty NodeBGPSpec, remove all annotations.
		delete(k8sNode.Annotations, nodeBgpIpv4AddrAnnotation)
		delete(k8sNode.Annotations, nodeBgpIpv6AddrAnnotation)
		delete(k8sNode.Annotations, nodeBgpAsnAnnotation)
		delete(k8sNode.Annotations, nodeIpInIpTunnelAddr)
		return k8sNode, nil
	}

	if calicoNode.Spec.BGP.IPv4Address != "" {
		ipAddr := calicoNode.Spec.BGP.IPv4Address
		k8sNode.Annotations[nodeBgpIpv4AddrAnnotation] = ipAddr
	} else {
		delete(k8sNode.Annotations, nodeBgpIpv4AddrAnnotation)
	}

	if calicoNode.Spec.BGP.IPv6Address != "" {
		ipAddr := calicoNode.Spec.BGP.IPv6Address
		k8sNode.Annotations[nodeBgpIpv6AddrAnnotation] = ipAddr
	} else {
		delete(k8sNode.Annotations, nodeBgpIpv6AddrAnnotation)
	}

	if calicoNode.Spec.BGP.ASNumber != nil {
		k8sNode.Annotations[nodeBgpAsnAnnotation] = calicoNode.Spec.BGP.ASNumber.String()
	} else {
		delete(k8sNode.Annotations, nodeBgpAsnAnnotation)
	}

	if calicoNode.Spec.BGP.IPv4IPIPTunnelAddr != "" {
		k8sNode.Annotations[nodeIpInIpTunnelAddr] = calicoNode.Spec.BGP.IPv4IPIPTunnelAddr
	} else {
		delete(k8sNode.Annotations, nodeIpInIpTunnelAddr)
	}

	return k8sNode, nil
}

func getTunIp(n *kapiv1.Node) string {
	if n.Spec.PodCIDR == "" {
		log.Warnf("Node %s does not have podCIDR for HostConfig", n.Name)
		return ""
	}

	ip, _, err := net.ParseCIDR(n.Spec.PodCIDR)
	if err != nil {
		log.Warnf("Invalid podCIDR for HostConfig: %s, %s", n.Name, n.Spec.PodCIDR)
		return ""
	}
	// We need to get the IP for the podCIDR and increment it to the
	// first IP in the CIDR.
	tunIp := ip.To4()
	tunIp[3]++

	return tunIp.String()
}
