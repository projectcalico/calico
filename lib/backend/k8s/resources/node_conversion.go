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

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	kapiv1 "k8s.io/client-go/pkg/api/v1"
)

// K8sNodeToCalico converts a Kubernetes format node, with Calico annotations, to a Calico Node.
func K8sNodeToCalico(node *kapiv1.Node) (*model.KVPair, error) {
	kvp := model.KVPair{
		Key: model.NodeKey{
			Hostname: node.Name,
		},
		Revision: node.ObjectMeta.ResourceVersion,
	}

	calicoNode := model.Node{}
	calicoNode.Labels = node.Labels
	annotations := node.ObjectMeta.Annotations
	cidrString, ok := annotations[nodeBgpIpv4CidrAnnotation]
	if ok {
		ip, cidr, err := net.ParseCIDR(cidrString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse projectcalico.org/IPv4Address: %s", err)
		}

		calicoNode.FelixIPv4 = ip
		calicoNode.BGPIPv4Addr = ip
		calicoNode.BGPIPv4Net = cidr
	}

	asnString, ok := annotations[nodeBgpAsnAnnotation]
	if ok {
		asn, err := numorstring.ASNumberFromString(asnString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse projectcalico.org/ASNumber: %s", err)
		}

		calicoNode.BGPASNumber = &asn
	}

	kvp.Value = &calicoNode

	return &kvp, nil
}

// mergeCalicoK8sNode takes a k8s node and a Calico node and push the values from the Calico
// node into the k8s node.
func mergeCalicoK8sNode(calicoNode *model.Node, k8sNode *kapiv1.Node) (*kapiv1.Node, error) {
	// If the Annotations map is nil, initialize it so we can populate it
	// with Calico annotations.
	if k8sNode.Annotations == nil {
		k8sNode.Annotations = map[string]string{}
	}

	// In order to make sure we always end up with a CIDR that has the IP and not just network
	// we assemble the CIDR from BGPIPv4Addr and BGPIPv4Net.
	if calicoNode.BGPIPv4Net != nil {
		subnet, _ := calicoNode.BGPIPv4Net.Mask.Size()
		ipCidr := fmt.Sprintf("%s/%d", calicoNode.BGPIPv4Addr.String(), subnet)
		k8sNode.Annotations[nodeBgpIpv4CidrAnnotation] = ipCidr
	} else {
		delete(k8sNode.Annotations, nodeBgpIpv4CidrAnnotation)
	}

	// Don't set the ASNumber if it is nil, and ensure it does not exist in k8s.
	if calicoNode.BGPASNumber != nil {
		k8sNode.Annotations[nodeBgpAsnAnnotation] = calicoNode.BGPASNumber.String()
	} else {
		delete(k8sNode.Annotations, nodeBgpAsnAnnotation)
	}

	return k8sNode, nil
}
