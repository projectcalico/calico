// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

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
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

const (
	nodeBgpIpv4AddrAnnotation = "projectcalico.org/IPv4Address"
	nodeBgpIpv6AddrAnnotation = "projectcalico.org/IPv6Address"
	nodeBgpAsnAnnotation      = "projectcalico.org/ASNumber"
	nodeBgpCIDAnnotation      = "projectcalico.org/RouteReflectorClusterID"
)

func NewNodeClient(c *kubernetes.Clientset) K8sResourceClient {
	return &nodeClient{
		clientSet: c,
	}
}

// Implements the api.Client interface for Nodes.
type nodeClient struct {
	clientSet *kubernetes.Clientset
}

func (c *nodeClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Warn("Operation Create is not supported on Node type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *nodeClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on Node type")
	// Get a current copy of the node to fill in fields we don't track.
	oldNode, err := c.clientSet.CoreV1().Nodes().Get(kvp.Key.(model.ResourceKey).Name, metav1.GetOptions{})
	if err != nil {
		return nil, K8sErrorToCalico(err, kvp.Key)
	}

	node, err := mergeCalicoNodeIntoK8sNode(kvp.Value.(*apiv3.Node), oldNode)
	if err != nil {
		return nil, err
	}

	newNode, err := c.clientSet.CoreV1().Nodes().UpdateStatus(node)
	if err != nil {
		log.WithError(err).Info("Error updating Node resource")
		return nil, K8sErrorToCalico(err, kvp.Key)
	}

	newCalicoNode, err := K8sNodeToCalico(newNode)
	if err != nil {
		log.Errorf("Failed to parse returned Node after call to update %+v", newNode)
		return nil, err
	}

	return newCalicoNode, nil
}

func (c *nodeClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on Node type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *nodeClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on Node type")
	node, err := c.clientSet.CoreV1().Nodes().Get(key.(model.ResourceKey).Name, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}

	kvp, err := K8sNodeToCalico(node)
	if err != nil {
		log.WithError(err).Error("Couldn't convert k8s node.")
		return nil, err
	}

	return kvp, nil
}

func (c *nodeClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debug("Received List request on Node type")
	nl := list.(model.ResourceListOptions)
	kvps := []*model.KVPair{}

	if nl.Name != "" {
		// The node is already fully qualified, so perform a Get instead.
		// If the entry does not exist then we just return an empty list.
		kvp, err := c.Get(ctx, model.ResourceKey{Name: nl.Name, Kind: apiv3.KindNode}, revision)
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
				return nil, err
			}
			return &model.KVPairList{
				KVPairs:  kvps,
				Revision: revision,
			}, nil
		}

		kvps = append(kvps, kvp)
		return &model.KVPairList{
			KVPairs:  []*model.KVPair{kvp},
			Revision: revision,
		}, nil
	}

	// Listing all nodes.
	nodes, err := c.clientSet.CoreV1().Nodes().List(metav1.ListOptions{ResourceVersion: revision})
	if err != nil {
		K8sErrorToCalico(err, list)
	}

	for _, node := range nodes.Items {
		kvp, err := K8sNodeToCalico(&node)
		if err != nil {
			log.Errorf("Unable to convert k8s node to Calico node: node=%s: %v", node.Name, err)
			continue
		}
		kvps = append(kvps, kvp)
	}

	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: revision,
	}, nil
}

func (c *nodeClient) EnsureInitialized() error {
	return nil
}

func (c *nodeClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// Build watch options to pass to k8s.
	opts := metav1.ListOptions{ResourceVersion: revision, Watch: true}
	rlo, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}
	if len(rlo.Name) != 0 {
		// We've been asked to watch a specific node resource.
		log.WithField("name", rlo.Name).Debug("Watching a single node")
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", rlo.Name).String()
	}

	k8sWatch, err := c.clientSet.CoreV1().Nodes().Watch(opts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		k8sNode, ok := r.(*kapiv1.Node)
		if !ok {
			return nil, errors.New("node conversion with incorrect k8s resource type")
		}
		return K8sNodeToCalico(k8sNode)
	}
	return newK8sWatcherConverter(ctx, "Node", converter, k8sWatch), nil
}

// K8sNodeToCalico converts a Kubernetes format node, with Calico annotations, to a Calico Node.
func K8sNodeToCalico(k8sNode *kapiv1.Node) (*model.KVPair, error) {
	// Create a new CalicoNode resource and copy the settings across from the k8s Node.
	calicoNode := apiv3.NewNode()
	calicoNode.ObjectMeta.Name = k8sNode.Name
	SetCalicoMetadataFromK8sAnnotations(calicoNode, k8sNode)

	// Extract the BGP configuration stored in the annotations.
	bgpSpec := &apiv3.NodeBGPSpec{}
	annotations := k8sNode.ObjectMeta.Annotations
	bgpSpec.IPv4Address = annotations[nodeBgpIpv4AddrAnnotation]
	bgpSpec.IPv6Address = annotations[nodeBgpIpv6AddrAnnotation]
	bgpSpec.RouteReflectorClusterID = annotations[nodeBgpCIDAnnotation]
	asnString, ok := annotations[nodeBgpAsnAnnotation]
	if ok {
		asn, err := numorstring.ASNumberFromString(asnString)
		if err != nil {
			log.WithError(err).Infof("failed to read node AS number from annotation: %s", nodeBgpAsnAnnotation)
		} else {
			bgpSpec.ASNumber = &asn
		}
	}

	if k8sNode.Spec.PodCIDR != "" {
		_, cidr, err := net.ParseCIDR(k8sNode.Spec.PodCIDR)
		if err != nil {
			log.WithError(err).Errorf("PodCIDR %s did not parse successfully", k8sNode.Spec.PodCIDR)
			return nil, errors.New("Invalid PodCIDR")
		} else if cidr.Version() == 4 {
			// For back compatibility with v2.6.x, always generate a tunnel address if we have the pod
			// CIDR.
			bgpSpec.IPv4IPIPTunnelAddr = getTunnelIp(k8sNode)
		}
		calicoNode.Spec.BGP = bgpSpec
	} else if bgpSpec.IPv4Address != "" || bgpSpec.IPv6Address != "" || bgpSpec.ASNumber != nil {
		log.Warnf("Node %s does not have podCIDR to use to calculate the IPIP Tunnel Address", k8sNode.Name)
		calicoNode.Spec.BGP = bgpSpec
	}

	// Create the resource key from the node name.
	return &model.KVPair{
		Key: model.ResourceKey{
			Name: k8sNode.Name,
			Kind: apiv3.KindNode,
		},
		Value:    calicoNode,
		Revision: k8sNode.ObjectMeta.ResourceVersion,
	}, nil
}

// mergeCalicoNodeIntoK8sNode takes a k8s node and a Calico node and push the values from the Calico
// node into the k8s node.
func mergeCalicoNodeIntoK8sNode(calicoNode *apiv3.Node, k8sNode *kapiv1.Node) (*kapiv1.Node, error) {
	// Set the k8s annotations from the Calico node metadata.  This ensures the k8s annotations
	// is initialized.
	SetK8sAnnotationsFromCalicoMetadata(k8sNode, calicoNode)

	if calicoNode.Spec.BGP == nil {
		// If it is a empty NodeBGPSpec, remove all annotations.
		delete(k8sNode.Annotations, nodeBgpIpv4AddrAnnotation)
		delete(k8sNode.Annotations, nodeBgpIpv6AddrAnnotation)
		delete(k8sNode.Annotations, nodeBgpAsnAnnotation)
		delete(k8sNode.Annotations, nodeBgpCIDAnnotation)
		return k8sNode, nil
	}

	if calicoNode.Spec.BGP.IPv4Address != "" {
		k8sNode.Annotations[nodeBgpIpv4AddrAnnotation] = calicoNode.Spec.BGP.IPv4Address
	} else {
		delete(k8sNode.Annotations, nodeBgpIpv4AddrAnnotation)
	}

	if calicoNode.Spec.BGP.IPv6Address != "" {
		k8sNode.Annotations[nodeBgpIpv6AddrAnnotation] = calicoNode.Spec.BGP.IPv6Address
	} else {
		delete(k8sNode.Annotations, nodeBgpIpv6AddrAnnotation)
	}

	if calicoNode.Spec.BGP.ASNumber != nil {
		k8sNode.Annotations[nodeBgpAsnAnnotation] = calicoNode.Spec.BGP.ASNumber.String()
	} else {
		delete(k8sNode.Annotations, nodeBgpAsnAnnotation)
	}

	if calicoNode.Spec.BGP.RouteReflectorClusterID != "" {
		k8sNode.Annotations[nodeBgpCIDAnnotation] = calicoNode.Spec.BGP.RouteReflectorClusterID
	} else {
		delete(k8sNode.Annotations, nodeBgpCIDAnnotation)
	}

	return k8sNode, nil
}

// Calculate the IPIP Tunnel IP address to use for a given Node.  We use the first IP in the
// node CIDR for our tunnel address.  If an IPv4 address cannot be picked from the given
// CIDR then an empty string will be returned.
func getTunnelIp(n *kapiv1.Node) string {
	ip, _, err := net.ParseCIDR(n.Spec.PodCIDR)
	if err != nil {
		log.Warnf("Invalid podCIDR for HostConfig: %s, %s", n.Name, n.Spec.PodCIDR)
		return ""
	}
	// We need to get the IP for the podCIDR and increment it to the
	// first IP in the CIDR.
	tunIp := ip.To4()
	if tunIp == nil {
		log.WithField("podCIDR", n.Spec.PodCIDR).Infof("Cannot pick an IPv4 tunnel address from the given CIDR")
		return ""
	}
	tunIp[3]++

	return tunIp.String()
}
