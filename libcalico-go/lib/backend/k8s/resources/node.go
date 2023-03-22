// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	validatorv3 "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

const (
	nodeBgpIpv4AddrAnnotation             = "projectcalico.org/IPv4Address"
	nodeBgpIpv4IPIPTunnelAddrAnnotation   = "projectcalico.org/IPv4IPIPTunnelAddr"
	nodeBgpIpv4VXLANTunnelAddrAnnotation  = "projectcalico.org/IPv4VXLANTunnelAddr"
	nodeBgpVXLANTunnelMACAddrAnnotation   = "projectcalico.org/VXLANTunnelMACAddr"
	nodeBgpIpv6VXLANTunnelAddrAnnotation  = "projectcalico.org/IPv6VXLANTunnelAddr"
	nodeBgpVXLANTunnelMACAddrV6Annotation = "projectcalico.org/VXLANTunnelMACAddrV6"
	nodeBgpIpv6AddrAnnotation             = "projectcalico.org/IPv6Address"
	nodeBgpAsnAnnotation                  = "projectcalico.org/ASNumber"
	nodeBgpCIDAnnotation                  = "projectcalico.org/RouteReflectorClusterID"
	nodeK8sLabelAnnotation                = "projectcalico.org/kube-labels"
	nodeWireguardIpv4IfaceAddrAnnotation  = "projectcalico.org/IPv4WireguardInterfaceAddr"
	nodeWireguardIpv6IfaceAddrAnnotation  = "projectcalico.org/IPv6WireguardInterfaceAddr"
	nodeWireguardPublicKeyAnnotation      = "projectcalico.org/WireguardPublicKey"
	nodeWireguardPublicKeyV6Annotation    = "projectcalico.org/WireguardPublicKeyV6"
)

func NewNodeClient(c *kubernetes.Clientset, usePodCIDR bool) K8sResourceClient {
	return &nodeClient{
		clientSet:  c,
		usePodCIDR: usePodCIDR,
	}
}

type validatorFunc func(string) error

// Implements the api.Client interface for Nodes.
type nodeClient struct {
	clientSet  *kubernetes.Clientset
	usePodCIDR bool
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
	oldNode, err := c.clientSet.CoreV1().Nodes().Get(ctx, kvp.Key.(model.ResourceKey).Name, metav1.GetOptions{})
	if err != nil {
		return nil, K8sErrorToCalico(err, kvp.Key)
	}

	node, err := mergeCalicoNodeIntoK8sNode(kvp.Value.(*libapiv3.Node), oldNode)
	if err != nil {
		return nil, err
	}

	newNode, err := c.clientSet.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Info("Error updating Node resource")
		return nil, K8sErrorToCalico(err, kvp.Key)
	}

	newCalicoNode, err := K8sNodeToCalico(newNode, c.usePodCIDR)
	if err != nil {
		log.Errorf("Failed to parse returned Node after call to update %+v", newNode)
		return nil, err
	}

	return newCalicoNode, nil
}

func (c *nodeClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *nodeClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on Node type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *nodeClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on Node type")
	node, err := c.clientSet.CoreV1().Nodes().Get(ctx, key.(model.ResourceKey).Name, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}

	kvp, err := K8sNodeToCalico(node, c.usePodCIDR)
	if err != nil {
		log.WithError(err).Error("Couldn't convert k8s node.")
		return nil, err
	}

	return kvp, nil
}

func (c *nodeClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	logContext := log.WithField("Resource", "Node")
	logContext.Debug("Received List request")
	nl := list.(model.ResourceListOptions)
	kvps := []*model.KVPair{}

	if nl.Name != "" {
		// The node is already fully qualified, so perform a Get instead.
		// If the entry does not exist then we just return an empty list.
		kvp, err := c.Get(ctx, model.ResourceKey{Name: nl.Name, Kind: libapiv3.KindNode}, revision)
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
			KVPairs:  kvps,
			Revision: revision,
		}, nil
	}

	// List all nodes.
	listFunc := func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		nodes, err := c.clientSet.CoreV1().Nodes().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		return nodes, nil
	}
	convertFunc := func(r Resource) ([]*model.KVPair, error) {
		node := r.(*v1.Node)
		kvp, err := K8sNodeToCalico(node, c.usePodCIDR)
		if err != nil {
			return nil, err
		}
		return []*model.KVPair{kvp}, nil
	}
	return pagedList(ctx, logContext, revision, list, convertFunc, listFunc)
}

func (c *nodeClient) EnsureInitialized() error {
	return nil
}

func (c *nodeClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// Build watch options to pass to k8s.
	opts := metav1.ListOptions{ResourceVersion: revision, Watch: true, AllowWatchBookmarks: false}
	rlo, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}
	if len(rlo.Name) != 0 {
		// We've been asked to watch a specific node resource.
		log.WithField("name", rlo.Name).Debug("Watching a single node")
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", rlo.Name).String()
	}

	k8sWatch, err := c.clientSet.CoreV1().Nodes().Watch(ctx, opts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		k8sNode, ok := r.(*kapiv1.Node)
		if !ok {
			return nil, errors.New("node conversion with incorrect k8s resource type")
		}
		return K8sNodeToCalico(k8sNode, c.usePodCIDR)
	}
	return newK8sWatcherConverter(ctx, "Node", converter, k8sWatch), nil
}

// K8sNodeToCalico converts a Kubernetes format node, with Calico annotations, to a Calico Node.
func K8sNodeToCalico(k8sNode *kapiv1.Node, usePodCIDR bool) (*model.KVPair, error) {
	// Create a new CalicoNode resource and copy the settings across from the k8s Node.
	calicoNode := libapiv3.NewNode()
	calicoNode.ObjectMeta.Name = k8sNode.Name
	SetCalicoMetadataFromK8sAnnotations(calicoNode, k8sNode)

	// Calico Nodes inherit labels from Kubernetes nodes, do that merge.
	err := mergeCalicoAndK8sLabels(calicoNode, k8sNode)
	if err != nil {
		log.WithError(err).Error("Failed to merge Calico and Kubernetes labels.")
		return nil, err
	}

	// Extract the BGP configuration stored in the annotations.
	bgpSpec := &libapiv3.NodeBGPSpec{}
	annotations := k8sNode.ObjectMeta.Annotations
	bgpSpec.IPv4Address = getAnnotation(k8sNode, nodeBgpIpv4AddrAnnotation, validatorv3.ValidateCIDRv4)
	bgpSpec.IPv6Address = getAnnotation(k8sNode, nodeBgpIpv6AddrAnnotation, validatorv3.ValidateCIDRv6)
	bgpSpec.RouteReflectorClusterID = getAnnotation(k8sNode, nodeBgpCIDAnnotation, validatorv3.ValidateIPv4Network)

	asnString, ok := annotations[nodeBgpAsnAnnotation]
	if ok {
		asn, err := numorstring.ASNumberFromString(asnString)
		if err != nil {
			log.WithError(err).Infof("failed to read node AS number from annotation: %s", nodeBgpAsnAnnotation)
		} else {
			bgpSpec.ASNumber = &asn
		}
	}

	// Initialize the wireguard spec. We'll include it if it contains non-zero data.
	wireguardSpec := &libapiv3.NodeWireguardSpec{}

	// Add in an orchestrator reference back to the Kubernetes node name.
	calicoNode.Spec.OrchRefs = []libapiv3.OrchRef{{NodeName: k8sNode.Name, Orchestrator: apiv3.OrchestratorKubernetes}}

	// If using host-local IPAM, assign an IPIP and wireguard tunnel address statically. They can both have the same IP.
	if usePodCIDR && k8sNode.Spec.PodCIDR != "" {
		// For back compatibility with v2.6.x, always generate an IPIP tunnel address if we have the pod CIDR.
		tunnelAddr, err := getStaticTunnelAddress(k8sNode)
		if err != nil {
			return nil, err
		}
		bgpSpec.IPv4IPIPTunnelAddr = tunnelAddr

		// Only assign the wireguard tunnel IP if we have a public key assigned - this is inline with how the IPs are
		// assigned in the calico IPAM scenarios.
		if annotations[nodeWireguardPublicKeyAnnotation] != "" {
			wireguardSpec.InterfaceIPv4Address = tunnelAddr
		}
	} else {
		// We are not using host local, so assign tunnel addresses from annotations.
		bgpSpec.IPv4IPIPTunnelAddr = getAnnotation(k8sNode, nodeBgpIpv4IPIPTunnelAddrAnnotation, validatorv3.ValidateIPv4Network)
		wireguardSpec.InterfaceIPv4Address = getAnnotation(k8sNode, nodeWireguardIpv4IfaceAddrAnnotation, validatorv3.ValidateIPv4Network)
		wireguardSpec.InterfaceIPv6Address = getAnnotation(k8sNode, nodeWireguardIpv6IfaceAddrAnnotation, validatorv3.ValidateIPv6Network)
	}

	// Only set the BGP spec if it is not empty.
	if !reflect.DeepEqual(*bgpSpec, libapiv3.NodeBGPSpec{}) {
		calicoNode.Spec.BGP = bgpSpec
	}

	// Only set the Wireguard spec if it is not empty.
	if !reflect.DeepEqual(*wireguardSpec, libapiv3.NodeWireguardSpec{}) {
		calicoNode.Spec.Wireguard = wireguardSpec
	}

	// Set the VXLAN tunnel addresses based on annotation.
	calicoNode.Spec.IPv4VXLANTunnelAddr = getAnnotation(k8sNode, nodeBgpIpv4VXLANTunnelAddrAnnotation, validatorv3.ValidateIPv4Network)
	calicoNode.Spec.VXLANTunnelMACAddr = getAnnotation(k8sNode, nodeBgpVXLANTunnelMACAddrAnnotation, validatorv3.ValidateMAC)
	calicoNode.Spec.IPv6VXLANTunnelAddr = getAnnotation(k8sNode, nodeBgpIpv6VXLANTunnelAddrAnnotation, validatorv3.ValidateIPv6Network)
	calicoNode.Spec.VXLANTunnelMACAddrV6 = getAnnotation(k8sNode, nodeBgpVXLANTunnelMACAddrV6Annotation, validatorv3.ValidateMAC)

	// Set the node status
	nodeStatus := libapiv3.NodeStatus{}
	nodeStatus.WireguardPublicKey = annotations[nodeWireguardPublicKeyAnnotation]
	nodeStatus.WireguardPublicKeyV6 = annotations[nodeWireguardPublicKeyV6Annotation]
	if !reflect.DeepEqual(nodeStatus, libapiv3.NodeStatus{}) {
		calicoNode.Status = nodeStatus
	}

	// Fill in status with Kubernetes pod CIDRs.
	if len(k8sNode.Spec.PodCIDRs) > 0 {
		calicoNode.Status.PodCIDRs = make([]string, len(k8sNode.Spec.PodCIDRs))
		for i, c := range k8sNode.Spec.PodCIDRs {
			calicoNode.Status.PodCIDRs[i] = c
		}
	}

	// Fill the list of all addresses from the calico Node
	fillAllAddresses(calicoNode, k8sNode)

	// Create the resource key from the node name.
	return &model.KVPair{
		Key: model.ResourceKey{
			Name: k8sNode.Name,
			Kind: libapiv3.KindNode,
		},
		Value:    calicoNode,
		Revision: k8sNode.ObjectMeta.ResourceVersion,
	}, nil
}

func fillAllAddresses(calicoNode *libapiv3.Node, k8sNode *kapiv1.Node) {
	if bgp := calicoNode.Spec.BGP; bgp != nil {
		if addr := bgp.IPv4Address; addr != "" {
			calicoNode.Spec.Addresses = append(calicoNode.Spec.Addresses, libapiv3.NodeAddress{Address: addr, Type: libapiv3.CalicoNodeIP})
		}
		if addr := bgp.IPv6Address; addr != "" {
			calicoNode.Spec.Addresses = append(calicoNode.Spec.Addresses, libapiv3.NodeAddress{Address: addr, Type: libapiv3.CalicoNodeIP})
		}
	}

	for _, kaddr := range k8sNode.Status.Addresses {
		switch kaddr.Type {
		case kapiv1.NodeInternalIP:
			calicoNode.Spec.Addresses = append(calicoNode.Spec.Addresses, libapiv3.NodeAddress{Address: kaddr.Address, Type: libapiv3.InternalIP})
		case kapiv1.NodeExternalIP:
			calicoNode.Spec.Addresses = append(calicoNode.Spec.Addresses, libapiv3.NodeAddress{Address: kaddr.Address, Type: libapiv3.ExternalIP})
		default:
			continue
		}
	}
}

// mergeCalicoNodeIntoK8sNode takes a k8s node and a Calico node and puts the values from the Calico
// node into the k8s node.
func mergeCalicoNodeIntoK8sNode(calicoNode *libapiv3.Node, k8sNode *kapiv1.Node) (*kapiv1.Node, error) {
	// Nodes inherit labels from Kubernetes, but we also have our own set of labels that are stored in an annotation.
	// For nodes that are being updated, we want to avoid writing k8s labels that we inherited into our annotation
	// and we don't want to touch the k8s labels directly.  Take a copy of the node resource and update its labels
	// to match what we want to store in our annotation only.
	calicoNode, err := restoreCalicoLabels(calicoNode)
	if err != nil {
		return nil, err
	}

	// Set the k8s annotations from the Calico node metadata.
	SetK8sAnnotationsFromCalicoMetadata(k8sNode, calicoNode)

	// Handle IPv4 VXLAN address.
	if calicoNode.Spec.IPv4VXLANTunnelAddr != "" {
		k8sNode.Annotations[nodeBgpIpv4VXLANTunnelAddrAnnotation] = calicoNode.Spec.IPv4VXLANTunnelAddr
	} else {
		delete(k8sNode.Annotations, nodeBgpIpv4VXLANTunnelAddrAnnotation)
	}

	// Handle IPv4 VXLAN MAC address.
	if calicoNode.Spec.VXLANTunnelMACAddr != "" {
		k8sNode.Annotations[nodeBgpVXLANTunnelMACAddrAnnotation] = calicoNode.Spec.VXLANTunnelMACAddr
	} else {
		delete(k8sNode.Annotations, nodeBgpVXLANTunnelMACAddrAnnotation)
	}

	// Handle IPv6 VXLAN address.
	if calicoNode.Spec.IPv6VXLANTunnelAddr != "" {
		k8sNode.Annotations[nodeBgpIpv6VXLANTunnelAddrAnnotation] = calicoNode.Spec.IPv6VXLANTunnelAddr
	} else {
		delete(k8sNode.Annotations, nodeBgpIpv6VXLANTunnelAddrAnnotation)
	}

	// Handle IPv6 VXLAN MAC address.
	if calicoNode.Spec.VXLANTunnelMACAddrV6 != "" {
		k8sNode.Annotations[nodeBgpVXLANTunnelMACAddrV6Annotation] = calicoNode.Spec.VXLANTunnelMACAddrV6
	} else {
		delete(k8sNode.Annotations, nodeBgpVXLANTunnelMACAddrV6Annotation)
	}

	if calicoNode.Spec.BGP == nil {
		// If it is a empty NodeBGPSpec, remove all annotations.
		delete(k8sNode.Annotations, nodeBgpIpv4AddrAnnotation)
		delete(k8sNode.Annotations, nodeBgpIpv4IPIPTunnelAddrAnnotation)
		delete(k8sNode.Annotations, nodeBgpIpv6AddrAnnotation)
		delete(k8sNode.Annotations, nodeBgpAsnAnnotation)
		delete(k8sNode.Annotations, nodeBgpCIDAnnotation)
	} else {
		// If the BGP spec is not nil, then handle each field within the BGP spec individually.
		if calicoNode.Spec.BGP.IPv4Address != "" {
			k8sNode.Annotations[nodeBgpIpv4AddrAnnotation] = calicoNode.Spec.BGP.IPv4Address
		} else {
			delete(k8sNode.Annotations, nodeBgpIpv4AddrAnnotation)
		}

		if calicoNode.Spec.BGP.IPv4IPIPTunnelAddr != "" {
			k8sNode.Annotations[nodeBgpIpv4IPIPTunnelAddrAnnotation] = calicoNode.Spec.BGP.IPv4IPIPTunnelAddr
		} else {
			delete(k8sNode.Annotations, nodeBgpIpv4IPIPTunnelAddrAnnotation)
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
	}

	if calicoNode.Spec.Wireguard == nil {
		delete(k8sNode.Annotations, nodeWireguardIpv4IfaceAddrAnnotation)
		delete(k8sNode.Annotations, nodeWireguardIpv6IfaceAddrAnnotation)
	} else {
		// Handle Wireguard interface address.
		if calicoNode.Spec.Wireguard.InterfaceIPv4Address != "" {
			k8sNode.Annotations[nodeWireguardIpv4IfaceAddrAnnotation] = calicoNode.Spec.Wireguard.InterfaceIPv4Address
		} else {
			delete(k8sNode.Annotations, nodeWireguardIpv4IfaceAddrAnnotation)
		}
		if calicoNode.Spec.Wireguard.InterfaceIPv6Address != "" {
			k8sNode.Annotations[nodeWireguardIpv6IfaceAddrAnnotation] = calicoNode.Spec.Wireguard.InterfaceIPv6Address
		} else {
			delete(k8sNode.Annotations, nodeWireguardIpv6IfaceAddrAnnotation)
		}
	}

	// Handle Wireguard public-key.
	if calicoNode.Status.WireguardPublicKey != "" {
		k8sNode.Annotations[nodeWireguardPublicKeyAnnotation] = calicoNode.Status.WireguardPublicKey
	} else {
		delete(k8sNode.Annotations, nodeWireguardPublicKeyAnnotation)
	}
	if calicoNode.Status.WireguardPublicKeyV6 != "" {
		k8sNode.Annotations[nodeWireguardPublicKeyV6Annotation] = calicoNode.Status.WireguardPublicKeyV6
	} else {
		delete(k8sNode.Annotations, nodeWireguardPublicKeyV6Annotation)
	}

	return k8sNode, nil
}

// mergeCalicoAndK8sLabels merges the Kubernetes labels (from k8sNode.Labels) with those that are already present in
// calicoNode (which were loaded from our annotation).  Kubernetes labels take precedence.  To make the operation
// reversible (so that we can support write back of a Calico node that was read from Kubernetes), we also store the
// complete set of Kubernetes labels in an annotation.
//
// Note: if a Kubernetes label shadows a Calico label, the Calico label will be lost when the resource is written
// back to the datastore.  This is consistent with kube-controllers' behavior.
func mergeCalicoAndK8sLabels(calicoNode *libapiv3.Node, k8sNode *kapiv1.Node) error {
	// Now, copy the Kubernetes Node labels over.  Note: this may overwrite Calico labels of the same name, but that's
	// consistent with the kube-controllers behavior.
	for k, v := range k8sNode.Labels {
		if calicoNode.Labels == nil {
			calicoNode.Labels = map[string]string{}
		}
		calicoNode.Labels[k] = v
	}

	// For consistency with kube-controllers, and so we can correctly round-trip labels, we stash the kubernetes labels
	// in an annotation.
	if calicoNode.Annotations == nil {
		calicoNode.Annotations = map[string]string{}
	}
	bytes, err := json.Marshal(k8sNode.Labels)
	if err != nil {
		log.WithError(err).Errorf("Error marshalling node labels")
		return err
	}
	calicoNode.Annotations[nodeK8sLabelAnnotation] = string(bytes)
	return nil
}

// restoreCalicoLabels tries to undo the transformation done by mergeCalicoLabels.  If no changes are needed, it
// returns the input value; otherwise, it returns a copy.
func restoreCalicoLabels(calicoNode *libapiv3.Node) (*libapiv3.Node, error) {
	rawLabels := calicoNode.Annotations[nodeK8sLabelAnnotation]
	if rawLabels == "" {
		return calicoNode, nil
	}

	// We're about to update the labels and annotations on the node, take a copy.
	calicoNode = calicoNode.DeepCopy()

	// We stashed the k8s labels in an annotation, extract them so we can compare with the combined labels.
	k8sLabels := map[string]string{}
	if err := json.Unmarshal([]byte(rawLabels), &k8sLabels); err != nil {
		log.WithError(err).Error("Failed to unmarshal k8s node labels from " +
			nodeK8sLabelAnnotation + " annotation")
		return nil, err
	}

	// Now remove any labels that match the k8s ones.
	if log.GetLevel() >= log.DebugLevel {
		log.WithField("k8s", k8sLabels).Debug("Loaded label annotations")
	}
	for k, k8sVal := range k8sLabels {
		if calVal, ok := calicoNode.Labels[k]; ok && calVal != k8sVal {
			log.WithFields(log.Fields{
				"label":    k,
				"newValue": calVal,
				"k8sValue": k8sVal,
			}).Warn("Update to label that is shadowed by a Kubernetes label will be ignored.")
		}

		// The k8s value was inherited and there was no old Calico value, drop the label so that we don't copy
		// it to the Calico annotation.
		if log.GetLevel() >= log.DebugLevel {
			log.WithField("key", k).Debug("Removing inherited k8s label")
		}
		delete(calicoNode.Labels, k)
	}

	// Filter out our bookkeeping annotation, which is only used for round-tripping labels correctly.
	delete(calicoNode.Annotations, nodeK8sLabelAnnotation)
	if len(calicoNode.Annotations) == 0 {
		calicoNode.Annotations = nil
	}

	return calicoNode, nil
}

// getStaticTunnelAddress calculates the IPv4 address to use for the IPIP tunnel and wireguard tunnel based on the
// node's pod CIDR, for use in conjunction with host-local IPAM backed by node.Spec.PodCIDR allocations.
func getStaticTunnelAddress(n *kapiv1.Node) (string, error) {
	ip, _, err := net.ParseCIDR(n.Spec.PodCIDR)
	if err != nil {
		log.Warnf("Invalid pod CIDR for node: %s, %s", n.Name, n.Spec.PodCIDR)
		return "", err
	}

	// We need to get the IP for the podCIDR and increment it to the
	// first IP in the CIDR.
	tunIp := ip.To4()
	if tunIp == nil {
		log.WithField("podCIDR", n.Spec.PodCIDR).Infof("Cannot pick an IPv4 tunnel address from the given CIDR")
		return "", nil
	}
	tunIp[3]++

	return tunIp.String(), nil
}

// getAnnotation reads the annotation from node object, runs the value through the validator function
// and returns it if the validation passes, else returns "".
func getAnnotation(n *kapiv1.Node, key string, validator validatorFunc) string {
	value := n.ObjectMeta.Annotations[key]
	if value == "" {
		return ""
	}
	err := validator(value)
	if err != nil {
		log.WithError(err).Infof("Annotation %s=%s is invalid, ignoring it.", key, value)
		return ""
	}
	return value
}
