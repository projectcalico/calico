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
	"context"

	log "github.com/sirupsen/logrus"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	nodeBgpIpv4AddrAnnotation = "projectcalico.org/IPv4Address"
	nodeBgpIpv6AddrAnnotation = "projectcalico.org/IPv6Address"
	nodeBgpAsnAnnotation      = "projectcalico.org/ASNumber"
	nodeIpInIpTunnelAddr      = "projectcalico.org/IpInIpTunnelAddr"
)

func NewNodeClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &retryWrapper{
		client: &nodeClient{
			clientSet: c,
		},
	}
}

// Implements the api.Client interface for Nodes.
type nodeClient struct {
	clientSet *kubernetes.Clientset
}

func (c *nodeClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, errors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *nodeClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	// Get a current copy of the node to fill in fields we don't track.
	oldNode, err := c.clientSet.CoreV1().Nodes().Get(kvp.Key.(model.ResourceKey).Name, metav1.GetOptions{})
	if err != nil {
		return nil, K8sErrorToCalico(err, kvp.Key)
	}

	node, err := mergeCalicoK8sNode(kvp.Value.(*apiv2.Node), oldNode)
	if err != nil {
		return nil, err
	}

	newNode, err := c.clientSet.CoreV1().Nodes().Update(node)
	if err != nil {
		log.WithError(err).Info("Error updating Node resource")
		err = K8sErrorToCalico(err, kvp.Key)

		// If this is an update conflict and we didn't specify a revision in the
		// request, indicate to the nodeRetryWrapper that we can retry the action.
		if _, ok := err.(errors.ErrorResourceUpdateConflict); ok && len(kvp.Revision) == 0 {
			err = retryError{err: err}
		}
		return nil, err
	}

	newCalicoNode, err := K8sNodeToCalico(newNode)
	if err != nil {
		log.Errorf("Failed to parse returned Node after call to update %+v", newNode)
		return nil, err
	}

	return newCalicoNode, nil
}

func (c *nodeClient) Apply(kvp *model.KVPair) (*model.KVPair, error) {
	node, err := c.Update(context.Background(), kvp)
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			return nil, err
		}
		log.WithField("node", kvp.Key.(model.NodeKey).Hostname).Warn("Node does not exist")

		// Create is not currently implemented, and probably will not be, but will throw an appropriate error
		// for the user, along with the above warning.
		return c.Create(context.Background(), kvp)
	}
	return node, nil
}

func (c *nodeClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on Node type")
	return nil, errors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *nodeClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on Node type")
	node, err := c.clientSet.CoreV1().Nodes().Get(key.(model.ResourceKey).Name, metav1.GetOptions{})
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}

	kvp, err := K8sNodeToCalico(node)
	if err != nil {
		log.Panicf("%s", err)
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
		kvp, err := c.Get(ctx, model.ResourceKey{Name: nl.Name, Kind: apiv2.KindNode}, revision)
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
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

	// Listing all nodes.
	nodes, err := c.clientSet.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		K8sErrorToCalico(err, list)
	}

	for _, node := range nodes.Items {
		n, err := K8sNodeToCalico(&node)
		if err != nil {
			log.Panicf("%s", err)
		}
		kvps = append(kvps, n)
	}

	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: revision,
	}, nil
}

func (c *nodeClient) EnsureInitialized() error {
	return nil
}
