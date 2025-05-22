// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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

package crdv3

import (
	"context"
	"fmt"
	"reflect"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Import all auth providers.
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	adminpolicyclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/typed/apis/v1alpha1"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var (
	resourceKeyType  = reflect.TypeOf(model.ResourceKey{})
	resourceListType = reflect.TypeOf(model.ResourceListOptions{})
)

type Client struct {
	// Contains methods for converting Kubernetes resources to
	// Calico resources.
	converter conversion.Converter

	// Resource clients keyed off Kind.
	clientsByResourceKind map[string]resources.K8sResourceClient

	// Non v3 resource clients keyed off Key Type.
	clientsByKeyType map[reflect.Type]resources.K8sResourceClient

	// Non v3 resource clients keyed off List Type.
	clientsByListType map[reflect.Type]resources.K8sResourceClient
}

func NewClient(ca *apiconfig.CalicoAPIConfigSpec) (api.Client, error) {
	// Create a controller-runtime client for interacting with Calico CRDs.
	config, err := restConfig(ca)
	if err != nil {
		return nil, err
	}

	// Register v3 resource types with the scheme.
	v3.AddToScheme(scheme.Scheme)

	// Create a generic client for projectcalico.org/v3 CRDs.
	cli, err := ctrlclient.New(config, ctrlclient.Options{})
	if err != nil {
		return nil, err
	}
	genericClient := NewCRDClient(cli)

	// Create a clientset for sub-clients that need it.
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, nil)
	}

	// And a REST client.
	rest, err := v3RESTClient(config)
	if err != nil {
		return nil, err
	}

	// Create a client for AdminNetworkPolicy.
	k8sAdminPolicyClient, err := buildK8SAdminPolicyClient(config)
	if err != nil {
		return nil, fmt.Errorf("Failed to build AdminNetworkPolicy client: %v", err)
	}

	c := &Client{
		clientsByResourceKind: make(map[string]resources.K8sResourceClient),
		clientsByKeyType:      make(map[reflect.Type]resources.K8sResourceClient),
		clientsByListType:     make(map[reflect.Type]resources.K8sResourceClient),
	}

	// These resources are implemented directly with CRDs, and the objects that we receive
	// in this client can be used as-is on the Kubernetes API.
	crdKinds := []string{
		apiv3.KindIPPool,
		apiv3.KindIPReservation,
		apiv3.KindGlobalNetworkPolicy,
		apiv3.KindStagedGlobalNetworkPolicy,
		apiv3.KindGlobalNetworkSet,
		apiv3.KindNetworkPolicy,
		apiv3.KindStagedNetworkPolicy,
		apiv3.KindStagedKubernetesNetworkPolicy,
		apiv3.KindNetworkSet,
		apiv3.KindTier,
		apiv3.KindBGPPeer,
		apiv3.KindBGPConfiguration,
		apiv3.KindFelixConfiguration,
		apiv3.KindClusterInformation,
		apiv3.KindHostEndpoint,
		apiv3.KindKubeControllersConfiguration,
		apiv3.KindCalicoNodeStatus,
	}
	for _, kind := range crdKinds {
		c.registerResourceClient(
			reflect.TypeOf(model.ResourceKey{}),
			reflect.TypeOf(model.ResourceListOptions{}),
			kind,
			genericClient,
		)
	}

	// These kinds are backed by Kubernetes objects, so need dedicated clients to implement them.
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		model.KindKubernetesAdminNetworkPolicy,
		resources.NewKubernetesAdminNetworkPolicyClient(k8sAdminPolicyClient),
	)
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		model.KindKubernetesBaselineAdminNetworkPolicy,
		resources.NewKubernetesBaselineAdminNetworkPolicyClient(k8sAdminPolicyClient),
	)
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		model.KindKubernetesNetworkPolicy,
		resources.NewKubernetesNetworkPolicyClient(cs),
	)
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		model.KindKubernetesEndpointSlice,
		resources.NewKubernetesEndpointSliceClient(cs),
	)
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		model.KindKubernetesService,
		resources.NewServiceClient(cs),
	)

	// These are Calico kinds that are backed by Kubernetes objects, and so need dedicated clients.
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		libapiv3.KindNode,
		resources.NewNodeClient(cs, ca.K8sUsePodCIDR),
	)
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv3.KindProfile,
		resources.NewProfileClient(cs),
	)
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		libapiv3.KindWorkloadEndpoint,
		resources.NewWorkloadEndpointClient(cs),
	)

	// These are Calico objects that need special manipulation - e.g., because we don't receive
	// v3 compatible objects on the backend API, and so need translation into CRD format with dedicated
	// sub-client logic.
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		libapiv3.KindIPAMConfig,
		genericClient,
	)
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		libapiv3.KindBlockAffinity,
		genericClient,
	)
	c.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv3.KindBGPFilter,
		genericClient,
	)

	if !ca.K8sUsePodCIDR {
		// Using Calico IPAM - use CRDs to back IPAM resources.
		log.Debug("Calico is configured to use calico-ipam")
		c.registerResourceClient(
			reflect.TypeOf(model.BlockAffinityKey{}),
			reflect.TypeOf(model.BlockAffinityListOptions{}),
			libapiv3.KindBlockAffinity,
			resources.NewBlockAffinityClient(cs, rest),
		)
		c.registerResourceClient(
			reflect.TypeOf(model.BlockKey{}),
			reflect.TypeOf(model.BlockListOptions{}),
			libapiv3.KindIPAMBlock,
			resources.NewIPAMBlockClient(cs, rest),
		)
		c.registerResourceClient(
			reflect.TypeOf(model.IPAMHandleKey{}),
			reflect.TypeOf(model.IPAMHandleListOptions{}),
			libapiv3.KindIPAMHandle,
			resources.NewIPAMHandleClient(cs, rest),
		)
		c.registerResourceClient(
			reflect.TypeOf(model.IPAMConfigKey{}),
			nil,
			libapiv3.KindIPAMConfig,
			resources.NewIPAMConfigClient(cs, rest),
		)
	}

	return c, nil
}

// registerResourceClient registers a specific resource client with the associated
// key and list types (and for v3 resources with the resource kind - since these share
// a common key and list type).
func (c *Client) registerResourceClient(keyType, listType reflect.Type, resourceKind string, client resources.K8sResourceClient) {
	if keyType == resourceKeyType {
		c.clientsByResourceKind[resourceKind] = client
	} else {
		c.clientsByKeyType[keyType] = client
		c.clientsByListType[listType] = client
	}
}

// getResourceClientFromKey returns the appropriate resource client for the v3 resource kind.
func (c *Client) GetResourceClientFromResourceKind(kind string) resources.K8sResourceClient {
	return c.clientsByResourceKind[kind]
}

// getResourceClientFromKey returns the appropriate resource client for the key.
func (c *Client) getResourceClientFromKey(key model.Key) resources.K8sResourceClient {
	kt := reflect.TypeOf(key)
	if kt == resourceKeyType {
		return c.clientsByResourceKind[key.(model.ResourceKey).Kind]
	} else {
		return c.clientsByKeyType[kt]
	}
}

// getResourceClientFromList returns the appropriate resource client for the list.
func (c *Client) getResourceClientFromList(list model.ListInterface) resources.K8sResourceClient {
	lt := reflect.TypeOf(list)
	if lt == resourceListType {
		return c.clientsByResourceKind[list.(model.ResourceListOptions).Kind]
	} else {
		return c.clientsByListType[lt]
	}
}

// EnsureInitialized checks that the necessary custom resource definitions
// exist in the backend. This usually passes when using etcd
// as a backend but can often fail when using KDD as it relies
// on various custom resources existing.
// To ensure the datastore is initialized, this function checks that a
// known custom resource is defined: GlobalFelixConfig. It accomplishes this
// by trying to set the ClusterType (an instance of GlobalFelixConfig).
func (c *Client) EnsureInitialized() error {
	return nil
}

// Remove Calico-creatable data from the datastore.  This is purely used for the
// test framework.
func (c *Client) Clean() error {
	log.Warning("Cleaning all Calico v3 CRDs")
	kinds := []string{
		apiv3.KindBGPConfiguration,
		apiv3.KindBGPPeer,
		apiv3.KindClusterInformation,
		apiv3.KindCalicoNodeStatus,
		apiv3.KindFelixConfiguration,
		apiv3.KindGlobalNetworkPolicy,
		apiv3.KindStagedGlobalNetworkPolicy,
		apiv3.KindNetworkPolicy,
		apiv3.KindStagedNetworkPolicy,
		apiv3.KindStagedKubernetesNetworkPolicy,
		apiv3.KindTier,
		apiv3.KindGlobalNetworkSet,
		apiv3.KindNetworkSet,
		apiv3.KindIPPool,
		apiv3.KindIPReservation,
		apiv3.KindHostEndpoint,
		apiv3.KindKubeControllersConfiguration,
		libapiv3.KindIPAMConfig,
		libapiv3.KindBlockAffinity,
		apiv3.KindBGPFilter,
	}
	ctx := context.Background()
	for _, k := range kinds {
		lo := model.ResourceListOptions{Kind: k}
		if rs, err := c.List(ctx, lo, ""); err != nil {
			log.WithError(err).WithField("Kind", k).Warning("Failed to list resources")
		} else {
			for _, r := range rs.KVPairs {
				if _, err = c.Delete(ctx, r.Key, r.Revision); err != nil {
					log.WithField("Key", r.Key).Warning("Failed to delete entry from KDD")
				}
			}
		}
	}

	// Cleanup IPAM resources that have slightly different backend semantics.
	for _, li := range []model.ListInterface{
		model.BlockListOptions{},
		model.BlockAffinityListOptions{},
		model.BlockAffinityListOptions{},
		model.IPAMHandleListOptions{},
	} {
		if rs, err := c.List(ctx, li, ""); err != nil {
			log.WithError(err).WithField("Kind", li).Warning("Failed to list resources")
		} else {
			for _, r := range rs.KVPairs {
				if _, err = c.DeleteKVP(ctx, r); err != nil {
					log.WithError(err).WithField("Key", r.Key).Warning("Failed to delete entry from KDD")
				}
			}
		}
	}

	// Get a list of Nodes and remove all BGP configuration from the nodes.
	if nodes, err := c.List(ctx, model.ResourceListOptions{Kind: libapiv3.KindNode}, ""); err != nil {
		log.Warning("Failed to list Nodes")
	} else {
		for _, nodeKvp := range nodes.KVPairs {
			node := nodeKvp.Value.(*libapiv3.Node)
			node.Spec.BGP = nil
			if _, err := c.Update(ctx, nodeKvp); err != nil {
				log.WithField("Node", node.Name).Warning("Failed to remove Calico config from node")
			}
		}
	}

	// Delete global IPAM config
	if _, err := c.Delete(ctx, model.IPAMConfigKey{}, ""); err != nil {
		log.WithError(err).WithField("key", model.IPAMConfigGlobalName).Warning("Failed to delete global IPAM Config from KDD")
	}
	return nil
}

// Close the underlying client
func (c *Client) Close() error {
	log.Debugf("Closing client - NOOP")
	return nil
}

// buildK8SAdminPolicyClient builds a RESTClient configured to interact (Baseline) Admin Network Policy.
func buildK8SAdminPolicyClient(cfg *rest.Config) (*adminpolicyclient.PolicyV1alpha1Client, error) {
	return adminpolicyclient.NewForConfig(cfg)
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *Client) Create(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	log.Debugf("Performing 'Create' for %+v", d)
	client := c.getResourceClientFromKey(d.Key)
	if client == nil {
		log.Debug("Attempt to 'Create' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: d.Key,
			Operation:  "Create",
		}
	}
	return client.Create(ctx, d)
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist.
func (c *Client) Update(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	log.Debugf("Performing 'Update' for %+v", d)
	client := c.getResourceClientFromKey(d.Key)
	if client == nil {
		log.Debug("Attempt to 'Update' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: d.Key,
			Operation:  "Update",
		}
	}
	return client.Update(ctx, d)
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.  This is not exposed in the main client - but we keep here for the backend
// API.
func (c *Client) Apply(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	logContext := log.WithFields(log.Fields{
		"Key":   kvp.Key,
		"Value": kvp.Value,
	})
	logContext.Debug("Apply Kubernetes resource")

	// Attempt to Create and do an Update if the resource already exists.
	// We only log debug here since the Create and Update will also log.
	// Can't set Revision while creating a resource.
	updated, err := c.Create(ctx, &model.KVPair{
		Key:   kvp.Key,
		Value: kvp.Value,
	})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
			logContext.Debug("Error applying resource (using Create)")
			return nil, err
		}

		// Try to Update if the resource already exists.
		updated, err = c.Update(ctx, kvp)
		if err != nil {
			logContext.Debug("Error applying resource (using Update)")
			return nil, err
		}
	}
	return updated, nil
}

// Delete an entry in the datastore.
func (c *Client) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debugf("Performing 'DeleteKVP' for %+v", kvp.Key)
	client := c.getResourceClientFromKey(kvp.Key)
	if client == nil {
		log.Debug("Attempt to 'DeleteKVP' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: kvp.Key,
			Operation:  "Delete",
		}
	}
	return client.DeleteKVP(ctx, kvp)
}

// Delete an entry in the datastore by key.
func (c *Client) Delete(ctx context.Context, k model.Key, revision string) (*model.KVPair, error) {
	log.Debugf("Performing 'Delete' for %+v", k)
	client := c.getResourceClientFromKey(k)
	if client == nil {
		log.Debug("Attempt to 'Delete' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: k,
			Operation:  "Delete",
		}
	}
	return client.Delete(ctx, k, revision, nil)
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *Client) Get(ctx context.Context, k model.Key, revision string) (*model.KVPair, error) {
	log.Debugf("Performing 'Get' for %+v %v", k, revision)
	client := c.getResourceClientFromKey(k)
	if client == nil {
		log.Debug("Attempt to 'Get' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: k,
			Operation:  "Get",
		}
	}
	return client.Get(ctx, k, revision)
}

// List entries in the datastore.  This may return an empty list if there are
// no entries matching the request in the ListInterface.
func (c *Client) List(ctx context.Context, l model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debugf("Performing 'List' for %+v %v", l, reflect.TypeOf(l))
	client := c.getResourceClientFromList(l)
	if client == nil {
		log.Info("Attempt to 'List' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: l,
			Operation:  "List",
		}
	}
	return client.List(ctx, l, revision)
}

// Watch starts a watch on a particular resource type.
func (c *Client) Watch(ctx context.Context, l model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	log.Debugf("Performing 'Watch' for %+v %v", l, reflect.TypeOf(l))
	client := c.getResourceClientFromList(l)
	if client == nil {
		log.Debug("Attempt to 'Watch' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: l,
			Operation:  "Watch",
		}
	}
	return client.Watch(ctx, l, options)
}
