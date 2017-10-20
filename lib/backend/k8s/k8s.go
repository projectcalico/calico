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

package k8s

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	_ "k8s.io/client-go/plugin/pkg/client/auth" // Import all auth providers.

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	resourceKeyType  = reflect.TypeOf(model.ResourceKey{})
	resourceListType = reflect.TypeOf(model.ResourceListOptions{})
)

type KubeClient struct {
	// Main Kubernetes clients.
	clientSet *kubernetes.Clientset

	// Client for interacting with CustomResourceDefinition.
	crdClientV1 *rest.RESTClient

	disableNodePoll bool

	// Contains methods for converting Kubernetes resources to
	// Calico resources.
	converter conversion.Converter

	// Resource clients keyed off Kind.
	clientsByResourceKind map[string]resources.K8sResourceClient

	// Non v2 resource clients keyed off Key Type.
	clientsByKeyType map[reflect.Type]resources.K8sResourceClient

	// Non v2 resource clients keyed off List Type.
	clientsByListType map[reflect.Type]resources.K8sResourceClient
}

func NewKubeClient(kc *apiconfig.KubeConfig) (api.Client, error) {
	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	log.Debugf("Building client for config: %+v", kc)
	configOverrides := &clientcmd.ConfigOverrides{}
	var overridesMap = []struct {
		variable *string
		value    string
	}{
		{&configOverrides.ClusterInfo.Server, kc.K8sAPIEndpoint},
		{&configOverrides.AuthInfo.ClientCertificate, kc.K8sCertFile},
		{&configOverrides.AuthInfo.ClientKey, kc.K8sKeyFile},
		{&configOverrides.ClusterInfo.CertificateAuthority, kc.K8sCAFile},
		{&configOverrides.AuthInfo.Token, kc.K8sAPIToken},
	}

	// Set an explicit path to the kubeconfig if one
	// was provided.
	loadingRules := clientcmd.ClientConfigLoadingRules{}
	if kc.Kubeconfig != "" {
		loadingRules.ExplicitPath = kc.Kubeconfig
	}

	// Using the override map above, populate any non-empty values.
	for _, override := range overridesMap {
		if override.value != "" {
			*override.variable = override.value
		}
	}
	if kc.K8sInsecureSkipTLSVerify {
		configOverrides.ClusterInfo.InsecureSkipTLSVerify = true
	}
	log.Debugf("Config overrides: %+v", configOverrides)

	// A kubeconfig file was provided.  Use it to load a config, passing through
	// any overrides.
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&loadingRules, configOverrides).ClientConfig()
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, nil)
	}

	// Create the clientset
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, nil)
	}
	log.Debugf("Created k8s clientSet: %+v", cs)

	crdClientV1, err := buildCRDClientV1(*config)
	if err != nil {
		return nil, fmt.Errorf("Failed to build V1 CRD client: %s", err)
	}

	kubeClient := &KubeClient{
		clientSet:             cs,
		crdClientV1:           crdClientV1,
		disableNodePoll:       kc.K8sDisableNodePoll,
		clientsByResourceKind: make(map[string]resources.K8sResourceClient),
		clientsByKeyType:      make(map[reflect.Type]resources.K8sResourceClient),
		clientsByListType:     make(map[reflect.Type]resources.K8sResourceClient),
	}

	// Create the Calico sub-clients and register them.
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindIPPool,
		resources.NewIPPoolClient(cs, crdClientV1),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindGlobalNetworkPolicy,
		resources.NewGlobalNetworkPolicyClient(cs, crdClientV1),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindNetworkPolicy,
		resources.NewNetworkPolicyClient(cs, crdClientV1),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindBGPPeer,
		resources.NewBGPPeerClient(cs, crdClientV1),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindBGPConfiguration,
		resources.NewBGPConfigClient(cs, crdClientV1),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindFelixConfiguration,
		resources.NewFelixConfigClient(cs, crdClientV1),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindClusterInformation,
		resources.NewClusterInfoClient(cs, crdClientV1),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindNode,
		resources.NewNodeClient(cs),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindProfile,
		resources.NewProfileClient(cs),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.ResourceKey{}),
		reflect.TypeOf(model.ResourceListOptions{}),
		apiv2.KindWorkloadEndpoint,
		resources.NewWorkloadEndpointClient(cs),
	)
	kubeClient.registerResourceClient(
		reflect.TypeOf(model.BlockAffinityKey{}),
		reflect.TypeOf(model.BlockAffinityListOptions{}),
		"",
		resources.NewAffinityBlockClient(cs),
	)

	return kubeClient, nil
}

// registerResourceClient registers a specific resource client with the associated
// key and list types (and for v2 resources with the resource kind - since these share
// a common key and list type).
func (c *KubeClient) registerResourceClient(keyType, listType reflect.Type, resourceKind string, client resources.K8sResourceClient) {
	if keyType == resourceKeyType {
		c.clientsByResourceKind[resourceKind] = client
	} else {
		c.clientsByKeyType[keyType] = client
		c.clientsByListType[listType] = client
	}
}

// getResourceClientFromKey returns the appropriate resource client for the v2 resource kind.
func (c *KubeClient) getResourceClientFromResourceKind(kind string) resources.K8sResourceClient {
	return c.clientsByResourceKind[kind]
}

// getResourceClientFromKey returns the appropriate resource client for the key.
func (c *KubeClient) getResourceClientFromKey(key model.Key) resources.K8sResourceClient {
	kt := reflect.TypeOf(key)
	if kt == resourceKeyType {
		return c.clientsByResourceKind[key.(model.ResourceKey).Kind]
	} else {
		return c.clientsByKeyType[kt]
	}
}

// getResourceClientFromList returns the appropriate resource client for the list.
func (c *KubeClient) getResourceClientFromList(list model.ListInterface) resources.K8sResourceClient {
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
func (c *KubeClient) EnsureInitialized() error {
	log.Info("Ensuring datastore has been initialized.")
	err := c.waitForClusterType()
	if err != nil {
		return fmt.Errorf("Failed to ensure datastore has been initialized: \"%s\". Make sure the Custom Resource Definitions have been created and Calico has been authorized to access them.", err)
	}
	log.Info("Confirmed datastore has been initialized.")
	return nil
}

func (c *KubeClient) Clean() error {
	log.Warning("Cleaning KDD of all Calico-creatable data")
	kinds := []string{
		apiv2.KindBGPConfiguration,
		apiv2.KindBGPPeer,
		apiv2.KindClusterInformation,
		apiv2.KindFelixConfiguration,
		apiv2.KindGlobalNetworkPolicy,
		apiv2.KindIPPool,
	}
	ctx := context.Background()
	for _, k := range kinds {
		lo := model.ResourceListOptions{Kind: k}
		rs, _ := c.List(ctx, lo, "")
		for _, r := range rs.KVPairs {
			log.WithField("Key", r.Key).Info("Deleting from KDD")
			c.Delete(ctx, r.Key, r.Revision)
		}
	}
	return nil
}

// waitForClusterType polls until GlobalFelixConfig is ready, or until 30 seconds have passed.
func (c *KubeClient) waitForClusterType() error {
	return wait.PollImmediate(1*time.Second, 30*time.Second, func() (bool, error) {
		return c.ensureClusterType()
	})
}

// ensureClusterType ensures that the ClusterType is configured.
func (c *KubeClient) ensureClusterType() (bool, error) {
	k := model.GlobalConfigKey{
		Name: "ClusterType",
	}
	value := "KDD"

	// See if a cluster type has been set.  If so, append
	// any existing values to it.
	ct, err := c.Get(context.Background(), k, "")
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			// Resource exists but we got another error.
			return false, err
		}
		// Resource does not exist.
	}
	rv := ""
	if ct != nil {
		existingValue := ct.Value.(string)
		if !strings.Contains(existingValue, "KDD") {
			existingValue = fmt.Sprintf("%s,KDD", existingValue)
		}
		value = existingValue
		rv = ct.Revision
	}
	log.WithField("value", value).Debug("Setting ClusterType")
	_, err = c.Apply(&model.KVPair{
		Key:      k,
		Value:    value,
		Revision: rv,
	})
	if err != nil {
		// Don't return an error, but indicate that we need
		// to retry.
		log.Warnf("Failed to apply ClusterType: %s", err)
		return false, nil
	}
	return true, nil
}

// buildCRDClientV1 builds a RESTClient configured to interact with Calico CustomResourceDefinitions
func buildCRDClientV1(cfg rest.Config) (*rest.RESTClient, error) {
	// Generate config using the base config.
	cfg.GroupVersion = &schema.GroupVersion{
		Group:   "crd.projectcalico.org",
		Version: "v1",
	}
	cfg.APIPath = "/apis"
	cfg.ContentType = runtime.ContentTypeJSON
	cfg.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: scheme.Codecs}

	cli, err := rest.RESTClientFor(&cfg)
	if err != nil {
		return nil, err
	}

	// We also need to register resources.
	schemeBuilder := runtime.NewSchemeBuilder(
		func(scheme *runtime.Scheme) error {
			scheme.AddKnownTypes(
				*cfg.GroupVersion,
				&apiv2.FelixConfiguration{},
				&apiv2.FelixConfigurationList{},
				&apiv2.IPPool{},
				&apiv2.IPPoolList{},
				&apiv2.BGPPeer{},
				&apiv2.BGPPeerList{},
				&apiv2.BGPConfiguration{},
				&apiv2.BGPConfigurationList{},
				&apiv2.ClusterInformation{},
				&apiv2.ClusterInformationList{},
				&apiv2.GlobalNetworkPolicy{},
				&apiv2.GlobalNetworkPolicyList{},
				&apiv2.NetworkPolicy{},
				&apiv2.NetworkPolicyList{},
			)
			return nil
		})

	schemeBuilder.AddToScheme(scheme.Scheme)

	return cli, nil
}

func (c *KubeClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	// TODO: Fix this when we are done with the transition to v2 data model.
	// return newSyncer(&realKubeAPI{c}, c.converter, callbacks, c.disableNodePoll)
	return nil
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *KubeClient) Create(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
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
func (c *KubeClient) Update(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
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
func (c *KubeClient) Apply(kvp *model.KVPair) (*model.KVPair, error) {
	logContext := log.WithFields(log.Fields{
		"Key":   kvp.Key,
		"Value": kvp.Value,
	})
	logContext.Debug("Apply Kubernetes resource")

	// Attempt to Create and do an Update if the resource already exists.
	// We only log debug here since the Create and Update will also log.
	// Can't set Revision while creating a resource.
	updated, err := c.Create(context.Background(), &model.KVPair{
		Key:   kvp.Key,
		Value: kvp.Value,
	})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
			logContext.Debug("Error applying resource (using Create)")
			return nil, err
		}

		// Try to Update if the resource already exists.
		updated, err = c.Update(context.Background(), kvp)
		if err != nil {
			logContext.Debug("Error applying resource (using Update)")
			return nil, err
		}
	}
	return updated, nil
}

// Delete an entry in the datastore. This is a no-op when using the k8s backend.
func (c *KubeClient) Delete(ctx context.Context, k model.Key, revision string) (*model.KVPair, error) {
	log.Debugf("Performing 'Delete' for %+v", k)
	client := c.getResourceClientFromKey(k)
	if client == nil {
		log.Debug("Attempt to 'Delete' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: k,
			Operation:  "Delete",
		}
	}
	return client.Delete(ctx, k, revision)
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *KubeClient) Get(ctx context.Context, k model.Key, revision string) (*model.KVPair, error) {
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
func (c *KubeClient) List(ctx context.Context, l model.ListInterface, revision string) (*model.KVPairList, error) {
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

// List entries in the datastore.  This may return an empty list if there are
// no entries matching the request in the ListInterface.
func (c *KubeClient) Watch(ctx context.Context, l model.ListInterface, revision string) (api.WatchInterface, error) {
	log.Debugf("Performing 'Watch' for %+v %v", l, reflect.TypeOf(l))
	client := c.getResourceClientFromList(l)
	if client == nil {
		log.Debug("Attempt to 'Watch' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: l,
			Operation:  "Watch",
		}
	}
	return client.Watch(ctx, l, revision)
}

func (c *KubeClient) getReadyStatus(ctx context.Context, k model.ReadyFlagKey, revision string) (*model.KVPair, error) {
	return &model.KVPair{Key: k, Value: true}, nil
}

func (c *KubeClient) listHostConfig(ctx context.Context, l model.HostConfigListOptions, revision string) (*model.KVPairList, error) {
	var kvps = []*model.KVPair{}

	// Short circuit if they aren't asking for information we can provide.
	if l.Name != "" && l.Name != "IpInIpTunnelAddr" {
		return &model.KVPairList{
			KVPairs:  kvps,
			Revision: revision,
		}, nil
	}

	// First see if we were handed a specific host, if not list all Nodes
	if l.Hostname == "" {
		nodes, err := c.clientSet.CoreV1().Nodes().List(metav1.ListOptions{})
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, l)
		}

		for _, node := range nodes.Items {
			kvp, err := getTunIp(&node)
			if err != nil || kvp == nil {
				continue
			}

			kvps = append(kvps, kvp)
		}
	} else {
		node, err := c.clientSet.CoreV1().Nodes().Get(l.Hostname, metav1.GetOptions{})
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, l)
		}

		kvp, err := getTunIp(node)
		if err != nil || kvp == nil {
			return &model.KVPairList{
				KVPairs:  []*model.KVPair{},
				Revision: revision,
			}, nil
		}

		kvps = append(kvps, kvp)
	}

	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: revision,
	}, nil
}

func getTunIp(n *v1.Node) (*model.KVPair, error) {
	if n.Spec.PodCIDR == "" {
		log.Warnf("Node %s does not have podCIDR for HostConfig", n.Name)
		return nil, nil
	}

	ip, _, err := net.ParseCIDR(n.Spec.PodCIDR)
	if err != nil {
		log.Warnf("Invalid podCIDR for HostConfig: %s, %s", n.Name, n.Spec.PodCIDR)
		return nil, err
	}
	// We need to get the IP for the podCIDR and increment it to the
	// first IP in the CIDR.
	tunIp := ip.To4()
	tunIp[3]++

	kvp := &model.KVPair{
		Key: model.HostConfigKey{
			Hostname: n.Name,
			Name:     "IpInIpTunnelAddr",
		},
		Value: tunIp.String(),
	}

	return kvp, nil
}
