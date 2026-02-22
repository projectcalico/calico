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

package k8s

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Import all auth providers.
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	netpolicyclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/typed/apis/v1alpha2"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

var (
	resourceKeyType  = reflect.TypeFor[model.ResourceKey]()
	resourceListType = reflect.TypeFor[model.ResourceListOptions]()
)

type KubeClient struct {
	// Main Kubernetes clients.
	ClientSet *kubernetes.Clientset

	// Client for interacting with K8S Cluster Network Policy.
	k8sClusterPolicyClient *netpolicyclient.PolicyV1alpha2Client

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

func NewKubeClient(ca *apiconfig.CalicoAPIConfigSpec) (api.Client, error) {
	// Whether or not we are writing to projectcalico.org/v3 resources. If true, we're running in
	// "no API server" mode where the v3 resources are backed by CRDs directly. Otherwise, we're running
	// with the Calico API server and should instead use crd.projectcalico.org/v1 resources directly.
	group := BackendAPIGroup(ca)
	log.WithField("apiGroup", group).Info("Using API group for CRD backend")

	config, cs, err := CreateKubernetesClientset(ca)
	if err != nil {
		return nil, err
	}

	restClient, err := restClient(*config, group)
	if err != nil {
		return nil, fmt.Errorf("failed to build CRD client: %v", err)
	}

	cnpClient, err := clusterNetworkPolicyClient(config)
	if err != nil {
		return nil, fmt.Errorf("Failed to build ClusterNetworkPolicy client: %v", err)
	}

	c := &KubeClient{
		ClientSet:             cs,
		clientsByResourceKind: make(map[string]resources.K8sResourceClient),
		clientsByKeyType:      make(map[reflect.Type]resources.K8sResourceClient),
		clientsByListType:     make(map[reflect.Type]resources.K8sResourceClient),
	}

	// These resources are backed by Calico custom resource definitions (CRDs). Whether they are
	// backed by projectcalico.org/v3 or crd.projectcalico.org/v1 is configurable.
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindIPPool,
		resources.NewIPPoolClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindIPReservation,
		resources.NewIPReservationClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindGlobalNetworkPolicy,
		resources.NewGlobalNetworkPolicyClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindStagedGlobalNetworkPolicy,
		resources.NewStagedGlobalNetworkPolicyClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindGlobalNetworkSet,
		resources.NewGlobalNetworkSetClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindNetworkPolicy,
		resources.NewNetworkPolicyClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindStagedNetworkPolicy,
		resources.NewStagedNetworkPolicyClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindStagedKubernetesNetworkPolicy,
		resources.NewStagedKubernetesNetworkPolicyClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindNetworkSet,
		resources.NewNetworkSetClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindTier,
		resources.NewTierClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindBGPPeer,
		resources.NewBGPPeerClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindBGPConfiguration,
		resources.NewBGPConfigClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindFelixConfiguration,
		resources.NewFelixConfigClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindClusterInformation,
		resources.NewClusterInfoClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindHostEndpoint,
		resources.NewHostEndpointClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindKubeControllersConfiguration,
		resources.NewKubeControllersConfigClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindCalicoNodeStatus,
		resources.NewCalicoNodeStatusClient(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindBlockAffinity,
		resources.NewBlockAffinityClientV3(restClient, group),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindBGPFilter,
		resources.NewBGPFilterClient(restClient, group),
	)

	// IPAMConfig can come to us from two places:
	// - The lib/ipam code, which uses the older v1 API 'IPAMConfig'
	// - The lib/clientv3 code, which uses the newer v3 API 'IPAMConfiguration'
	// We always register the v3 client, but also register the v1 client for the
	// older IPAM code below if it's in use.
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindIPAMConfiguration,
		resources.NewIPAMConfigClientV3(restClient, group),
	)

	// These resources are backed directly by core Kubernetes APIs, and do not
	// use CRDs.
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		model.KindKubernetesService,
		resources.NewServiceClient(cs),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		model.KindKubernetesEndpointSlice,
		resources.NewKubernetesEndpointSliceClient(cs),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		internalapi.KindWorkloadEndpoint,
		resources.NewWorkloadEndpointClient(cs),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		internalapi.KindNode,
		resources.NewNodeClient(cs, ca.K8sUsePodCIDR),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		apiv3.KindProfile,
		resources.NewProfileClient(cs),
	)
	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		model.KindKubernetesNetworkPolicy,
		resources.NewKubernetesNetworkPolicyClient(cs),
	)

	c.registerResourceClient(
		reflect.TypeFor[model.ResourceKey](),
		reflect.TypeFor[model.ResourceListOptions](),
		model.KindKubernetesClusterNetworkPolicy,
		resources.NewKubernetesClusterNetworkPolicyClient(cnpClient),
	)

	if !ca.K8sUsePodCIDR {
		// Using Calico IPAM - use CRDs to back IPAM resources.
		log.Debug("Calico is configured to use calico-ipam")

		// lib/ipam uses different types for these resources, so register them separately
		// from the v3 resources already registered above.
		c.registerResourceClient(
			reflect.TypeFor[model.BlockAffinityKey](),
			reflect.TypeFor[model.BlockAffinityListOptions](),
			internalapi.KindBlockAffinity,
			resources.NewBlockAffinityClientV1(restClient, group),
		)
		c.registerResourceClient(
			reflect.TypeFor[model.IPAMConfigKey](),
			nil,
			internalapi.KindIPAMConfig,
			resources.NewIPAMConfigClientV1(restClient, group),
		)

		// These do not get registered as part of the v3 API, and are only
		// accessed from the lib/ipam code.
		c.registerResourceClient(
			reflect.TypeFor[model.BlockKey](),
			reflect.TypeFor[model.BlockListOptions](),
			internalapi.KindIPAMBlock,
			resources.NewIPAMBlockClient(restClient, group),
		)
		c.registerResourceClient(
			reflect.TypeFor[model.IPAMHandleKey](),
			reflect.TypeFor[model.IPAMHandleListOptions](),
			internalapi.KindIPAMHandle,
			resources.NewIPAMHandleClient(restClient, group),
		)
	}

	return c, nil
}

// deduplicate removes any duplicated values and returns a new slice, keeping the order unchanged
//
//	based on deduplicate([]string) []string found in k8s.io/client-go/tools/clientcmd/loader.go#634
//	Copyright 2014 The Kubernetes Authors.
func deduplicate(s []string) []string {
	encountered := map[string]struct{}{}
	ret := make([]string, 0)
	for i := range s {
		if _, ok := encountered[s[i]]; ok {
			continue
		}
		encountered[s[i]] = struct{}{}
		ret = append(ret, s[i])
	}
	return ret
}

// fill out loading rules based on filename(s) encountered in specified kubeconfig
func fillLoadingRulesFromKubeConfigSpec(loadingRules *clientcmd.ClientConfigLoadingRules, kubeConfig string) {
	fileList := filepath.SplitList(kubeConfig)

	if len(fileList) > 1 {
		loadingRules.Precedence = deduplicate(fileList)
		loadingRules.WarnIfAllMissing = true
		return
	}

	loadingRules.ExplicitPath = kubeConfig
}

func CreateKubernetesClientset(ca *apiconfig.CalicoAPIConfigSpec) (*rest.Config, *kubernetes.Clientset, error) {
	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	configOverrides := &clientcmd.ConfigOverrides{}
	overridesMap := []struct {
		variable *string
		value    string
	}{
		{&configOverrides.CurrentContext, ca.K8sCurrentContext},
		{&configOverrides.ClusterInfo.Server, ca.K8sAPIEndpoint},
		{&configOverrides.AuthInfo.ClientCertificate, ca.K8sCertFile},
		{&configOverrides.AuthInfo.ClientKey, ca.K8sKeyFile},
		{&configOverrides.ClusterInfo.CertificateAuthority, ca.K8sCAFile},
		{&configOverrides.AuthInfo.Token, ca.K8sAPIToken},
	}

	// Set an explicit path to the kubeconfig if one
	// was provided.
	loadingRules := clientcmd.ClientConfigLoadingRules{}
	if ca.Kubeconfig != "" {
		fillLoadingRulesFromKubeConfigSpec(&loadingRules, ca.Kubeconfig)
	}

	// Using the override map above, populate any non-empty values.
	for _, override := range overridesMap {
		if override.value != "" {
			*override.variable = override.value
		}
	}
	if ca.K8sInsecureSkipTLSVerify {
		configOverrides.ClusterInfo.InsecureSkipTLSVerify = true
	}

	// A kubeconfig file was provided.  Use it to load a config, passing through
	// any overrides.
	var config *rest.Config
	var err error
	if ca.KubeconfigInline != "" {
		var clientConfig clientcmd.ClientConfig
		clientConfig, err = clientcmd.NewClientConfigFromBytes([]byte(ca.KubeconfigInline))
		if err != nil {
			return nil, nil, resources.K8sErrorToCalico(err, nil)
		}
		config, err = clientConfig.ClientConfig()
	} else {
		config, err = winutils.NewNonInteractiveDeferredLoadingClientConfig(
			&loadingRules, configOverrides)
	}
	if err != nil {
		return nil, nil, resources.K8sErrorToCalico(err, nil)
	}

	config.AcceptContentTypes = strings.Join([]string{k8sruntime.ContentTypeProtobuf, k8sruntime.ContentTypeJSON}, ",")
	config.ContentType = k8sruntime.ContentTypeProtobuf

	// Overwrite the QPS if provided. Default QPS is 5.
	if ca.K8sClientQPS != float32(0) {
		config.QPS = ca.K8sClientQPS
	}

	// Create the clientset. We increase the burst so that the IPAM code performs
	// efficiently. The IPAM code can create bursts of requests to the API, so
	// in order to keep pod creation times sensible we allow a higher request rate.
	config.Burst = 100
	if ca.K8sClientBurst != 0 {
		config.Burst = ca.K8sClientBurst
	}
	log.Debugf("Kubernetes client QPS set to %v, burst set to %v", config.QPS, config.Burst)

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, resources.K8sErrorToCalico(err, nil)
	}
	return config, cs, nil
}

// registerResourceClient registers a specific resource client with the associated
// key and list types (and for v3 resources with the resource kind - since these share
// a common key and list type).
func (c *KubeClient) registerResourceClient(keyType, listType reflect.Type, resourceKind string, client resources.K8sResourceClient) {
	if keyType == resourceKeyType {
		c.clientsByResourceKind[resourceKind] = client
	} else {
		c.clientsByKeyType[keyType] = client
		c.clientsByListType[listType] = client
	}
}

// getResourceClientFromKey returns the appropriate resource client for the v3 resource kind.
func (c *KubeClient) GetResourceClientFromResourceKind(kind string) resources.K8sResourceClient {
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

func (c *KubeClient) EnsureInitialized() error {
	return nil
}

// Remove Calico-creatable data from the datastore.  This is purely used for the test framework.
func (c *KubeClient) Clean() error {
	timeout := 2 * time.Minute
	log.Warningf("Cleaning KDD of all Calico-creatable data: timeout %v", timeout)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// First delete "normal" resources by kind.
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
		apiv3.KindIPAMConfiguration,
		apiv3.KindBlockAffinity,
		apiv3.KindBGPFilter,
		internalapi.KindIPAMConfig,
	}

	// Deletion can fail due to CAS conflicts if multiple resources are
	// being deleted in parallel, so we do plenty of retries.
	kindsWithProblems := set.New[string]()
	var lock sync.Mutex
	for attempt := 1; attempt <= 20; attempt++ {
		recordKindProblem := func(k string) {
			lock.Lock()
			defer lock.Unlock()
			kindsWithProblems.Add(k)
		}

		// Need two layers of errgroup because we schedule deletion work from the
		// list go-routines.  If we scheduled it on the same errgroup then it could
		// deadlock.
		var listEG, delEG errgroup.Group
		listEG.SetLimit(runtime.NumCPU() / 2)
		delEG.SetLimit(runtime.NumCPU() / 2)

		for _, k := range kinds {
			listEG.Go(func() error {
				lo := model.ResourceListOptions{Kind: k}
				if rs, err := c.List(ctx, lo, ""); err != nil {
					log.WithError(err).WithField("Kind", k).Warning("Failed to list resources")
					recordKindProblem(k)
					return nil // Problems are reported through kindsWithProblems set.
				} else {
					for _, r := range rs.KVPairs {
						delEG.Go(func() error {
							if _, err := c.DeleteKVP(ctx, r); err != nil {
								log.WithError(err).WithField("Key", r.Key).Warning("Failed to delete entry from KDD")
								recordKindProblem(k)
							}
							return nil // Problems are reported through kindsWithProblems set.
						})
					}
				}
				return nil
			})
		}
		err := listEG.Wait()
		if err != nil {
			log.WithError(err).Error("Unexpected error during listing")
		}
		err = delEG.Wait()
		if err != nil {
			log.WithError(err).Error("Unexpected error from deletion errgroup")
		}

		if len(kindsWithProblems) == 0 {
			break
		}
		// Retry only the kinds that had problems on the next attempt.
		kinds = kindsWithProblems.Slice()
		kindsWithProblems.Clear()
	}
	if kindsWithProblems.Len() > 0 {
		log.WithField("kinds", kindsWithProblems).Error("Failed to delete all resources of these kinds")
	}

	// Delete IPAM resources using the older API, since they don't all support
	// the new.
	listIfaceProblems := set.New[model.ListInterface]()
	listIfaces := []model.ListInterface{
		model.BlockListOptions{},
		model.BlockAffinityListOptions{},
		model.IPAMHandleListOptions{},
	}
	for attempt := 1; attempt <= 20; attempt++ {
		recordLIProblem := func(l model.ListInterface) {
			lock.Lock()
			defer lock.Unlock()
			listIfaceProblems.Add(l)
		}

		// Need two layers of errgroup because we schedule deletion work from the
		// list go-routines.  If we scheduled it on the same errgroup then it could
		// deadlock.
		var listEG, delEG errgroup.Group
		listEG.SetLimit(runtime.NumCPU() / 2)
		delEG.SetLimit(runtime.NumCPU() / 2)

		for _, li := range listIfaces {
			listEG.Go(func() error {
				if rs, err := c.List(ctx, li, ""); err != nil {
					log.WithError(err).WithField("Kind", li).Warning("Failed to list resources")
					recordLIProblem(li)
				} else {
					for _, r := range rs.KVPairs {
						delEG.Go(func() error {
							if _, err = c.DeleteKVP(ctx, r); err != nil {
								log.WithError(err).WithField("Key", r.Key).Warning("Failed to delete entry from KDD")
								recordLIProblem(li)
							}
							return nil
						})
					}
				}
				return nil
			})
		}
		err := listEG.Wait()
		if err != nil {
			log.WithError(err).Error("Unexpected error during listing")
		}
		err = delEG.Wait()
		if err != nil {
			log.WithError(err).Error("Unexpected error from deletion errgroup")
		}

		if listIfaceProblems.Len() == 0 {
			break
		}
		// Retry only the list ifaces that had problems on the next attempt.
		listIfaces = listIfaceProblems.Slice()
		listIfaceProblems.Clear()
	}

	if listIfaceProblems.Len() > 0 {
		log.WithField("listInterfaces", listIfaceProblems).Error("Failed to delete all resources of these list interfaces")
	}

	// Get a list of Nodes and remove all BGP configuration from the nodes.
	if nodes, err := c.List(ctx, model.ResourceListOptions{Kind: internalapi.KindNode}, ""); err != nil {
		log.Warning("Failed to list Nodes")
	} else {
		for _, nodeKvp := range nodes.KVPairs {
			node := nodeKvp.Value.(*internalapi.Node)
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
func (c *KubeClient) Close() error {
	log.Debugf("Closing client - NOOP")
	return nil
}

// clusterNetworkPolicyClient builds a RESTClient configured to interact Cluster Network Policy.
func clusterNetworkPolicyClient(cfg *rest.Config) (*netpolicyclient.PolicyV1alpha2Client, error) {
	return netpolicyclient.NewForConfig(cfg)
}

// restClient builds a RESTClient configured to interact with Calico CustomResourceDefinitions
func restClient(cfg rest.Config, group resources.BackingAPIGroup) (*rest.RESTClient, error) {
	// Generate config using the base config.
	switch group {
	case resources.BackingAPIGroupV3:
		cfg.GroupVersion = &schema.GroupVersion{Group: "projectcalico.org", Version: "v3"}
		apiv3.AddToGlobalScheme()
	case resources.BackingAPIGroupV1:
		cfg.GroupVersion = &schema.GroupVersion{Group: "crd.projectcalico.org", Version: "v1"}
		v1scheme.AddCalicoResourcesToGlobalScheme()
	default:
		return nil, fmt.Errorf("unknown backing API group: %v", group)
	}

	cfg.APIPath = "/apis"
	cfg.ContentType = k8sruntime.ContentTypeJSON
	cfg.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs}

	cli, err := rest.RESTClientFor(&cfg)
	if err != nil {
		return nil, err
	}

	return cli, nil
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

// UpdateStatus updates the status of an existing entry in the datastore using
// the status subresource.  This errors if the entry does not exist.
func (c *KubeClient) UpdateStatus(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	log.Debugf("Performing 'UpdateStatus' for %+v", d)
	client := c.getResourceClientFromKey(d.Key)
	if client == nil {
		log.Debug("Attempt to 'UpdateStatus' using kubernetes backend is not supported.")
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: d.Key,
			Operation:  "UpdateStatus",
		}
	}
	// Use the UpdateStatus method on the resource client if it supports it,
	// otherwise fall back to Update.
	type statusUpdater interface {
		UpdateStatus(ctx context.Context, object *model.KVPair) (*model.KVPair, error)
	}
	if su, ok := client.(statusUpdater); ok {
		return su.UpdateStatus(ctx, d)
	}
	return client.Update(ctx, d)
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.  This is not exposed in the main client - but we keep here for the backend
// API.
func (c *KubeClient) Apply(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
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
func (c *KubeClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
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
	return client.Delete(ctx, k, revision, nil)
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

// Watch starts a watch on a particular resource type.
func (c *KubeClient) Watch(ctx context.Context, l model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
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
