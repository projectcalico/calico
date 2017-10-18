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
	goerrors "errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	_ "k8s.io/client-go/plugin/pkg/client/auth" // Import all auth providers.

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"

	"k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
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

type KubeClient struct {
	// Main Kubernetes clients.
	clientSet *kubernetes.Clientset

	// Client for interacting with CustomResourceDefinition.
	crdClientV1 *rest.RESTClient

	disableNodePoll bool

	// Contains methods for converting Kubernetes resources to
	// Calico resources.
	converter Converter

	// Clients for interacting with Calico resources.
	bgpPeerClient       resources.K8sResourceClient
	bgpConfigClient     resources.K8sResourceClient
	nodeBgpConfigClient resources.K8sResourceClient
	felixConfigClient   resources.K8sResourceClient
	clusterInfoClient   resources.K8sResourceClient
	ipPoolClient        resources.K8sResourceClient
	gnpClient           resources.K8sResourceClient
	nodeClient          resources.K8sResourceClient
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
		clientSet:       cs,
		crdClientV1:     crdClientV1,
		disableNodePoll: kc.K8sDisableNodePoll,
	}

	// Create the Calico sub-clients.
	kubeClient.ipPoolClient = resources.NewIPPoolClient(cs, crdClientV1)
	kubeClient.nodeClient = resources.NewNodeClient(cs, crdClientV1)
	kubeClient.gnpClient = resources.NewGlobalNetworkPolicyClient(cs, crdClientV1)
	kubeClient.bgpPeerClient = resources.NewBGPPeerClient(cs, crdClientV1)
	kubeClient.bgpConfigClient = resources.NewBGPConfigClient(cs, crdClientV1)
	kubeClient.felixConfigClient = resources.NewFelixConfigClient(cs, crdClientV1)
	kubeClient.clusterInfoClient = resources.NewClusterInfoClient(cs, crdClientV1)

	return kubeClient, nil
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
	/*types := []model.ListInterface{
		model.BGPConfigListOptions{},
		model.BGPPeerListOptions{},
		model.GlobalConfigListOptions{},
		model.IPPoolListOptions{},
	}
	for _, t := range types {
		rs, _ := c.List(t, "")
		for _, r := range rs.KVPairs {
			log.WithField("Key", r.Key).Info("Deleting from KDD")
			backend.Delete(r.Key, r.Revision)
		}
	}
	*/
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
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
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
			)
			return nil
		})

	schemeBuilder.AddToScheme(scheme.Scheme)

	return cli, nil
}

func (c *KubeClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return newSyncer(&realKubeAPI{c}, c.converter, callbacks, c.disableNodePoll)
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *KubeClient) Create(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	log.Debugf("Performing 'Create' for %+v", d)
	switch d.Value.(type) {
	case *apiv2.IPPool:
		return c.ipPoolClient.Create(ctx, d)
	case *apiv2.Node:
		return c.nodeClient.Create(ctx, d)
	case *apiv2.BGPPeer:
		return c.bgpPeerClient.Create(ctx, d)
	case *apiv2.BGPConfiguration:
		return c.bgpConfigClient.Create(ctx, d)
	case *apiv2.FelixConfiguration:
		return c.felixConfigClient.Create(ctx, d)
	case *apiv2.ClusterInformation:
		return c.clusterInfoClient.Create(ctx, d)
	case *apiv2.GlobalNetworkPolicy:
		return c.gnpClient.Create(ctx, d)
	default:
		log.Warn("Attempt to 'Create' using kubernetes backend is not supported.")
		return nil, errors.ErrorOperationNotSupported{
			Identifier: d.Key,
			Operation:  "Create",
		}
	}
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist.
func (c *KubeClient) Update(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	log.Debugf("Performing 'Update' for %+v", d)
	switch d.Value.(type) {
	case *apiv2.IPPool:
		return c.ipPoolClient.Update(ctx, d)
	case *apiv2.Node:
		return c.nodeClient.Update(ctx, d)
	case *apiv2.BGPPeer:
		return c.bgpPeerClient.Update(ctx, d)
	case *apiv2.BGPConfiguration:
		return c.bgpConfigClient.Update(ctx, d)
	case *apiv2.FelixConfiguration:
		return c.felixConfigClient.Update(ctx, d)
	case *apiv2.ClusterInformation:
		return c.clusterInfoClient.Update(ctx, d)
	case *apiv2.GlobalNetworkPolicy:
		return c.gnpClient.Update(ctx, d)
	default:
		log.Warn("Attempt to 'Update' using kubernetes backend is not supported.")
		return nil, errors.ErrorOperationNotSupported{
			Identifier: d.Key,
			Operation:  "Update",
		}
	}
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *KubeClient) Apply(d *model.KVPair) (*model.KVPair, error) {
	log.Debugf("Performing 'Apply' for %+v", d)
	switch d.Key.(type) {
	case model.WorkloadEndpointKey:
		return c.applyWorkloadEndpoint(d)
	case model.GlobalConfigKey:
		return c.felixConfigClient.Apply(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Apply(d)
	case model.NodeKey:
		return c.nodeClient.Apply(d)
	case model.GlobalBGPPeerKey:
		return c.bgpPeerClient.Apply(d)
	case model.GlobalBGPConfigKey:
		return c.bgpConfigClient.Apply(d)
	case model.NodeBGPConfigKey:
		return c.nodeBgpConfigClient.Apply(d)
	case model.ActiveStatusReportKey, model.LastStatusReportKey,
		model.HostEndpointStatusKey, model.WorkloadEndpointStatusKey:
		// Felix periodically reports status to the datastore.  This isn't supported
		// right now, but we handle it anyway to avoid spamming warning logs.
		log.WithField("key", d.Key).Debug("Dropping status report (not supported)")
		return d, nil
	default:
		log.Warn("Attempt to 'Apply' using kubernetes backend is not supported.")
		return nil, errors.ErrorOperationNotSupported{
			Identifier: d.Key,
			Operation:  "Apply",
		}
	}
}

// Delete an entry in the datastore. This is a no-op when using the k8s backend.
func (c *KubeClient) Delete(ctx context.Context, k model.Key, revision string) (*model.KVPair, error) {
	log.Debugf("Performing 'Delete' for %+v", k)
	switch k.(model.ResourceKey).Kind {
	case apiv2.KindIPPool:
		return c.ipPoolClient.Delete(ctx, k, revision)
	case apiv2.KindNode:
		return c.nodeClient.Delete(ctx, k, revision)
	case apiv2.KindBGPPeer:
		return c.bgpPeerClient.Delete(ctx, k, revision)
	case apiv2.KindBGPConfiguration:
		return c.bgpConfigClient.Delete(ctx, k, revision)
	case apiv2.KindFelixConfiguration:
		return c.felixConfigClient.Delete(ctx, k, revision)
	case apiv2.KindClusterInformation:
		return c.clusterInfoClient.Delete(ctx, k, revision)
	case apiv2.KindGlobalNetworkPolicy:
		return c.gnpClient.Delete(ctx, k, revision)
	default:
		log.Warn("Attempt to 'Delete' using kubernetes backend is not supported.")
		return nil, errors.ErrorOperationNotSupported{
			Identifier: k,
			Operation:  "Delete",
		}
	}
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *KubeClient) Get(ctx context.Context, k model.Key, revision string) (*model.KVPair, error) {
	log.Debugf("Performing 'Get' for %+v %v", k, revision)
	switch k.(model.ResourceKey).Kind {
	case apiv2.KindProfile:
		return c.getProfile(ctx, k.(model.ResourceKey), revision)
	case apiv2.KindWorkloadEndpoint:
		return c.getWorkloadEndpoint(ctx, k.(model.ResourceKey), revision)
	case apiv2.KindGlobalNetworkPolicy, apiv2.KindNetworkPolicy:
		return c.getPolicy(ctx, k.(model.ResourceKey), revision)
	case apiv2.KindIPPool:
		return c.ipPoolClient.Get(ctx, k, revision)
	case apiv2.KindNode:
		return c.nodeClient.Get(ctx, k.(model.ResourceKey), revision)
	case apiv2.KindBGPPeer:
		return c.bgpPeerClient.Get(ctx, k, revision)
	case apiv2.KindBGPConfiguration:
		return c.bgpConfigClient.Get(ctx, k, revision)
	case apiv2.KindFelixConfiguration:
		return c.felixConfigClient.Get(ctx, k, revision)
	case apiv2.KindClusterInformation:
		return c.clusterInfoClient.Get(ctx, k, revision)
	default:
		return nil, errors.ErrorOperationNotSupported{
			Identifier: k,
			Operation:  "Get",
		}
	}
}

// List entries in the datastore.  This may return an empty list if there are
// no entries matching the request in the ListInterface.
func (c *KubeClient) List(ctx context.Context, l model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debugf("Performing 'List' for %+v %v", l, reflect.TypeOf(l))
	switch l.(model.ResourceListOptions).Kind {
	case apiv2.KindProfile:
		return c.listProfiles(ctx, l.(model.ResourceListOptions), revision)
	case apiv2.KindWorkloadEndpoint:
		return c.listWorkloadEndpoints(ctx, l.(model.ResourceListOptions), revision)
	case apiv2.KindGlobalNetworkPolicy, apiv2.KindNetworkPolicy:
		return c.listPolicies(ctx, l.(model.ResourceListOptions), revision)
	case apiv2.KindIPPool:
		return c.ipPoolClient.List(ctx, l, revision)
	case apiv2.KindBGPPeer:
		return c.bgpPeerClient.List(ctx, l, revision)
	case apiv2.KindBGPConfiguration:
		return c.bgpConfigClient.List(ctx, l, revision)
	case apiv2.KindFelixConfiguration:
		return c.felixConfigClient.List(ctx, l, revision)
	case apiv2.KindClusterInformation:
		return c.clusterInfoClient.List(ctx, l, revision)
	case apiv2.KindNode:
		return c.nodeClient.List(ctx, l, revision)
	default:
		return &model.KVPairList{
			KVPairs:  []*model.KVPair{},
			Revision: revision,
		}, nil
	}
}

// listProfiles lists Profiles from the k8s API based on existing Namespaces.
func (c *KubeClient) listProfiles(ctx context.Context, l model.ResourceListOptions, revision string) (*model.KVPairList, error) {
	// If a name is specified, then do an exact lookup.
	if l.Name != "" {
		kvp, err := c.getProfile(ctx, model.ResourceKey{Name: l.Name, Kind: l.Kind}, revision)
		if err != nil {
			log.WithError(err).Debug("Error retrieving profile")
			// TODO(doublek): Check the return value here.
			return &model.KVPairList{
				KVPairs:  []*model.KVPair{},
				Revision: revision,
			}, nil
		}
		return &model.KVPairList{
			KVPairs:  []*model.KVPair{kvp},
			Revision: revision,
		}, nil
	}

	// Otherwise, enumerate all.
	namespaces, err := c.clientSet.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, l)
	}

	// For each Namespace, return a profile.
	ret := []*model.KVPair{}
	for _, ns := range namespaces.Items {
		kvp, err := c.converter.NamespaceToProfile(&ns)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvp)
	}
	return &model.KVPairList{
		KVPairs:  ret,
		Revision: revision,
	}, nil
}

// getProfile gets the Profile from the k8s API based on existing Namespaces.
func (c *KubeClient) getProfile(ctx context.Context, k model.ResourceKey, revision string) (*model.KVPair, error) {
	if k.Name == "" {
		return nil, fmt.Errorf("Profile key missing name: %+v", k)
	}
	namespaceName, err := c.converter.parseProfileName(k.Name)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Profile name: %s", err)
	}
	namespace, err := c.clientSet.CoreV1().Namespaces().Get(namespaceName, metav1.GetOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, k)
	}

	return c.converter.NamespaceToProfile(namespace)
}

// applyWorkloadEndpoint patches the existing Pod to include an IP address, if
// one has been set on the workload endpoint.
// TODO: This is only required as a workaround for an upstream k8s issue.  Once fixed,
// this should be a no-op. See https://github.com/kubernetes/kubernetes/issues/39113
func (c *KubeClient) applyWorkloadEndpoint(k *model.KVPair) (*model.KVPair, error) {
	ips := k.Value.(*model.WorkloadEndpoint).IPv4Nets
	if len(ips) > 0 {
		log.Debugf("Applying workload with IPs: %+v", ips)
		ns, name := c.converter.parseWorkloadID(k.Key.(model.WorkloadEndpointKey).WorkloadID)
		pod, err := c.clientSet.CoreV1().Pods(ns).Get(name, metav1.GetOptions{})
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k.Key)
		}
		pod.Status.PodIP = ips[0].IP.String()
		pod, err = c.clientSet.CoreV1().Pods(ns).UpdateStatus(pod)
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k.Key)
		}
		log.Debugf("Successfully applied pod: %+v", pod)
		return c.converter.PodToWorkloadEndpoint(pod)
	}
	return k, nil
}

// listWorkloadEndpoints lists WorkloadEndpoints from the k8s API based on existing Pods.
func (c *KubeClient) listWorkloadEndpoints(ctx context.Context, l model.ResourceListOptions, revision string) (*model.KVPairList, error) {
	// If a workload is provided, we can do an exact lookup of this
	// workload endpoint.
	if l.Name != "" {
		kvp, err := c.getWorkloadEndpoint(ctx, model.ResourceKey{
			Name: l.Name,
			Kind: l.Kind,
		}, revision)
		if err != nil {
			switch err.(type) {
			// Return empty slice of KVPair if the object doesn't exist, return the error otherwise.
			case errors.ErrorResourceDoesNotExist:
				return &model.KVPairList{
					KVPairs:  []*model.KVPair{},
					Revision: revision,
				}, nil
			default:
				return nil, err
			}
		}

		return &model.KVPairList{
			KVPairs:  []*model.KVPair{kvp},
			Revision: revision,
		}, nil
	}

	// Otherwise, enumerate all pods in all namespaces.
	// We don't yet support hostname, orchestratorID, for the k8s backend.
	pods, err := c.clientSet.CoreV1().Pods("").List(metav1.ListOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, l)
	}

	// For each Pod, return a workload endpoint.
	ret := []*model.KVPair{}
	for _, pod := range pods.Items {
		// Decide if this pod should be displayed.
		if !c.converter.isReadyCalicoPod(&pod) {
			continue
		}

		kvp, err := c.converter.PodToWorkloadEndpoint(&pod)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvp)
	}
	return &model.KVPairList{
		KVPairs:  ret,
		Revision: revision,
	}, nil
}

// getWorkloadEndpoint gets the WorkloadEndpoint from the k8s API based on existing Pods.
func (c *KubeClient) getWorkloadEndpoint(ctx context.Context, k model.ResourceKey, revision string) (*model.KVPair, error) {
	// The workloadID is of the form namespace.podname.  Parse it so we
	// can find the correct namespace to get the pod.
	namespace, podName := c.converter.parseWorkloadID(k.Name)

	pod, err := c.clientSet.CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, k)
	}

	// Decide if this pod should be displayed.
	if !c.converter.isReadyCalicoPod(pod) {
		return nil, errors.ErrorResourceDoesNotExist{Identifier: k}
	}
	return c.converter.PodToWorkloadEndpoint(pod)
}

// listPolicies lists the Policies from the k8s API based on NetworkPolicy objects.
func (c *KubeClient) listPolicies(ctx context.Context, l model.ResourceListOptions, revision string) (*model.KVPairList, error) {
	if l.Name != "" {
		// Exact lookup on a NetworkPolicy.
		kvp, err := c.getPolicy(ctx, model.ResourceKey{Name: l.Name, Kind: l.Kind}, revision)
		if err != nil {
			switch err.(type) {
			// Return empty slice of KVPair if the object doesn't exist, return the error otherwise.
			case errors.ErrorResourceDoesNotExist:
				return &model.KVPairList{
					KVPairs:  []*model.KVPair{},
					Revision: revision,
				}, nil
			default:
				return nil, err
			}
		}

		return &model.KVPairList{
			KVPairs:  []*model.KVPair{kvp},
			Revision: revision,
		}, nil
	}

	// Otherwise, list all NetworkPolicy objects in all Namespaces.
	networkPolicies := extensions.NetworkPolicyList{}

	// For each policy, turn it into a Policy and generate the list.
	ret := []*model.KVPair{}
	for _, p := range networkPolicies.Items {
		kvp, err := c.converter.NetworkPolicyToPolicy(&p)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvp)
	}

	// List all Global Network Policies.
	gnps, err := c.gnpClient.List(ctx, l, revision)
	if err != nil {
		return nil, err
	}
	ret = append(ret, gnps.KVPairs...)

	return &model.KVPairList{
		KVPairs:  ret,
		Revision: revision,
	}, nil
}

// getPolicy gets the Policy from the k8s API based on NetworkPolicy objects.
func (c *KubeClient) getPolicy(ctx context.Context, k model.ResourceKey, revision string) (*model.KVPair, error) {
	if k.Name == "" {
		return nil, goerrors.New("Missing policy name")
	}

	// Check to see if this is backed by a NetworkPolicy.
	if strings.HasPrefix(k.Name, "knp.default.") {
		// Backed by a NetworkPolicy. Parse out the namespace / name.
		namespace, policyName, err := c.converter.parsePolicyNameNetworkPolicy(k.Name)
		if err != nil {
			return nil, errors.ErrorResourceDoesNotExist{Err: err, Identifier: k}
		}

		// Get the NetworkPolicy from the API and convert it.
		networkPolicy := extensions.NetworkPolicy{}
		err = c.clientSet.ExtensionsV1beta1().RESTClient().
			Get().
			Resource("networkpolicies").
			Namespace(namespace).
			Name(policyName).
			Timeout(10 * time.Second).
			Do().Into(&networkPolicy)
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k)
		}
		return c.converter.NetworkPolicyToPolicy(&networkPolicy)
	} else {
		// This is backed by a Global Network Policy CRD.
		return c.gnpClient.Get(ctx, k, revision)
	}
}

func (c *KubeClient) getReadyStatus(ctx context.Context, k model.ReadyFlagKey, revision string) (*model.KVPair, error) {
	return &model.KVPair{Key: k, Value: true}, nil
}

func (c *KubeClient) getHostConfig(ctx context.Context, k model.HostConfigKey, revision string) (*model.KVPair, error) {
	if k.Name == "IpInIpTunnelAddr" {
		n, err := c.clientSet.CoreV1().Nodes().Get(k.Hostname, metav1.GetOptions{})
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k)
		}

		kvp, err := getTunIp(n)
		if err != nil {
			return nil, err
		} else if kvp == nil {
			return nil, errors.ErrorResourceDoesNotExist{}
		}

		return kvp, nil
	}

	return nil, errors.ErrorResourceDoesNotExist{Identifier: k}
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
