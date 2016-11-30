// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	goerrors "errors"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"k8s.io/client-go/kubernetes"
	k8sapi "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/clientcmd"
)

type KubeClient struct {
	clientSet *kubernetes.Clientset
	converter converter
}

type KubeConfig struct {
	Kubeconfig     string `json:"kubeconfig" envconfig:"KUBECONFIG" default:""`
	K8sAPIEndpoint string `json:"k8sAPIEndpoint" envconfig:"K8S_API_ENDPOINT" default:""`
	K8sKeyFile     string `json:"k8sKeyFile" envconfig:"K8S_KEY_FILE" default:""`
	K8sCertFile    string `json:"k8sCertFile" envconfig:"K8S_CERT_FILE" default:""`
	K8sCAFile      string `json:"k8sCAFile" envconfig:"K8S_CA_FILE" default:""`
	K8sAPIToken    string `json:"k8sAPIToken" envconfig:"K8S_API_TOKEN" default:""`
}

func NewKubeClient(kc *KubeConfig) (*KubeClient, error) {
	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	log.Infof("Building client for config: %+v", kc)
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
	log.Infof("Config overrides: %+v", configOverrides)

	// A kubeconfig file was provided.  Use it to load a config, passing through
	// any overrides.
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&loadingRules, configOverrides).ClientConfig()
	if err != nil {
		return nil, err
	}

	// Create the clientset
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	log.Debugf("Created k8s clientSet: %+v", cs)
	return &KubeClient{clientSet: cs}, nil
}

func (c *KubeClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return newSyncer(*c, callbacks)
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *KubeClient) Create(d *model.KVPair) (*model.KVPair, error) {
	log.Warn("Attempt to 'Create' using kubernetes backend is not supported.")
	return nil, errors.ErrorResourceDoesNotExist{
		Err:        goerrors.New("Resource does not exist"),
		Identifier: d.Key,
	}
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist.
func (c *KubeClient) Update(d *model.KVPair) (*model.KVPair, error) {
	// This is a noop.  Calico components shouldn't be modifying
	// k8s resources.
	log.Infof("Kubernetes backend received 'Update' for %+v - do nothing.", d.Key)
	return d, nil
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *KubeClient) Apply(d *model.KVPair) (*model.KVPair, error) {
	log.Infof("Ignoring 'Apply' for %s", d.Key)
	return d, nil
}

// Delete an entry in the datastore. This is a no-op when using the k8s backend.
func (c *KubeClient) Delete(d *model.KVPair) error {
	log.Warn("Attempt to 'Delete' using kubernetes backend is not supported.")
	return nil
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *KubeClient) Get(k model.Key) (*model.KVPair, error) {
	log.Debugf("Received 'Get' request for %+v", k)
	switch k.(type) {
	case model.ProfileKey:
		return c.getProfile(k.(model.ProfileKey))
	case model.WorkloadEndpointKey:
		return c.getWorkloadEndpoint(k.(model.WorkloadEndpointKey))
	case model.PolicyKey:
		return c.getPolicy(k.(model.PolicyKey))
	case model.HostConfigKey:
		return c.getHostConfig(k.(model.HostConfigKey))
	case model.GlobalConfigKey:
		return c.getGlobalConfig(k.(model.GlobalConfigKey))
	case model.ReadyFlagKey:
		return c.getReadyStatus(k.(model.ReadyFlagKey))
	default:
		return nil, errors.ErrorResourceDoesNotExist{
			Err:        goerrors.New("Resource does not exist"),
			Identifier: k,
		}
	}
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *KubeClient) List(l model.ListInterface) ([]*model.KVPair, error) {
	log.Debugf("Received 'List' request for %+v", l)
	switch l.(type) {
	case model.ProfileListOptions:
		return c.listProfiles(l.(model.ProfileListOptions))
	case model.WorkloadEndpointListOptions:
		return c.listWorkloadEndpoints(l.(model.WorkloadEndpointListOptions))
	case model.PolicyListOptions:
		return c.listPolicies(l.(model.PolicyListOptions))
	case model.GlobalConfigListOptions:
		return c.listGlobalConfig(l.(model.GlobalConfigListOptions))
	case model.HostConfigListOptions:
		return c.listHostConfig(l.(model.HostConfigListOptions))
	default:
		return []*model.KVPair{}, nil
	}
}

// listProfiles lists Profiles from the k8s API based on existing Namespaces.
func (c *KubeClient) listProfiles(l model.ProfileListOptions) ([]*model.KVPair, error) {
	// If a name is specified, then do an exact lookup.
	if l.Name != "" {
		kvp, err := c.getProfile(model.ProfileKey{Name: l.Name})
		if err != nil {
			return []*model.KVPair{}, nil
		}
		return []*model.KVPair{kvp}, nil
	}

	// Otherwise, enumerate all.
	namespaces, err := c.clientSet.Namespaces().List(k8sapi.ListOptions{})
	if err != nil {
		return nil, err
	}

	// For each Namespace, return a profile.
	ret := []*model.KVPair{}
	for _, ns := range namespaces.Items {
		kvp, err := c.converter.namespaceToProfile(&ns)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvp)
	}
	return ret, nil
}

// getProfile gets the Profile from the k8s API based on existing Namespaces.
func (c *KubeClient) getProfile(k model.ProfileKey) (*model.KVPair, error) {
	if k.Name == "" {
		return nil, goerrors.New("Missing profile name")
	}
	namespaceName, err := c.converter.parseProfileName(k.Name)
	if err != nil {
		return nil, err
	}
	namespace, err := c.clientSet.Namespaces().Get(namespaceName)
	if err != nil {
		return nil, err
	}

	return c.converter.namespaceToProfile(namespace)
}

// listWorkloadEndpoints lists WorkloadEndpoints from the k8s API based on existing Pods.
func (c *KubeClient) listWorkloadEndpoints(l model.WorkloadEndpointListOptions) ([]*model.KVPair, error) {
	// If a workload is provided, we can do an exact lookup of this
	// workload endpoint.
	if l.WorkloadID != "" {
		kvp, err := c.getWorkloadEndpoint(model.WorkloadEndpointKey{
			WorkloadID: l.WorkloadID,
		})
		if err != nil {
			// Error getting the endpoint.
			return nil, err
		}
		if kvp == nil {
			// The workload endpoint doesn't exist.
			return nil, nil
		}
		return []*model.KVPair{kvp}, nil
	}

	// Otherwise, enumerate all pods in all namespaces.
	// We don't yet support hostname, orchestratorID, for the k8s backend.
	pods, err := c.clientSet.Pods("").List(k8sapi.ListOptions{})
	if err != nil {
		return nil, err
	}

	// For each Pod, return a workload endpoint.
	ret := []*model.KVPair{}
	for _, pod := range pods.Items {
		// Decide if this pod should be displayed.
		if !c.converter.isCalicoPod(&pod) {
			continue
		}

		kvp, err := c.converter.podToWorkloadEndpoint(&pod)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvp)
	}
	return ret, nil
}

// getWorkloadEndpoint gets the WorkloadEndpoint from the k8s API based on existing Pods.
func (c *KubeClient) getWorkloadEndpoint(k model.WorkloadEndpointKey) (*model.KVPair, error) {
	// The workloadID is of the form namespace.podname.  Parse it so we
	// can find the correct namespace to get the pod.
	namespace, podName := c.converter.parseWorkloadID(k.WorkloadID)

	pod, err := c.clientSet.Pods(namespace).Get(podName)
	if err != nil {
		return nil, err
	}

	// Decide if this pod should be displayed.
	if !c.converter.isCalicoPod(pod) {
		return nil, nil
	}
	return c.converter.podToWorkloadEndpoint(pod)
}

// listPolicies lists the Policies from the k8s API based on NetworkPolicy objects.
func (c *KubeClient) listPolicies(l model.PolicyListOptions) ([]*model.KVPair, error) {
	if l.Name != "" {
		// Exact lookup on a NetworkPolicy.
		kvp, err := c.getPolicy(model.PolicyKey{Name: l.Name})
		if err != nil {
			return []*model.KVPair{}, nil
		}
		return []*model.KVPair{kvp}, nil
	}

	// Otherwise, list all NetworkPolicy objects in all Namespaces.
	networkPolicies := extensions.NetworkPolicyList{}
	err := c.clientSet.Extensions().RESTClient().
		Get().
		Resource("networkpolicies").
		Timeout(10 * time.Second).
		Do().Into(&networkPolicies)
	if err != nil {
		return nil, err
	}

	// For each policy, turn it into a Policy and generate the list.
	ret := []*model.KVPair{}
	for _, p := range networkPolicies.Items {
		kvp, err := c.converter.networkPolicyToPolicy(&p)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvp)
	}

	return ret, nil
}

// getPolicy gets the Policy from the k8s API based on NetworkPolicy objects.
func (c *KubeClient) getPolicy(k model.PolicyKey) (*model.KVPair, error) {
	if k.Name == "" {
		return nil, goerrors.New("Missing policy name")
	}
	namespace, policyName := c.converter.parsePolicyName(k.Name)

	networkPolicy := extensions.NetworkPolicy{}
	err := c.clientSet.Extensions().RESTClient().
		Get().
		Resource("networkpolicies").
		Namespace(namespace).
		Name(policyName).
		Timeout(10 * time.Second).
		Do().Into(&networkPolicy)
	if err != nil {
		return nil, err
	}
	return c.converter.networkPolicyToPolicy(&networkPolicy)
}

func (c *KubeClient) getReadyStatus(k model.ReadyFlagKey) (*model.KVPair, error) {
	return &model.KVPair{Key: k, Value: true}, nil
}

func (c *KubeClient) getGlobalConfig(k model.GlobalConfigKey) (*model.KVPair, error) {
	return nil, goerrors.New("Get for GlobalConfig not supported in kubernetes backend")
}

func (c *KubeClient) listGlobalConfig(l model.GlobalConfigListOptions) ([]*model.KVPair, error) {
	return []*model.KVPair{}, nil
}

func (c *KubeClient) getHostConfig(k model.HostConfigKey) (*model.KVPair, error) {
	return nil, goerrors.New("Get for HostConfig not supported in kubernetes backend")
}

func (c *KubeClient) listHostConfig(l model.HostConfigListOptions) ([]*model.KVPair, error) {
	return []*model.KVPair{}, nil
}
