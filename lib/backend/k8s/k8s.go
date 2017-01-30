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
	"fmt"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"

	"k8s.io/client-go/kubernetes"
	clientapi "k8s.io/client-go/pkg/api"
	kerrors "k8s.io/client-go/pkg/api/errors"
	kapiv1 "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	metav1 "k8s.io/client-go/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/runtime"
	"k8s.io/client-go/pkg/runtime/schema"
	"k8s.io/client-go/pkg/runtime/serializer"
	"k8s.io/client-go/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubeClient struct {
	// Main Kubernetes clients.
	clientSet *kubernetes.Clientset

	// Client for interacting with ThirdPartyResources.
	tprClient *rest.RESTClient

	// Contains methods for converting Kubernetes resources to
	// Calico resources.
	converter converter

	// Clients for interacting with Calico resources.
	ipPoolClient api.Client
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

	tprClient, err := buildTPRClient(config)
	if err != nil {
		return nil, err
	}
	kubeClient := &KubeClient{
		clientSet: cs,
		tprClient: tprClient,
	}

	// Create the Calico sub-clients.
	kubeClient.ipPoolClient = resources.NewIPPools(cs, tprClient)

	return kubeClient, nil
}

func (c *KubeClient) EnsureInitialized() error {
	// Ensure the necessary ThirdPartyResources exist in the API.
	log.Info("Ensuring ThirdPartyResources exist")
	err := c.ensureThirdPartyResources()
	if err != nil {
		return err
	}
	log.Info("ThirdPartyResources exist")

	// Ensure ClusterType is set.
	log.Info("Ensuring ClusterType is set")
	err = c.waitForClusterType()
	if err != nil {
		return err
	}
	log.Info("ClusterType is set")
	return nil
}

func (c *KubeClient) EnsureCalicoNodeInitialized(node string) error {
	log.WithField("Node", node).Info("Ensuring node is initialized")
	return nil
}

// ensureThirdPartyResources ensures the necessary thirdparty resources are created
// and will retry every second for 30 seconds or until they exist.
func (c *KubeClient) ensureThirdPartyResources() error {
	return wait.PollImmediate(1*time.Second, 30*time.Second, func() (bool, error) {
		if err := c.createThirdPartyResources(); err != nil {
			return false, err
		}
		return true, nil
	})
}

// createThirdPartyResources creates the necessary third party resources if they
// do not already exist.
func (c *KubeClient) createThirdPartyResources() error {
	// Ensure a resource exists for Calico global configuration.
	log.Info("Ensuring GlobalConfig ThirdPartyResource exists")
	tpr := extensions.ThirdPartyResource{
		ObjectMeta: kapiv1.ObjectMeta{
			Name:      "global-config.projectcalico.org",
			Namespace: "kube-system",
		},
		Description: "Calico Global Configuration",
		Versions:    []extensions.APIVersion{{Name: "v1"}},
	}
	_, err := c.clientSet.Extensions().ThirdPartyResources().Create(&tpr)
	if err != nil {
		// Don't care if it already exists.
		if !kerrors.IsAlreadyExists(err) {
			return resources.K8sErrorToCalico(err, tpr)
		}
	}

	// Ensure the IP Pool TPR exists.
	return c.ipPoolClient.EnsureInitialized()
}

// waitForClusterType polls until GlobalConfig is ready, or until 30 seconds have passed.
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
	value := "kubernetes,k8sdatastoredriver"

	// See if a cluster type has been set.  If so, append
	// any existing values to it.
	ct, err := c.Get(k)
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			// Resource exists but we got another error.
			return false, err
		}
		// Resource does not exist.
	}
	if ct != nil {
		existingValue := ct.Value.(string)
		if !strings.Contains(existingValue, "kubernetes") {
			existingValue = fmt.Sprintf("%s,kubernetes", existingValue)
		}

		if !strings.Contains(existingValue, "k8sdatastoredriver") {
			existingValue = fmt.Sprintf("%s,k8sdatastoredriver", existingValue)
		}
		value = existingValue
	}
	_, err = c.Apply(&model.KVPair{
		Key:   k,
		Value: value,
	})
	if err != nil {
		// Don't return an error, but indicate that we need
		// to retry.
		log.Warnf("Failed to apply ClusterType: %s", err)
		return false, nil
	}
	return true, nil
}

// buildTPRClient builds a RESTClient configured to interact with Calico ThirdPartyResources
func buildTPRClient(baseConfig *rest.Config) (*rest.RESTClient, error) {
	// Generate config using the base config.
	cfg := baseConfig
	cfg.GroupVersion = &schema.GroupVersion{
		Group:   "projectcalico.org",
		Version: "v1",
	}
	cfg.APIPath = "/apis"
	cfg.ContentType = runtime.ContentTypeJSON
	cfg.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: clientapi.Codecs}

	cli, err := rest.RESTClientFor(cfg)
	if err != nil {
		return nil, err
	}

	// We also need to register resources.
	schemeBuilder := runtime.NewSchemeBuilder(
		func(scheme *runtime.Scheme) error {
			scheme.AddKnownTypes(
				*cfg.GroupVersion,
				&thirdparty.GlobalConfig{},
				&thirdparty.GlobalConfigList{},
				&thirdparty.IpPool{},
				&thirdparty.IpPoolList{},
				&kapiv1.ListOptions{},
				&kapiv1.DeleteOptions{},
			)
			return nil
		})
	schemeBuilder.AddToScheme(clientapi.Scheme)

	return cli, nil
}

func (c *KubeClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return newSyncer(*c, callbacks)
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *KubeClient) Create(d *model.KVPair) (*model.KVPair, error) {
	switch d.Key.(type) {
	case model.GlobalConfigKey:
		return c.createGlobalConfig(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Create(d)
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
func (c *KubeClient) Update(d *model.KVPair) (*model.KVPair, error) {
	switch d.Key.(type) {
	case model.GlobalConfigKey:
		return c.updateGlobalConfig(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Update(d)
	default:
		// If the resource isn't supported, then this is a no-op.
		log.Infof("'Update' for %+v is no-op", d.Key)
		return d, nil
	}
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *KubeClient) Apply(d *model.KVPair) (*model.KVPair, error) {
	switch d.Key.(type) {
	case model.WorkloadEndpointKey:
		return c.applyWorkloadEndpoint(d)
	case model.GlobalConfigKey:
		return c.applyGlobalConfig(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Apply(d)
	default:
		log.Infof("'Apply' for %s is no-op", d.Key)
		return d, nil
	}
}

// Delete an entry in the datastore. This is a no-op when using the k8s backend.
func (c *KubeClient) Delete(d *model.KVPair) error {
	switch d.Key.(type) {
	case model.GlobalConfigKey:
		return c.deleteGlobalConfig(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Delete(d)
	default:
		log.Warn("Attempt to 'Delete' using kubernetes backend is not supported.")
		return nil
	}
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *KubeClient) Get(k model.Key) (*model.KVPair, error) {
	log.Debugf("Performing 'Get' for %+v", k)
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
	case model.IPPoolKey:
		return c.ipPoolClient.Get(k.(model.IPPoolKey))
	default:
		return nil, errors.ErrorOperationNotSupported{
			Identifier: k,
			Operation:  "Get",
		}
	}
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *KubeClient) List(l model.ListInterface) ([]*model.KVPair, error) {
	log.Debugf("Performing 'List' for %+v", l)
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
	case model.IPPoolListOptions:
		return c.ipPoolClient.List(l.(model.IPPoolListOptions))
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
	namespaces, err := c.clientSet.Namespaces().List(kapiv1.ListOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, l)
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
	namespace, err := c.clientSet.Namespaces().Get(namespaceName, metav1.GetOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, k)
	}

	return c.converter.namespaceToProfile(namespace)
}

// applyWorkloadEndpoint patches the existing Pod to include an IP address, if
// one has been set on the workload endpoint.
func (c *KubeClient) applyWorkloadEndpoint(k *model.KVPair) (*model.KVPair, error) {
	ips := k.Value.(*model.WorkloadEndpoint).IPv4Nets
	if len(ips) > 0 {
		log.Debugf("Applying workload with IPs: %+v", ips)
		ns, name := c.converter.parseWorkloadID(k.Key.(model.WorkloadEndpointKey).WorkloadID)
		pod, err := c.clientSet.Pods(ns).Get(name, metav1.GetOptions{})
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k.Key)
		}
		pod.Status.PodIP = ips[0].IP.String()
		pod, err = c.clientSet.Pods(ns).UpdateStatus(pod)
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k.Key)
		}
		log.Debugf("Successfully applied pod: %+v", pod)
		return c.converter.podToWorkloadEndpoint(pod)
	}
	return k, nil
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
	pods, err := c.clientSet.Pods("").List(kapiv1.ListOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, l)
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

	pod, err := c.clientSet.Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, k)
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
		return nil, resources.K8sErrorToCalico(err, l)
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

	// List all Namespaces and turn them into Policies as well.
	namespaces, err := c.clientSet.Namespaces().List(kapiv1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, ns := range namespaces.Items {
		kvp, err := c.converter.namespaceToPolicy(&ns)
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

	// Check to see if this is backed by a NetworkPolicy or a Namespace.
	if strings.HasPrefix(k.Name, "np.projectcalico.org/") {
		// Backed by a NetworkPolicy. Parse out the namespace / name.
		namespace, policyName, err := c.converter.parsePolicyNameNetworkPolicy(k.Name)
		if err != nil {
			return nil, errors.ErrorResourceDoesNotExist{Err: err, Identifier: k}
		}

		// Get the NetworkPolicy from the API and convert it.
		networkPolicy := extensions.NetworkPolicy{}
		err = c.clientSet.Extensions().RESTClient().
			Get().
			Resource("networkpolicies").
			Namespace(namespace).
			Name(policyName).
			Timeout(10 * time.Second).
			Do().Into(&networkPolicy)
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k)
		}
		return c.converter.networkPolicyToPolicy(&networkPolicy)
	} else if strings.HasPrefix(k.Name, "ns.projectcalico.org/") {
		// This is backed by a Namespace.
		namespace, err := c.converter.parsePolicyNameNamespace(k.Name)
		if err != nil {
			return nil, errors.ErrorResourceDoesNotExist{Err: err, Identifier: k}
		}

		ns, err := c.clientSet.Namespaces().Get(namespace, metav1.GetOptions{})
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k)
		}
		return c.converter.namespaceToPolicy(ns)
	} else {
		// Received a Get() for a Policy that doesn't exist.
		return nil, errors.ErrorResourceDoesNotExist{Identifier: k}
	}
}

func (c *KubeClient) getReadyStatus(k model.ReadyFlagKey) (*model.KVPair, error) {
	return &model.KVPair{Key: k, Value: true}, nil
}

// applyGlobalConfig updates a global config if it exists, and creates it
// if it doesn't.
func (c *KubeClient) applyGlobalConfig(kvp *model.KVPair) (*model.KVPair, error) {
	updated, err := c.updateGlobalConfig(kvp)
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			// Error other than "not found" - return.
			return nil, err
		}

		// It doesn't exist - create it.
		updated, err = c.createGlobalConfig(kvp)
		if err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// updateGlobalConfig updates a global config if it exists, and returns an error
// if it doesn't.
func (c *KubeClient) updateGlobalConfig(kvp *model.KVPair) (*model.KVPair, error) {
	gcfg := c.converter.globalConfigToTPR(kvp)
	res := thirdparty.GlobalConfig{}
	req := c.tprClient.Put().
		Resource("globalconfigs").
		Namespace("kube-system").
		Body(&gcfg).
		Name(gcfg.Metadata.Name)
	err := req.Do().Into(&res)
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, kvp.Key)
	}
	kvp.Revision = gcfg.Metadata.ResourceVersion
	return kvp, nil
}

// createGlobalConfig creates a global config if it doesn't exist, and
// returns an error if it does.
func (c *KubeClient) createGlobalConfig(kvp *model.KVPair) (*model.KVPair, error) {
	gcfg := c.converter.globalConfigToTPR(kvp)
	res := thirdparty.GlobalConfig{}
	req := c.tprClient.Post().
		Resource("globalconfigs").
		Namespace("kube-system").
		Body(&gcfg)
	err := req.Do().Into(&res)
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, kvp.Key)
	}
	kvp.Revision = gcfg.Metadata.ResourceVersion
	return kvp, nil
}

// getGlobalConfig gets a global config and returns an error if it doesn't exist.
func (c *KubeClient) getGlobalConfig(k model.GlobalConfigKey) (*model.KVPair, error) {
	cfg := thirdparty.GlobalConfig{}
	err := c.tprClient.Get().
		Resource("globalconfigs").
		Namespace("kube-system").
		Name(strings.ToLower(k.Name)).
		Do().Into(&cfg)
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, k)
	}

	return c.converter.tprToGlobalConfig(&cfg), nil
}

// listGlobalConfig lists all global configs.
func (c *KubeClient) listGlobalConfig(l model.GlobalConfigListOptions) ([]*model.KVPair, error) {
	cfgs := []*model.KVPair{}
	gcfg := thirdparty.GlobalConfigList{}

	// Build the request.
	req := c.tprClient.Get().Resource("globalconfigs").Namespace("kube-system")
	if l.Name != "" {
		req.Name(strings.ToLower(l.Name))
	}

	// Perform the request.
	err := req.Do().Into(&gcfg)
	if err != nil {
		// Don't return errors for "not found".  This just
		// means thre are no GlobalConfigs, and we should return
		// an empty list.
		if !kerrors.IsNotFound(err) {
			return nil, resources.K8sErrorToCalico(err, l)
		}
	}

	// Convert them to KVPairs.
	for _, cfg := range gcfg.Items {
		cfgs = append(cfgs, c.converter.tprToGlobalConfig(&cfg))
	}

	return cfgs, nil
}

// deleteGlobalConfig deletes the given global config.
func (c *KubeClient) deleteGlobalConfig(k *model.KVPair) error {
	result := c.tprClient.Delete().
		Resource("globalconfigs").
		Namespace("kube-system").
		Name(strings.ToLower(k.Key.(model.GlobalConfigKey).Name)).
		Do()
	return resources.K8sErrorToCalico(result.Error(), k.Key)
}

func (c *KubeClient) getHostConfig(k model.HostConfigKey) (*model.KVPair, error) {
	return &model.KVPair{
		Key:   k,
		Value: nil,
	}, nil
}

func (c *KubeClient) listHostConfig(l model.HostConfigListOptions) ([]*model.KVPair, error) {
	return []*model.KVPair{}, nil
}
