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
	goerrors "errors"
	"fmt"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	capi "github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientapi "k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubeClient struct {
	// Main Kubernetes clients.
	clientSet *kubernetes.Clientset

	// Client for interacting with ThirdPartyResources.
	tprClientV1      *rest.RESTClient
	tprClientV1alpha *rest.RESTClient

	disableNodePoll bool

	// Contains methods for converting Kubernetes resources to
	// Calico resources.
	converter converter

	// Clients for interacting with Calico resources.
	ipPoolClient api.Client
	nodeClient   api.Client
	snpClient    api.Client
}

func NewKubeClient(kc *capi.KubeConfig) (*KubeClient, error) {
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

	tprClientV1, err := buildTPRClientV1(*config)
	if err != nil {
		return nil, fmt.Errorf("Failed to build V1 TPR client: %s", err)
	}
	tprClientV1alpha, err := buildTPRClientV1alpha(*config)
	if err != nil {
		return nil, fmt.Errorf("Failed to build V1alpha TPR client: %s", err)
	}
	kubeClient := &KubeClient{
		clientSet:        cs,
		tprClientV1:      tprClientV1,
		tprClientV1alpha: tprClientV1alpha,
		disableNodePoll:  kc.K8sDisableNodePoll,
	}

	// Create the Calico sub-clients.
	kubeClient.ipPoolClient = resources.NewIPPools(cs, tprClientV1)
	kubeClient.nodeClient = resources.NewNodeClient(cs, tprClientV1)
	kubeClient.snpClient = resources.NewSystemNetworkPolicies(cs, tprClientV1alpha)

	return kubeClient, nil
}

func (c *KubeClient) EnsureInitialized() error {
	// Ensure the necessary ThirdPartyResources exist in the API.
	log.Info("Ensuring ThirdPartyResources exist")
	err := c.ensureThirdPartyResources()
	if err != nil {
		return fmt.Errorf("Failed to ensure ThirdPartyResources exist: %s", err)
	}
	log.Info("ThirdPartyResources exist")

	// Ensure ClusterType is set.
	log.Info("Ensuring ClusterType is set")
	err = c.waitForClusterType()
	if err != nil {
		return fmt.Errorf("Failed to ensure ClusterType is set: %s", err)
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
		ObjectMeta: metav1.ObjectMeta{
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

	// Ensure the IP Pool and System Network Policy TPRs exists.
	if err := c.ipPoolClient.EnsureInitialized(); err != nil {
		return err
	}
	if err := c.snpClient.EnsureInitialized(); err != nil {
		return err
	}

	return nil
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
	value := "KDD"

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
		if !strings.Contains(existingValue, "KDD") {
			existingValue = fmt.Sprintf("%s,KDD", existingValue)
		}
		value = existingValue
	}
	log.WithField("value", value).Debug("Setting ClusterType")
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

// buildTPRClientV1 builds a RESTClient configured to interact with Calico ThirdPartyResources
func buildTPRClientV1(cfg rest.Config) (*rest.RESTClient, error) {
	// Generate config using the base config.
	cfg.GroupVersion = &schema.GroupVersion{
		Group:   "projectcalico.org",
		Version: "v1",
	}
	cfg.APIPath = "/apis"
	cfg.ContentType = runtime.ContentTypeJSON
	cfg.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: clientapi.Codecs}

	cli, err := rest.RESTClientFor(&cfg)
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
			)
			return nil
		})
	schemeBuilder.AddToScheme(clientapi.Scheme)

	return cli, nil
}

// buildTPRClientV1alpha builds a RESTClient configured to interact with Calico ThirdPartyResources
func buildTPRClientV1alpha(cfg rest.Config) (*rest.RESTClient, error) {
	// Generate config using the base config.
	cfg.GroupVersion = &schema.GroupVersion{
		Group:   "alpha.projectcalico.org",
		Version: "v1",
	}
	cfg.APIPath = "/apis"
	cfg.ContentType = runtime.ContentTypeJSON
	cfg.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: clientapi.Codecs}

	cli, err := rest.RESTClientFor(&cfg)
	if err != nil {
		return nil, err
	}

	// We also need to register resources.
	schemeBuilder := runtime.NewSchemeBuilder(
		func(scheme *runtime.Scheme) error {
			scheme.AddKnownTypes(
				*cfg.GroupVersion,
				&thirdparty.SystemNetworkPolicy{},
				&thirdparty.SystemNetworkPolicyList{},
			)
			return nil
		})
	schemeBuilder.AddToScheme(clientapi.Scheme)

	return cli, nil
}

func (c *KubeClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return newSyncer(&realKubeAPI{c}, c.converter, callbacks, c.disableNodePoll)
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *KubeClient) Create(d *model.KVPair) (*model.KVPair, error) {
	log.Debugf("Performing 'Create' for %+v", d)
	switch d.Key.(type) {
	case model.GlobalConfigKey:
		return c.createGlobalConfig(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Create(d)
	case model.NodeKey:
		return c.nodeClient.Create(d)
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
	log.Debugf("Performing 'Update' for %+v", d)
	switch d.Key.(type) {
	case model.GlobalConfigKey:
		return c.updateGlobalConfig(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Update(d)
	case model.NodeKey:
		return c.nodeClient.Update(d)
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
		return c.applyGlobalConfig(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Apply(d)
	case model.NodeKey:
		return c.nodeClient.Apply(d)
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
func (c *KubeClient) Delete(d *model.KVPair) error {
	log.Debugf("Performing 'Delete' for %+v", d)
	switch d.Key.(type) {
	case model.GlobalConfigKey:
		return c.deleteGlobalConfig(d)
	case model.IPPoolKey:
		return c.ipPoolClient.Delete(d)
	case model.NodeKey:
		return c.nodeClient.Delete(d)
	default:
		log.Warn("Attempt to 'Delete' using kubernetes backend is not supported.")
		return errors.ErrorOperationNotSupported{
			Identifier: d.Key,
			Operation:  "Delete",
		}
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
	case model.NodeKey:
		return c.nodeClient.Get(k.(model.NodeKey))
	default:
		return nil, errors.ErrorOperationNotSupported{
			Identifier: k,
			Operation:  "Get",
		}
	}
}

// List entries in the datastore.  This may return an empty list if there are
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
		kvps, _, err := c.listGlobalConfig(l.(model.GlobalConfigListOptions))
		return kvps, err
	case model.HostConfigListOptions:
		return c.listHostConfig(l.(model.HostConfigListOptions))
	case model.IPPoolListOptions:
		return c.ipPoolClient.List(l.(model.IPPoolListOptions))
	case model.NodeListOptions:
		return c.nodeClient.List(l.(model.NodeListOptions))
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
	namespaces, err := c.clientSet.Namespaces().List(metav1.ListOptions{})
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
		return nil, fmt.Errorf("Profile key missing name: %+v", k)
	}
	namespaceName, err := c.converter.parseProfileName(k.Name)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Profile name: %s", err)
	}
	namespace, err := c.clientSet.Namespaces().Get(namespaceName, metav1.GetOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, k)
	}

	return c.converter.namespaceToProfile(namespace)
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
			switch err.(type) {
			// Return empty slice of KVPair if the object doesn't exist, return the error otherwise.
			case errors.ErrorResourceDoesNotExist:
				return []*model.KVPair{}, nil
			default:
				return nil, err
			}
		}

		return []*model.KVPair{kvp}, nil
	}

	// Otherwise, enumerate all pods in all namespaces.
	// We don't yet support hostname, orchestratorID, for the k8s backend.
	pods, err := c.clientSet.Pods("").List(metav1.ListOptions{})
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
	if !c.converter.isReadyCalicoPod(pod) {
		return nil, errors.ErrorResourceDoesNotExist{Identifier: k}
	}
	return c.converter.podToWorkloadEndpoint(pod)
}

// listPolicies lists the Policies from the k8s API based on NetworkPolicy objects.
func (c *KubeClient) listPolicies(l model.PolicyListOptions) ([]*model.KVPair, error) {
	if l.Name != "" {
		// Exact lookup on a NetworkPolicy.
		kvp, err := c.getPolicy(model.PolicyKey{Name: l.Name})
		if err != nil {
			switch err.(type) {
			// Return empty slice of KVPair if the object doesn't exist, return the error otherwise.
			case errors.ErrorResourceDoesNotExist:
				return []*model.KVPair{}, nil
			default:
				return nil, err
			}
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

	// List all System Network Policies.
	snps, err := c.snpClient.List(l)
	if err != nil {
		return nil, err
	}
	ret = append(ret, snps...)

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
	} else if strings.HasPrefix(k.Name, resources.SystemNetworkPolicyNamePrefix) {
		// This is backed by a System Network Policy TPR.
		return c.snpClient.Get(k)
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
	req := c.tprClientV1.Put().
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
	req := c.tprClientV1.Post().
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
	err := c.tprClientV1.Get().
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
func (c *KubeClient) listGlobalConfig(l model.GlobalConfigListOptions) ([]*model.KVPair, string, error) {
	cfgs := []*model.KVPair{}
	gcfg := thirdparty.GlobalConfigList{}
	resourceVersion := ""

	// Build the request.
	req := c.tprClientV1.Get().Resource("globalconfigs").Namespace("kube-system")
	if l.Name != "" {
		req.Name(strings.ToLower(l.Name))
	}

	// Perform the request.
	err := req.Do().Into(&gcfg)
	if err != nil {
		// Don't return errors for "not found".  This just
		// means there are no GlobalConfigs, and we should return
		// an empty list.
		if !kerrors.IsNotFound(err) {
			return nil, resourceVersion, resources.K8sErrorToCalico(err, l)
		}
	}
	resourceVersion = gcfg.Metadata.ResourceVersion

	// Convert them to KVPairs.
	for _, cfg := range gcfg.Items {
		cfgs = append(cfgs, c.converter.tprToGlobalConfig(&cfg))
	}

	return cfgs, resourceVersion, nil
}

// deleteGlobalConfig deletes the given global config.
func (c *KubeClient) deleteGlobalConfig(k *model.KVPair) error {
	result := c.tprClientV1.Delete().
		Resource("globalconfigs").
		Namespace("kube-system").
		Name(strings.ToLower(k.Key.(model.GlobalConfigKey).Name)).
		Do()
	return resources.K8sErrorToCalico(result.Error(), k.Key)
}

func (c *KubeClient) getHostConfig(k model.HostConfigKey) (*model.KVPair, error) {
	if k.Name == "IpInIpTunnelAddr" {
		n, err := c.clientSet.Nodes().Get(k.Hostname, metav1.GetOptions{})
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

func (c *KubeClient) listHostConfig(l model.HostConfigListOptions) ([]*model.KVPair, error) {
	var kvps = []*model.KVPair{}

	// Short circuit if they aren't asking for information we can provide.
	if l.Name != "" && l.Name != "IpInIpTunnelAddr" {
		return kvps, nil
	}

	// First see if we were handed a specific host, if not list all Nodes
	if l.Hostname == "" {
		nodes, err := c.clientSet.Nodes().List(metav1.ListOptions{})
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
		node, err := c.clientSet.Nodes().Get(l.Hostname, metav1.GetOptions{})
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, l)
		}

		kvp, err := getTunIp(node)
		if err != nil || kvp == nil {
			return []*model.KVPair{}, nil
		}

		kvps = append(kvps, kvp)
	}

	return kvps, nil
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
