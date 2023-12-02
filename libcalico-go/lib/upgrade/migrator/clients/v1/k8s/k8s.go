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

package k8s

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Import all auth providers.
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	capi "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients/v1/k8s/custom"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients/v1/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

type KubeClient struct {
	// Main Kubernetes clients.
	clientSet *kubernetes.Clientset

	// Client for interacting with CustomResourceDefinition.
	crdClientV1 *rest.RESTClient

	// Clients for interacting with Calico resources.
	nodeBgpPeerClient       resources.K8sResourceClient
	globalBgpConfigClient   resources.K8sResourceClient
	globalFelixConfigClient resources.K8sResourceClient
}

func NewKubeClient(kc *capi.KubeConfig) (*KubeClient, error) {
	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
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

	// A kubeconfig file was provided.  Use it to load a config, passing through
	// any overrides.
	var config *rest.Config
	var err error
	if winutils.InHostProcessContainer() {
		// ClientConfig() calls InClusterConfig() at some point, which doesn't work
		// on Windows HPC. Use winutils.GetInClusterConfig() instead in this case.
		// FIXME: this will no longer be needed when containerd v1.6 is EOL'd
		config, err = winutils.GetInClusterConfig()
	} else {
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&loadingRules, configOverrides).ClientConfig()
	}
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
		return nil, fmt.Errorf("failed to build V1 CRD client: %s", err)
	}

	kubeClient := &KubeClient{
		clientSet:   cs,
		crdClientV1: crdClientV1,
	}

	// Create the Calico sub-clients.
	kubeClient.nodeBgpPeerClient = resources.NewNodeBGPPeerClient(cs)
	kubeClient.globalBgpConfigClient = resources.NewGlobalBGPConfigClient(cs, crdClientV1)
	kubeClient.globalFelixConfigClient = resources.NewGlobalFelixConfigClient(cs, crdClientV1)

	return kubeClient, nil
}

func (c *KubeClient) IsKDD() bool {
	return true
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
	cfg.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs}

	cli, err := rest.RESTClientFor(&cfg)
	if err != nil {
		return nil, err
	}

	// We also need to register resources.
	schemeBuilder := runtime.NewSchemeBuilder(
		func(scheme *runtime.Scheme) error {
			scheme.AddKnownTypes(
				*cfg.GroupVersion,
				&custom.GlobalFelixConfig{},
				&custom.GlobalFelixConfigList{},
				&custom.GlobalBGPConfig{},
				&custom.GlobalBGPConfigList{},
			)
			return nil
		})

	schemeBuilder.AddToScheme(scheme.Scheme)

	return cli, nil
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist. (Not implemented for KDD.)
func (c *KubeClient) Update(d *model.KVPair) (*model.KVPair, error) {
	log.Warn("Attempt to 'Update' using kubernetes backend is not supported.")
	return nil, errors.ErrorOperationNotSupported{
		Identifier: d.Key,
		Operation:  "Update",
	}
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *KubeClient) Apply(d *model.KVPair) (*model.KVPair, error) {
	log.Warn("Attempt to 'Apply' using kubernetes backend is not supported.")
	return nil, errors.ErrorOperationNotSupported{
		Identifier: d.Key,
		Operation:  "Apply",
	}
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *KubeClient) Get(k model.Key) (*model.KVPair, error) {
	log.Debugf("Performing 'Get' for %+v", k)
	switch k.(type) {
	case model.GlobalConfigKey:
		return c.globalFelixConfigClient.Get(k)
	case model.NodeBGPPeerKey:
		return c.nodeBgpPeerClient.Get(k)
	case model.GlobalBGPConfigKey:
		return c.globalBgpConfigClient.Get(k)
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
	case model.NodeBGPPeerListOptions:
		k, _, err := c.nodeBgpPeerClient.List(l)
		return k, err
	case model.GlobalConfigListOptions:
		k, _, err := c.globalFelixConfigClient.List(l)
		return k, err
	case model.GlobalBGPConfigListOptions:
		k, _, err := c.globalBgpConfigClient.List(l)
		return k, err
	default:
		return nil, errors.ErrorOperationNotSupported{
			Identifier: l,
			Operation:  "List",
		}
	}
}
