// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

// Package k8sclient builds Kubernetes and KubeVirt clients from a CNI network config, for
// both the calico plugin and calico-ipam.
package k8sclient

import (
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

// configOverride is one network config value that, when set, overrides a kubeconfig field.
type configOverride struct {
	variable *string
	value    string
}

// restConfig creates a Kubernetes REST config from the CNI network configuration.
// This helper function builds the config with kubeconfig file and overrides from the network config.
func restConfig(conf types.NetConf) (*rest.Config, error) {
	// Some config can be passed in a kubeconfig file
	kubeconfig := conf.Kubernetes.Kubeconfig

	// Config can be overridden by config passed in explicitly in the network config.
	configOverrides := &clientcmd.ConfigOverrides{}

	// Earlier versions of the config gave the API root as a full URL ending in `/api/v1/`,
	// so keep only the host and port.
	conf.Policy.K8sAPIRoot = strings.Split(conf.Policy.K8sAPIRoot, "/api/")[0]

	overridesMap := []configOverride{
		{&configOverrides.ClusterInfo.Server, conf.Policy.K8sAPIRoot},
		{&configOverrides.AuthInfo.ClientCertificate, conf.Policy.K8sClientCertificate},
		{&configOverrides.AuthInfo.ClientKey, conf.Policy.K8sClientKey},
		{&configOverrides.ClusterInfo.CertificateAuthority, conf.Policy.K8sCertificateAuthority},
		{&configOverrides.AuthInfo.Token, conf.Policy.K8sAuthToken},
	}

	// Using the override map above, populate any non-empty values.
	for _, override := range overridesMap {
		if override.value != "" {
			*override.variable = override.value
		}
	}

	// Also allow the K8sAPIRoot to appear under the "kubernetes" block in the network config.
	if conf.Kubernetes.K8sAPIRoot != "" {
		configOverrides.ClusterInfo.Server = conf.Kubernetes.K8sAPIRoot
	}

	// Use the kubernetes client code to load the kubeconfig file and combine it with the overrides.
	return winutils.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		configOverrides)
}

// New creates a Kubernetes clientset from the CNI network configuration's kubeconfig and
// any API server, certificate and token overrides it sets.
func New(conf types.NetConf, logger *logrus.Entry) (*kubernetes.Clientset, error) {
	// Get the Kubernetes REST config
	config, err := restConfig(conf)
	if err != nil {
		return nil, err
	}

	// Create the clientset
	return kubernetes.NewForConfig(config)
}

// NewKubeVirt creates a KubeVirt client from the CNI network configuration.
// Note: This will return an error if KubeVirt is not installed in the cluster.
func NewKubeVirt(conf types.NetConf, logger *logrus.Entry) (kubevirt.VirtClientInterface, error) {
	// Get the Kubernetes REST config
	config, err := restConfig(conf)
	if err != nil {
		return nil, err
	}

	// Create KubeVirt client
	return kubevirt.NewVirtClient(config)
}
