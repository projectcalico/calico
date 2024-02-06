// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1beta1"
)

type RestClient struct {
	RestConfig            *rest.Config
	Clientset             kubernetes.Interface
	APIRegistrationClient v1beta1.ApiregistrationV1beta1Interface
}

// GetRestClient returns a bundle of K8s REST client interfaces.
func NewRestClient() (*RestClient, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	apiClient, err := v1beta1.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return &RestClient{
		RestConfig:            restConfig,
		Clientset:             clientset,
		APIRegistrationClient: apiClient,
	}, nil
}
