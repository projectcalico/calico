// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	k8sbackend "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/typha/pkg/calc"
)

func NewK8sAPI(nc *calc.NodeCounter) *RealK8sAPI {
	return &RealK8sAPI{nodeCounter: nc}
}

type RealK8sAPI struct {
	cachedClientSet *kubernetes.Clientset
	nodeCounter     *calc.NodeCounter
}

func (r *RealK8sAPI) clientSet() (*kubernetes.Clientset, error) {
	if r.cachedClientSet == nil {
		// Build the clientset via the standard libcalico-go apiconfig path so we
		// honour the same environment configuration as Typha's datastore client
		// and the rest of Calico: KUBECONFIG, K8S_API_ENDPOINT, custom CA/cert/
		// token, and the K8S_INSECURE_SKIP_TLS_VERIFY option.  This avoids a
		// second, divergent way of building the Kubernetes client.
		apiCfg, err := apiconfig.LoadClientConfigFromEnvironment()
		if err != nil {
			log.WithError(err).Error("Unable to load Kubernetes API config.")
			return nil, err
		}
		_, clientSet, err := k8sbackend.CreateKubernetesClientset(&apiCfg.Spec)
		if err != nil {
			log.WithError(err).Error("Unable to create Kubernetes client set.")
			return nil, err
		}
		r.cachedClientSet = clientSet
	}
	return r.cachedClientSet, nil
}

func (r *RealK8sAPI) GetNumTyphas(ctx context.Context, namespace, serviceName, portName string) (int, error) {
	clientSet, err := r.clientSet()
	if err != nil {
		return 0, err
	}

	epSliceClient := clientSet.DiscoveryV1().EndpointSlices(namespace)
	epSlices, err := epSliceClient.List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + serviceName})
	if err != nil {
		log.WithError(err).Error("Failed to get Typha EndpointSlice from Kubernetes")
		return 0, err
	}

	ips := set.New[string]()
	for _, epSlice := range epSlices.Items {
		found := false
		for _, port := range epSlice.Ports {
			if port.Name != nil && *port.Name == portName {
				found = true
				break
			}
		}
		if found {
			for _, endpoint := range epSlice.Endpoints {
				for _, ip := range endpoint.Addresses {
					ips.Add(ip)
				}
			}
		}
	}
	return ips.Len(), nil
}

func (r *RealK8sAPI) GetNumNodes() (int, error) {
	return r.nodeCounter.GetNumNodes()
}

// Clientset returns the shared Kubernetes clientset, constructing it on first
// call.  Used by subsystems that need direct API access (e.g. leader election).
func (r *RealK8sAPI) Clientset() (*kubernetes.Clientset, error) {
	return r.clientSet()
}
