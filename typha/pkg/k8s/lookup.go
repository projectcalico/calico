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
	"k8s.io/client-go/rest"

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
		// TODO Typha: support Typha lookup without using rest.InClusterConfig().
		k8sconf, err := rest.InClusterConfig()
		if err != nil {
			log.WithError(err).Error("Unable to create Kubernetes config.")
			return nil, err
		}
		clientSet, err := kubernetes.NewForConfig(k8sconf)
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

	epClient := clientSet.CoreV1().Endpoints(namespace)
	ep, err := epClient.Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		log.WithError(err).Error("Failed to get Typha endpoint from Kubernetes")
		return 0, err
	}

	ips := set.New[string]()
	for _, s := range ep.Subsets {
		found := false
		for _, port := range s.Ports {
			if port.Name == portName {
				found = true
				break
			}
		}
		if found {
			for _, ip := range s.Addresses {
				ips.Add(ip.IP)
			}
		}
	}
	return ips.Len(), nil
}

func (r *RealK8sAPI) GetNumNodes() (int, error) {
	return r.nodeCounter.GetNumNodes()
}
