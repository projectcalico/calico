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
	"fmt"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/libcalico-go/lib/set"
)

func NewK8sAPI() *RealK8sAPI {
	return &RealK8sAPI{}
}

type RealK8sAPI struct {
	cachedClientSet    *kubernetes.Clientset
	cachedNodeIndexer  cache.Indexer
	cachedNodeInformer cache.Controller
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

func (r *RealK8sAPI) nodeIndexer() (cache.Indexer, error) {
	if r.cachedNodeIndexer == nil {
		// Create an indexer for nodes that we can use to access resource counts without
		// going all the way to the API.
		clientSet, err := r.clientSet()
		if err != nil {
			return nil, err
		}

		nodeListWatcher := cache.NewListWatchFromClient(clientSet.CoreV1().RESTClient(), "nodes", metav1.NamespaceNone, fields.Everything())
		nodeIndexer, nodeInformer := cache.NewIndexerInformer(nodeListWatcher, &v1.Node{}, 0, cache.ResourceEventHandlerFuncs{}, cache.Indexers{})
		r.cachedNodeIndexer = nodeIndexer
		r.cachedNodeInformer = nodeInformer
	}

	// If the informer hasn't synced yet, return an error. We'll retry later.
	if !r.cachedNodeInformer.HasSynced() {
		return nil, fmt.Errorf("Node informer has not yet sync'd")
	}
	return r.cachedNodeIndexer, nil
}

func (r *RealK8sAPI) GetNumTyphas(namespace, serviceName, portName string) (int, error) {
	clientSet, err := r.clientSet()
	if err != nil {
		return 0, err
	}

	epClient := clientSet.CoreV1().Endpoints(namespace)
	ep, err := epClient.Get(serviceName, metav1.GetOptions{})
	if err != nil {
		log.WithError(err).Error("Failed to get Typha endpoint from Kubernetes")
	}

	ips := set.New()
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
	// Use the indexer's local store to get the number of nodes.
	indexer, err := r.nodeIndexer()
	if err != nil {
		return 0, err
	}
	return len(indexer.ListKeys()), nil
}
