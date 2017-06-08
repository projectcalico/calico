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
	"errors"

	log "github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/typha/pkg/set"
)

var ErrServiceNotReady = errors.New("service not ready")

func GetNumTyphas(namespace, serviceName, portName string) (int, error) {
	// If we get here, we need to look up the Typha service using the k8s API.
	// TODO Typha: support Typha lookup without using rest.InClusterConfig().
	k8sconf, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes config.")
		return 0, err
	}
	clientset, err := kubernetes.NewForConfig(k8sconf)
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes client set.")
		return 0, err
	}

	epClient := clientset.CoreV1().Endpoints(namespace)
	ep, err := epClient.Get(serviceName, v1.GetOptions{})
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

func GetNumNodes() (int, error) {
	// If we get here, we need to look up the Typha service using the k8s API.
	// TODO Typha: support Typha lookup without using rest.InClusterConfig().
	k8sconf, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes config.")
		return 0, err
	}
	clientset, err := kubernetes.NewForConfig(k8sconf)
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes client set.")
		return 0, err
	}

	noClient := clientset.CoreV1().Nodes()
	list, err := noClient.List(v1.ListOptions{})
	if err != nil {
		return 0, err
	}
	return len(list.Items), nil
}
