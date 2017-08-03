// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package main

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions"

	"github.com/projectcalico/felix/k8sfv/internalversion"
)

var nsPrefixNum = 0

func getNamespacePrefix() (nsPrefix string) {
	nsPrefixNum++
	nsPrefix = fmt.Sprintf("ns%d-", nsPrefixNum)
	return
}

type namespacePolicy struct {
	Ingress struct {
		Isolation string `json:"isolation"`
	} `json:"ingress"`
}

func createNamespace(clientset *kubernetes.Clientset, name string, labels map[string]string) {
	createNamespaceInt(clientset, name, labels, "")
}

func createIsolatedNamespace(clientset *kubernetes.Clientset, name string, labels map[string]string) {
	createNamespaceInt(clientset, name, labels, "DefaultDeny")
}

func createNamespaceInt(
	clientset *kubernetes.Clientset,
	name string,
	labels map[string]string,
	isolation string,
) {
	ns_in := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
	if isolation != "" {
		np := namespacePolicy{}
		np.Ingress.Isolation = isolation
		annotation, _ := json.Marshal(np)
		ns_in.ObjectMeta.Annotations = map[string]string{
			"net.beta.kubernetes.io/network-policy": string(annotation),
		}
	}
	log.WithField("ns_in", ns_in).Debug("Namespace defined")
	ns_out, err := clientset.Namespaces().Create(ns_in)
	if err != nil {
		panic(err)
	}
	log.WithField("ns_out", ns_out).Debug("Created namespace")
}

func cleanupAllNamespaces(clientset *kubernetes.Clientset, nsPrefix string) {
	log.Info("Cleaning up all namespaces...")
	nsList, err := clientset.Namespaces().List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nsList.Items)).Info("Namespaces present")
	for _, ns := range nsList.Items {
		if strings.HasPrefix(ns.ObjectMeta.Name, nsPrefix) {
			err = clientset.Namespaces().Delete(ns.ObjectMeta.Name, deleteImmediately)
			if err != nil {
				panic(err)
			}
		} else {
			log.WithField("name", ns.ObjectMeta.Name).Debug("Namespace skipped")
		}
	}
	log.Info("Cleaned up all namespaces")
}

// Create a NetworkPolicy, for pods in the specified namespace, that allows ingress from other pods
// in the same namespace.
func createNetworkPolicy(clientset *kubernetes.Clientset, namespace string) {
	npInterface := internalversion.NewNetworkPolicies(clientset.ExtensionsV1beta1Client, namespace)
	np := extensions.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "test-syncer-basic-net-policy",
		},
		Spec: extensions.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"calico/k8s_ns": namespace},
			},
			Ingress: []extensions.NetworkPolicyIngressRule{
				extensions.NetworkPolicyIngressRule{
					Ports: []extensions.NetworkPolicyPort{
						extensions.NetworkPolicyPort{},
					},
					From: []extensions.NetworkPolicyPeer{
						extensions.NetworkPolicyPeer{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"calico/k8s_ns": namespace,
								},
							},
						},
					},
				},
			},
		},
	}
	npInterface.Create(&np)
}
