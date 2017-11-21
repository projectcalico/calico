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
	"k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
	ns_out, err := clientset.CoreV1().Namespaces().Create(ns_in)
	if err != nil {
		panic(err)
	}
	log.WithField("ns_out", ns_out).Debug("Created namespace")
}

func cleanupAllNamespaces(clientset *kubernetes.Clientset, nsPrefix string) {
	log.Info("Cleaning up all namespaces...")
	nsList, err := clientset.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nsList.Items)).Info("Namespaces present")
	for _, ns := range nsList.Items {
		if strings.HasPrefix(ns.ObjectMeta.Name, nsPrefix) {
			err = clientset.CoreV1().Namespaces().Delete(ns.ObjectMeta.Name, deleteImmediately)
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
	np := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "test-syncer-basic-net-policy",
		},
		Spec: networkingv1.NetworkPolicySpec{
			// An empty PodSelector selects all pods in this Namespace.
			PodSelector: metav1.LabelSelector{},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				networkingv1.NetworkPolicyIngressRule{
					From: []networkingv1.NetworkPolicyPeer{
						networkingv1.NetworkPolicyPeer{
							// An empty PodSelector selects all pods in this Namespace.
							PodSelector: &metav1.LabelSelector{},
						},
					},
				},
			},
		},
	}
	clientset.NetworkingV1().NetworkPolicies("").Create(&np)
}
