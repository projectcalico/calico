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
	log "github.com/Sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	capi "github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/libcalico-go/lib/client"
)

func initialize(k8sServerEndpoint string) (clientset *kubernetes.Clientset) {

	initializeCalicoDeployment(k8sServerEndpoint)

	config, err := clientcmd.NewNonInteractiveClientConfig(*api.NewConfig(),
		"",
		&clientcmd.ConfigOverrides{
			ClusterDefaults: api.Cluster{
				Server:                k8sServerEndpoint,
				InsecureSkipTLSVerify: true,
			},
		},
		clientcmd.NewDefaultClientConfigLoadingRules()).ClientConfig()
	if err != nil {
		panic(err)
	}

	config.QPS = 10000
	config.Burst = 20000
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	return
}

func initializeCalicoDeployment(k8sServerEndpoint string) {
	// Create client into the Kubernetes datastore.
	c, err := client.New(capi.CalicoAPIConfig{
		Spec: capi.CalicoAPIConfigSpec{
			DatastoreType: capi.Kubernetes,
			KubeConfig: k8s.KubeConfig{
				K8sAPIEndpoint:           k8sServerEndpoint,
				K8sInsecureSkipTLSVerify: true,
			},
		},
	})
	if err != nil {
		panic(err)
	}

	// Establish the other global config that Calico requires.
	err = c.EnsureInitialized()
	if err != nil {
		panic(err)
	}
}

func create1000Pods(clientset *kubernetes.Clientset, nsPrefix string) error {

	d := NewDeployment(49, true)
	nsName := nsPrefix + "test"

	// Create 1000 pods.
	createNamespace(clientset, nsName, nil)
	log.Info("Creating pods:")
	for i := 0; i < 1000; i++ {
		createPod(clientset, d, nsName, podSpec{})
	}
	log.Info("Done")

	return nil
}

func cleanupAll(clientset *kubernetes.Clientset, nsPrefix string) {
	cleanupAllPods(clientset, nsPrefix)
	cleanupAllNodes(clientset)
	cleanupAllNamespaces(clientset, nsPrefix)
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
	return
}
