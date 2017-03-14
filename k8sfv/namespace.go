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
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
)

var nsPrefixNum = 0

func getNamespacePrefix() (nsPrefix string) {
	nsPrefixNum++
	nsPrefix = fmt.Sprintf("ns%d-", nsPrefixNum)
	return
}

func createNamespace(clientset *kubernetes.Clientset, name string, labels map[string]string) {
	ns_in := &v1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
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
	nsList, err := clientset.Namespaces().List(v1.ListOptions{})
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
