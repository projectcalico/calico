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
	"math/rand"
	"sync"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/pkg/api/v1"
)

type host struct {
	name    string
	isLocal bool
}

type deployment interface {
	ChooseHost(clientset *kubernetes.Clientset) host
}

type localPlusRemotes struct {
	numLocal      int
	numRemotes    int
	remotePrefix  string
	localHostname string
	k8sCreated    map[string]bool
	mutex         sync.Mutex
}

func NewDeployment(
	clientset *kubernetes.Clientset,
	numRemotes int,
	includeLocal bool,
) deployment {
	numLocal := 0
	if includeLocal {
		numLocal = 1
	}
	d := &localPlusRemotes{
		numLocal:     numLocal,
		numRemotes:   numRemotes,
		remotePrefix: "remote-host-",
		k8sCreated:   map[string]bool{},
	}
	if includeLocal {
		d.localHostname = felixHostname
	}
	// Regardless of whether we're going to place _pods_ on the local host, we need to define a
	// Node resource for the local host, so that Felix can get going.
	d.ensureNodeDefined(clientset, felixHostname, felixIP+"/24")
	localFelixConfigured = true
	return d
}

var GetNextRemoteHostCIDR = ipAddrAllocator("11.65.%d.%d/16")

func (d *localPlusRemotes) ensureNodeDefined(
	clientset *kubernetes.Clientset,
	hostName string,
	hostCIDR string,
) {
	d.mutex.Lock()
	if !d.k8sCreated[hostName] {
		if hostCIDR == "" {
			hostCIDR = GetNextRemoteHostCIDR()
		}
		node_in := &v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: hostName,
				Annotations: map[string]string{
					"projectcalico.org/IPv4Address": hostCIDR,
				},
			},
			Spec: v1.NodeSpec{},
		}
		log.WithField("node_in", node_in).Debug("Node defined")
		node_out, err := clientset.Nodes().Create(node_in)
		log.WithField("node_out", node_out).Debug("Created node")
		if err != nil {
			panic(err)
		}
		d.k8sCreated[hostName] = true
	}
	d.mutex.Unlock()
}

func (d *localPlusRemotes) ChooseHost(clientset *kubernetes.Clientset) (h host) {
	r := rand.Intn(d.numLocal + d.numRemotes)
	if r < d.numLocal {
		h = host{name: d.localHostname, isLocal: true}
	} else {
		h = host{name: fmt.Sprintf("%s%d", d.remotePrefix, r), isLocal: false}
	}
	d.ensureNodeDefined(clientset, h.name, "")
	return
}

func cleanupAllNodes(clientset *kubernetes.Clientset) {
	log.Info("Cleaning up all nodes...")
	nodeList, err := clientset.Nodes().List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	log.WithField("count", len(nodeList.Items)).Info("Nodes present")
	for _, node := range nodeList.Items {
		err = clientset.Nodes().Delete(node.ObjectMeta.Name, deleteImmediately)
		if err != nil {
			panic(err)
		}
	}
	log.Info("Cleaned up all nodes")
	localFelixConfigured = false
}
