// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package shutdown

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"
)

// This file contains the main shutdown processing for the calico/node.  This
// includes:
// -  Save time stamp to shutdown file.
// -  Set node condition to "networkUnavailable=true"
func Run() {
	// Save shutdown timestamp immediately.
	// Depends on how we configure termination grace period,
	// the shutdown process can be killed at any given time.
	if err := utils.SaveShutdownTimestamp(); err != nil {
		log.WithError(err).Errorf("Unable to save shutdown timestamp")
	}

	// Determine the name for this node.
	nodeName := utils.DetermineNodeName()
	log.Infof("Shutting down node %s", nodeName)

	var clientset *kubernetes.Clientset

	// If running under kubernetes with secrets to call k8s API
	if config, err := rest.InClusterConfig(); err == nil {
		// default timeout is 30 seconds, which isn't appropriate for this kind of
		// shutdown action because network services, like kube-proxy might not be
		// running and we don't want to block the full 30 seconds if they are just
		// a few seconds behind.
		config.Timeout = 2 * time.Second

		// Create the k8s clientset.
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			log.WithError(err).Error("Failed to create clientset")
			return
		}
	}

	// If Calico is running in policy only mode we don't need to set node conditions.
	if os.Getenv("CALICO_NETWORKING_BACKEND") != "none" {
		if clientset != nil {
			// Determine the Kubernetes node name. Default to the Calico node name unless an explicit
			// value is provided.
			k8sNodeName := nodeName
			if nodeRef := os.Getenv("CALICO_K8S_NODE_REF"); nodeRef != "" {
				k8sNodeName = nodeRef
			}

			hundredYears := 876600 * time.Hour
			// Set node condition with a big timeout value (100 years).
			// The maximum execution time for the shutdown process is defined by terminationGracePeriod of calico-node.
			// Depends on how we configure terminationGracePeriod (currently 5 seconds with operator install),
			// this operation may not be successful if it takes too long to update node condition.
			err := utils.SetNodeNetworkUnavailableCondition(*clientset, k8sNodeName, true, hundredYears)
			if err != nil {
				log.WithError(err).Error("Unable to set NetworkUnavailable to true")
				return
			}
		}
	}
}
