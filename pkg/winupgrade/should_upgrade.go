// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
package winupgrade

import (
	"context"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/node/pkg/lifecycle/utils"

	log "github.com/sirupsen/logrus"
)

// Exit with code zero if Windows upgrade service should be installed.
func ShouldInstallUpgradeService() {
	version := getVersion()
	variant := getVariant()

	// Determine the name for this node.
	nodeName := utils.DetermineNodeName()
	log.Debugf("Check if Calico upgrade service should be installed on node: %s. Version: %s, Variant: %s, baseDir: %s", nodeName, version, variant, baseDir())

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile())
	if err != nil {
		log.WithError(err).Fatal("Failed to build Kubernetes client config")
		os.Exit(2)
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.WithError(err).Fatal("Failed to create Kubernetes client")
		os.Exit(2)
	}

	// Update annotations for running variant and version.
	node := k8snode(nodeName)
	err = node.addRemoveNodeAnnotations(clientSet,
		map[string]string{
			CalicoVersionAnnotation: version,
			CalicoVariantAnnotation: variant,
		},
		[]string{})
	if err != nil {
		log.WithError(err).Fatal("Failed to set version/variant annotations")
		os.Exit(2)
	}

	upgrade, _ := upgradeTriggered(context.Background(), clientSet, nodeName)
	if !upgrade {
		os.Exit(1)
	}
	os.Exit(0)
}
