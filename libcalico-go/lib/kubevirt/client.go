// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// This file provides utilities for creating KubeVirt clients.
package kubevirt

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"
)

// NewVirtClient creates a VirtClientInterface from a rest.Config.
func NewVirtClient(restConfig *rest.Config) (VirtClientInterface, error) {
	kvClient, err := kubevirtcorev1.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain KubeVirt client: %w", err)
	}
	return &virtClientAdapter{client: kvClient}, nil
}

// virtClientAdapter adapts the typed KubeVirt client to our VirtClientInterface.
type virtClientAdapter struct {
	client kubevirtcorev1.KubevirtV1Interface
}

func IsKubeVirtInstalled(discoveryClient discovery.DiscoveryInterface) (bool, error) {
	apiGroupList, err := discoveryClient.ServerGroups()
	if err != nil {
		log.Debugf("Cannot obtain API group list: %s", err)
		return false, err
	}

	for _, group := range apiGroupList.Groups {
		if group.Name == "kubevirt.io" {
			return true, nil
		}
	}

	log.Debugf("Kubevirt is not installed in the cluster")
	return false, nil
}

// VirtualMachineInstance implements VirtClientInterface.
func (v *virtClientAdapter) VirtualMachineInstance(namespace string) VMIInterface {
	return v.client.VirtualMachineInstances(namespace)
}

// VirtualMachine implements VirtClientInterface.
func (v *virtClientAdapter) VirtualMachine(namespace string) VMInterface {
	return v.client.VirtualMachines(namespace)
}

// VirtualMachineInstanceMigration implements VirtClientInterface.
func (v *virtClientAdapter) VirtualMachineInstanceMigration(namespace string) VMIMInterface {
	return v.client.VirtualMachineInstanceMigrations(namespace)
}

// tryCreateVirtClient attempts to create a KubeVirt client.
// Returns nil if KubeVirt is not available.
func TryCreateVirtClient(restConfig *rest.Config) (VirtClientInterface, error) {
	if restConfig == nil {
		log.Debug("No REST config provided.")
		return nil, fmt.Errorf("no REST config provided")
	}
	// Check if KubeVirt API group is available before attempting to create the client
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		log.WithError(err).Debug("Failed to create discovery client for kubevirt detection")
		return nil, err
	}
	isKubevirtInstalled, err := IsKubeVirtInstalled(discoveryClient)
	if err != nil {
		log.WithError(err).Warn("Failed to detect kubevirt installation, proceeding without KubeVirt support")
		return nil, nil
	}
	if !isKubevirtInstalled {
		return nil, nil
	}

	// Attempt to create a KubeVirt client from the REST config
	virtClient, err := NewVirtClient(restConfig)
	if err != nil {
		return nil, err
	}

	// Wrap the client with our interface adapter
	log.Info("Successfully created KubeVirt client")
	return virtClient, nil
}
