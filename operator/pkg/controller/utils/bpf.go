// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
)

type BPFBootstrap struct {
	K8sService          *corev1.Service
	K8sServiceEndpoints *discoveryv1.EndpointSliceList
}

// BPFBootstrapRequirements checks whether the BPF auto-bootstrap requirements are met.
// If so, it retrieves the kube-proxy DaemonSet, the Kubernetes service, and its EndpointSlices, returning them in a BPFBootstrap struct.
// If it's not possible to retrieve any of these resources, it returns an error.
func BPFBootstrapRequirements(ctx context.Context, c client.Client, install *operator.InstallationSpec) (*BPFBootstrap, error) {
	// If BPFNetworkBootstrap is not Enabled, skip further processing.
	if !install.BPFNetworkBootstrapEnabled() {
		return nil, nil
	}

	// 1. If BPFNetworkBootstrap is enabled, linuxDataplane must be BPF.
	if !install.BPFEnabled() {
		return nil, fmt.Errorf("bpfNetworkBootstrap is enabled but linuxDataplane is not set to BPF")
	}

	// 2. kubernetes service endpoint shouldn't be defined by kubernetes-service-endpoints ConfigMap.
	_, err := GetK8sServiceEndPoint(c)
	if err == nil {
		return nil, fmt.Errorf("kubernetes service endpoint is defined by the kubernetes-service-endpoints ConfigMap")
	}

	bpfBootstrapReq := &BPFBootstrap{}
	// 3. Try to retrieve kubernetes service.
	service := &corev1.Service{}
	err = c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubernetes"}, service)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes service: %w", err)
	}
	bpfBootstrapReq.K8sService = service

	// 4. Try to retrieve kubernetes service endpoint slices. If the cluster is dual-stack, there should be at least one EndpointSlice for each address type.
	endpointSlice := &discoveryv1.EndpointSliceList{}
	err = c.List(ctx, endpointSlice, client.InNamespace("default"), client.MatchingLabels{"kubernetes.io/service-name": "kubernetes"})
	if err != nil || len(endpointSlice.Items) == 0 {
		return nil, fmt.Errorf("failed to get kubernetes endpoint slices: %w", err)
	}
	bpfBootstrapReq.K8sServiceEndpoints = endpointSlice

	return bpfBootstrapReq, nil
}
