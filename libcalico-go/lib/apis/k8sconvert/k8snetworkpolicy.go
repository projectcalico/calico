// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package k8sconvert

import (
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var VersionK8sNetworkingV1 = "networking.k8s.io/v1"

type K8sNetworkPolicy struct {
	unversioned.TypeMetadata
	Metadata K8sNetworkPolicyMetadata       `json:"metadata,omitempty"`
	Spec     networkingv1.NetworkPolicySpec `json:"spec,omitempty"`
}

func NewK8sNetworkPolicy() *K8sNetworkPolicy {
	return &K8sNetworkPolicy{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "NetworkPolicy",
			APIVersion: VersionK8sNetworkingV1,
		},
	}
}

type K8sNetworkPolicyMetadata struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}
