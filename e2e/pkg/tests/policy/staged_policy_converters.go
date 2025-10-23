// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package policy

import (
	"github.com/jinzhu/copier"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConvertStagedPolicyToEnforced converts a StagedNetworkPolicy into a StagedAction, NetworkPolicy pair
func ConvertStagedPolicyToEnforced(staged *v3.StagedNetworkPolicy) (v3.StagedAction, *v3.NetworkPolicy) {
	// Convert StagedNetworkPolicy to NetworkPolicy
	enforced := v3.NewNetworkPolicy()
	_ = copier.Copy(&enforced.ObjectMeta, &staged.ObjectMeta)
	_ = copier.Copy(&enforced.Spec, &staged.Spec)

	// Clear fields that should not be copied onto new objects.
	enforced.ResourceVersion = ""
	enforced.UID = ""

	return staged.Spec.StagedAction, enforced
}

// ConvertStagedGlobalPolicyToEnforced converts a StagedGlobalNetworkPolicy into a StagedAction, GlobalNetworkPolicy pair
func ConvertStagedGlobalPolicyToEnforced(staged *v3.StagedGlobalNetworkPolicy) (v3.StagedAction, *v3.GlobalNetworkPolicy) {
	enforced := v3.NewGlobalNetworkPolicy()
	_ = copier.Copy(&enforced.ObjectMeta, &staged.ObjectMeta)
	_ = copier.Copy(&enforced.Spec, &staged.Spec)

	// Clear fields that should not be copied onto new objects.
	enforced.ResourceVersion = ""
	enforced.UID = ""

	return staged.Spec.StagedAction, enforced
}

// ConvertStagedKubernetesPolicyToK8SEnforced converts a StagedKubernetesNetworkPolicy into a StagedAction, networkingv1 NetworkPolicy pair
func ConvertStagedKubernetesPolicyToK8SEnforced(staged *v3.StagedKubernetesNetworkPolicy) (v3.StagedAction, *networkingv1.NetworkPolicy) {
	// Convert StagedKubernetesNetworkPolicy to networkingv1.NetworkPolicy
	enforced := networkingv1.NetworkPolicy{}
	_ = copier.Copy(&enforced.ObjectMeta, &staged.ObjectMeta)
	_ = copier.Copy(&enforced.Spec, &staged.Spec)
	enforced.TypeMeta = metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}

	// Clear fields that should not be copied onto new objects.
	enforced.ResourceVersion = ""
	enforced.UID = ""

	return staged.Spec.StagedAction, &enforced
}
