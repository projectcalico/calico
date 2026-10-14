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

package validation_test

import (
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A staged delete names the policy it would remove, so any policy content in it
// is ignored and almost certainly a mistake. Types are exempt because an
// admission policy fills them in.
func TestStagedPolicy_DeleteHasEmptySpec(t *testing.T) {
	const (
		wantCalico = "spec fields other than tier must be empty when stagedAction is Delete"
		wantK8s    = "spec fields must be empty when stagedAction is Delete"
	)
	for _, tt := range []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "StagedNetworkPolicy delete with only a tier",
			obj: &v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("snp"), Namespace: "default"},
				Spec:       v3.StagedNetworkPolicySpec{StagedAction: v3.StagedActionDelete, Tier: "default"},
			},
		},
		{
			name: "StagedNetworkPolicy delete with a selector",
			obj: &v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("snp"), Namespace: "default"},
				Spec:       v3.StagedNetworkPolicySpec{StagedAction: v3.StagedActionDelete, Selector: "all()"},
			},
			wantErr: wantCalico,
		},
		{
			name: "StagedNetworkPolicy set with a selector",
			obj: &v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("snp"), Namespace: "default"},
				Spec:       v3.StagedNetworkPolicySpec{StagedAction: v3.StagedActionSet, Selector: "all()"},
			},
		},
		{
			name: "StagedGlobalNetworkPolicy delete with an order",
			obj: &v3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp")},
				Spec:       v3.StagedGlobalNetworkPolicySpec{StagedAction: v3.StagedActionDelete, Order: ptr.To(10.0)},
			},
			wantErr: wantCalico,
		},
		{
			name: "StagedGlobalNetworkPolicy delete with applyOnForward",
			obj: &v3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp")},
				Spec:       v3.StagedGlobalNetworkPolicySpec{StagedAction: v3.StagedActionDelete, ApplyOnForward: true},
			},
			wantErr: wantCalico,
		},
		{
			name: "StagedKubernetesNetworkPolicy delete with an empty spec",
			obj: &v3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sknp"), Namespace: "default"},
				Spec:       v3.StagedKubernetesNetworkPolicySpec{StagedAction: v3.StagedActionDelete},
			},
		},
		{
			name: "StagedKubernetesNetworkPolicy delete with a pod selector",
			obj: &v3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sknp"), Namespace: "default"},
				Spec: v3.StagedKubernetesNetworkPolicySpec{
					StagedAction: v3.StagedActionDelete,
					PodSelector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				},
			},
			wantErr: wantK8s,
		},
		{
			name: "StagedKubernetesNetworkPolicy delete with an ingress rule",
			obj: &v3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sknp"), Namespace: "default"},
				Spec: v3.StagedKubernetesNetworkPolicySpec{
					StagedAction: v3.StagedActionDelete,
					Ingress:      []networkingv1.NetworkPolicyIngressRule{{}},
				},
			},
			wantErr: wantK8s,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}
