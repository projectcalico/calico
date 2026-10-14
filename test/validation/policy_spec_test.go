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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// policyKinds builds the same ingress and egress rules into each policy kind
// that shares the Calico rule model.
func policyKinds(ingress, egress []v3.Rule) map[string]client.Object {
	return map[string]client.Object{
		"NetworkPolicy": &v3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
			Spec:       v3.NetworkPolicySpec{Ingress: ingress, Egress: egress},
		},
		"GlobalNetworkPolicy": &v3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gnp")},
			Spec:       v3.GlobalNetworkPolicySpec{Ingress: ingress, Egress: egress},
		},
		"StagedNetworkPolicy": &v3.StagedNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueName("snp"), Namespace: "default"},
			Spec:       v3.StagedNetworkPolicySpec{Ingress: ingress, Egress: egress},
		},
		"StagedGlobalNetworkPolicy": &v3.StagedGlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp")},
			Spec:       v3.StagedGlobalNetworkPolicySpec{Ingress: ingress, Egress: egress},
		},
	}
}

// A global policy has no namespace of its own to resolve a service name in.
func TestGlobalPolicy_ServicesNamespace(t *testing.T) {
	const wantErr = "services in a global policy must specify a namespace"
	named := &v3.ServiceMatch{Name: "my-svc", Namespace: "default"}
	bare := &v3.ServiceMatch{Name: "my-svc"}

	for _, tt := range []struct {
		name    string
		ingress []v3.Rule
		egress  []v3.Rule
		wantErr string
	}{
		{
			name:    "namespace set",
			ingress: []v3.Rule{{Action: v3.Allow, Source: v3.EntityRule{Services: named}}},
			egress:  []v3.Rule{{Action: v3.Allow, Destination: v3.EntityRule{Services: named}}},
		},
		{
			name:    "egress destination without namespace",
			egress:  []v3.Rule{{Action: v3.Allow, Destination: v3.EntityRule{Services: bare}}},
			wantErr: wantErr,
		},
		{
			name:    "ingress source without namespace",
			ingress: []v3.Rule{{Action: v3.Allow, Source: v3.EntityRule{Services: bare}}},
			wantErr: wantErr,
		},
	} {
		objs := policyKinds(tt.ingress, tt.egress)
		for _, kind := range []string{"GlobalNetworkPolicy", "StagedGlobalNetworkPolicy"} {
			t.Run(tt.name+" "+kind, func(t *testing.T) {
				if tt.wantErr != "" {
					expectCreateFails(t, objs[kind], tt.wantErr)
				} else {
					expectCreateSucceeds(t, objs[kind])
				}
			})
		}
	}

	// A namespaced policy falls back to its own namespace.
	expectCreateSucceeds(t, policyKinds([]v3.Rule{{Action: v3.Allow, Source: v3.EntityRule{Services: bare}}}, nil)["NetworkPolicy"])
}

// A service match names the far end of the connection, so it only makes sense
// as an egress destination or an ingress source.
func TestPolicy_ServicesDirection(t *testing.T) {
	svc := &v3.ServiceMatch{Name: "my-svc", Namespace: "default"}
	for _, tt := range []struct {
		name    string
		ingress []v3.Rule
		egress  []v3.Rule
		wantErr string
	}{
		{
			name:    "egress destination and ingress source",
			egress:  []v3.Rule{{Action: v3.Allow, Destination: v3.EntityRule{Services: svc}}},
			ingress: []v3.Rule{{Action: v3.Allow, Source: v3.EntityRule{Services: svc}}},
		},
		{
			name:    "egress source",
			egress:  []v3.Rule{{Action: v3.Allow, Source: v3.EntityRule{Services: svc}}},
			wantErr: "services are not allowed in an egress rule source",
		},
		{
			name:    "ingress destination",
			ingress: []v3.Rule{{Action: v3.Allow, Destination: v3.EntityRule{Services: svc}}},
			wantErr: "services are not allowed in an ingress rule destination",
		},
	} {
		for kind, obj := range policyKinds(tt.ingress, tt.egress) {
			t.Run(tt.name+" "+kind, func(t *testing.T) {
				if tt.wantErr != "" {
					expectCreateFails(t, obj, tt.wantErr)
				} else {
					expectCreateSucceeds(t, obj)
				}
			})
		}
	}
}
