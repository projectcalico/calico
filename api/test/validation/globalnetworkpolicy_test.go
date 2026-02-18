// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"context"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestGlobalNetworkPolicy_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "doNotTrack and preDNAT both true is rejected",
			obj: &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gnp")},
				Spec: v3.GlobalNetworkPolicySpec{
					DoNotTrack:     true,
					PreDNAT:        true,
					ApplyOnForward: true,
				},
			},
			wantErr: "preDNAT and doNotTrack cannot both be true",
		},
		{
			name: "preDNAT with egress rules is rejected",
			obj: &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gnp")},
				Spec: v3.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Egress: []v3.Rule{
						{Action: v3.Allow},
					},
				},
			},
			wantErr: "preDNAT policy cannot have any egress rules",
		},
		{
			name: "preDNAT with Egress type is rejected",
			obj: &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gnp")},
				Spec: v3.GlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Types:          []v3.PolicyType{v3.PolicyTypeEgress},
				},
			},
			wantErr: "preDNAT policy cannot have 'Egress' type",
		},
		{
			name: "doNotTrack with applyOnForward=false is rejected",
			obj: &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gnp")},
				Spec: v3.GlobalNetworkPolicySpec{
					DoNotTrack:     true,
					ApplyOnForward: false,
				},
			},
			wantErr: "applyOnForward must be true if either preDNAT or doNotTrack is true",
		},
		{
			name: "doNotTrack with applyOnForward=true is accepted",
			obj: &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gnp")},
				Spec: v3.GlobalNetworkPolicySpec{
					DoNotTrack:     true,
					ApplyOnForward: true,
					Ingress: []v3.Rule{
						{Action: v3.Allow},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestGlobalNetworkPolicy_Defaults(t *testing.T) {
	gnp := &v3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gnp-dflt")},
		Spec: v3.GlobalNetworkPolicySpec{
			Ingress: []v3.Rule{
				{Action: v3.Allow},
			},
		},
	}
	mustCreate(t, gnp)

	got := &v3.GlobalNetworkPolicy{}
	if err := testClient.Get(context.Background(), client.ObjectKeyFromObject(gnp), got); err != nil {
		t.Fatalf("failed to get gnp: %v", err)
	}
	if got.Spec.Tier != "default" {
		t.Fatalf("expected tier to default to %q, got %q", "default", got.Spec.Tier)
	}
}

func TestStagedGlobalNetworkPolicy_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "doNotTrack and preDNAT both true is rejected",
			obj: &v3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp")},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					DoNotTrack:     true,
					PreDNAT:        true,
					ApplyOnForward: true,
				},
			},
			wantErr: "preDNAT and doNotTrack cannot both be true",
		},
		{
			name: "preDNAT with egress rules is rejected",
			obj: &v3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp")},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Egress: []v3.Rule{
						{Action: v3.Allow},
					},
				},
			},
			wantErr: "preDNAT policy cannot have any egress rules",
		},
		{
			name: "preDNAT with Egress type is rejected",
			obj: &v3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp")},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					PreDNAT:        true,
					ApplyOnForward: true,
					Types:          []v3.PolicyType{v3.PolicyTypeEgress},
				},
			},
			wantErr: "preDNAT policy cannot have 'Egress' type",
		},
		{
			name: "doNotTrack with applyOnForward=false is rejected",
			obj: &v3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp")},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					DoNotTrack:     true,
					ApplyOnForward: false,
				},
			},
			wantErr: "applyOnForward must be true if either preDNAT or doNotTrack is true",
		},
		{
			name: "doNotTrack with applyOnForward=true is accepted",
			obj: &v3.StagedGlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("sgnp")},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					DoNotTrack:     true,
					ApplyOnForward: true,
					Ingress: []v3.Rule{
						{Action: v3.Allow},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}
