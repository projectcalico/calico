// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package v3

import (
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// TestCELValidationThroughValidate verifies that the v3 Validate() function
// also runs CRD CEL validation rules. This ensures that etcd-mode clients
// get the same validation that Kubernetes enforces via x-kubernetes-validations.
func TestCELValidationThroughValidate(t *testing.T) {
	defaultOrder := apiv3.DefaultTierOrder
	kubeAdminOrder := apiv3.KubeAdminTierOrder

	tests := []struct {
		name      string
		tier      *apiv3.Tier
		expectErr bool
		errSubstr string
	}{
		{
			name: "default tier with Deny passes",
			tier: func() *apiv3.Tier {
				deny := apiv3.Deny
				return &apiv3.Tier{
					TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec:       apiv3.TierSpec{Order: &defaultOrder, DefaultAction: &deny},
				}
			}(),
			expectErr: false,
		},
		{
			name: "default tier with Pass fails CEL",
			tier: func() *apiv3.Tier {
				pass := apiv3.Pass
				return &apiv3.Tier{
					TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec:       apiv3.TierSpec{Order: &defaultOrder, DefaultAction: &pass},
				}
			}(),
			expectErr: true,
			errSubstr: "default",
		},
		{
			name: "kube-admin tier with Pass passes",
			tier: func() *apiv3.Tier {
				pass := apiv3.Pass
				return &apiv3.Tier{
					TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
					ObjectMeta: metav1.ObjectMeta{Name: "kube-admin"},
					Spec:       apiv3.TierSpec{Order: &kubeAdminOrder, DefaultAction: &pass},
				}
			}(),
			expectErr: false,
		},
		{
			name: "kube-admin tier with Deny fails CEL",
			tier: func() *apiv3.Tier {
				deny := apiv3.Deny
				return &apiv3.Tier{
					TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
					ObjectMeta: metav1.ObjectMeta{Name: "kube-admin"},
					Spec:       apiv3.TierSpec{Order: &kubeAdminOrder, DefaultAction: &deny},
				}
			}(),
			expectErr: true,
			errSubstr: "kube-admin",
		},
		{
			name: "custom tier with any action passes",
			tier: func() *apiv3.Tier {
				pass := apiv3.Pass
				order := float64(100)
				return &apiv3.Tier{
					TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
					ObjectMeta: metav1.ObjectMeta{Name: "my-tier"},
					Spec:       apiv3.TierSpec{Order: &order, DefaultAction: &pass},
				}
			}(),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.tier)
			if tt.expectErr {
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
				verr, ok := err.(errors.ErrorValidation)
				if !ok {
					t.Fatalf("expected ErrorValidation, got %T: %v", err, err)
				}
				// Verify that CEL error details are included.
				found := false
				for _, f := range verr.ErroredFields {
					if contains(f.Reason, tt.errSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, got: %v", tt.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			}
		})
	}
}

// TestCELAndStructValidationCombined verifies that both Go struct validation
// errors and CEL validation errors are reported together in a single ErrorValidation.
func TestCELAndStructValidationCombined(t *testing.T) {
	// Create a 'default' tier with wrong action (CEL error) AND wrong order (struct error).
	pass := apiv3.Pass
	wrongOrder := float64(999)
	tier := &apiv3.Tier{
		TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: &wrongOrder, DefaultAction: &pass},
	}

	err := Validate(tier)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	verr, ok := err.(errors.ErrorValidation)
	if !ok {
		t.Fatalf("expected ErrorValidation, got %T: %v", err, err)
	}

	// Should have at least 2 errors: one from struct validation (wrong order)
	// and one from CEL (wrong defaultAction for 'default' tier).
	if len(verr.ErroredFields) < 2 {
		t.Errorf("expected at least 2 errored fields (struct + CEL), got %d: %v", len(verr.ErroredFields), verr.ErroredFields)
	}

	// Verify we got the CEL error about the default tier.
	foundCEL := false
	for _, f := range verr.ErroredFields {
		if contains(f.Reason, "default") && contains(f.Reason, "Deny") {
			foundCEL = true
			break
		}
	}
	if !foundCEL {
		t.Errorf("expected CEL error about default tier needing Deny, got: %v", err)
	}

	t.Logf("Combined errors: %v", err)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
