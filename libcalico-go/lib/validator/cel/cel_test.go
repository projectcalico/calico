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

package cel

import (
	"context"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidatorInit(t *testing.T) {
	// Verify that validators are loaded from embedded CRDs.
	kinds := ValidatorKinds()
	if len(kinds) == 0 {
		t.Fatal("expected at least one CEL validator to be compiled from embedded CRDs")
	}
	t.Logf("CEL validators compiled for kinds: %v", kinds)

	// Tier should have a validator (it has XValidation rules).
	if !HasValidator("Tier") {
		t.Fatal("expected Tier to have a CEL validator")
	}
}

func TestTierCELValidation_DefaultTierDeny(t *testing.T) {
	ctx := context.Background()
	deny := v3.Deny

	// The 'default' tier must have defaultAction 'Deny' - this should pass.
	tier := &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: v3.TierSpec{
			DefaultAction: &deny,
		},
	}

	errs := Validate(ctx, tier, nil)
	if len(errs) > 0 {
		t.Errorf("expected no validation errors for 'default' tier with Deny action, got: %v", errs)
	}
}

func TestTierCELValidation_DefaultTierWrongAction(t *testing.T) {
	ctx := context.Background()
	pass := v3.Pass

	// The 'default' tier must have defaultAction 'Deny' - Pass should fail.
	tier := &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: v3.TierSpec{
			DefaultAction: &pass,
		},
	}

	errs := Validate(ctx, tier, nil)
	if len(errs) == 0 {
		t.Error("expected validation error for 'default' tier with Pass action, got none")
	}
	t.Logf("Got expected errors: %v", errs)
}

func TestTierCELValidation_KubeAdminPass(t *testing.T) {
	ctx := context.Background()
	pass := v3.Pass

	// The 'kube-admin' tier must have defaultAction 'Pass' - this should pass.
	tier := &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-admin",
		},
		Spec: v3.TierSpec{
			DefaultAction: &pass,
		},
	}

	errs := Validate(ctx, tier, nil)
	if len(errs) > 0 {
		t.Errorf("expected no validation errors for 'kube-admin' tier with Pass action, got: %v", errs)
	}
}

func TestTierCELValidation_KubeAdminWrongAction(t *testing.T) {
	ctx := context.Background()
	deny := v3.Deny

	// The 'kube-admin' tier must have defaultAction 'Pass' - Deny should fail.
	tier := &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-admin",
		},
		Spec: v3.TierSpec{
			DefaultAction: &deny,
		},
	}

	errs := Validate(ctx, tier, nil)
	if len(errs) == 0 {
		t.Error("expected validation error for 'kube-admin' tier with Deny action, got none")
	}
	t.Logf("Got expected errors: %v", errs)
}

func TestTierCELValidation_KubeBaselinePass(t *testing.T) {
	ctx := context.Background()
	pass := v3.Pass

	// The 'kube-baseline' tier must have defaultAction 'Pass' - this should pass.
	tier := &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-baseline",
		},
		Spec: v3.TierSpec{
			DefaultAction: &pass,
		},
	}

	errs := Validate(ctx, tier, nil)
	if len(errs) > 0 {
		t.Errorf("expected no validation errors for 'kube-baseline' tier with Pass action, got: %v", errs)
	}
}

func TestTierCELValidation_CustomTierAnyAction(t *testing.T) {
	ctx := context.Background()
	deny := v3.Deny

	// A custom tier (not default/kube-admin/kube-baseline) can have any action.
	tier := &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-custom-tier",
		},
		Spec: v3.TierSpec{
			DefaultAction: &deny,
		},
	}

	errs := Validate(ctx, tier, nil)
	if len(errs) > 0 {
		t.Errorf("expected no validation errors for custom tier, got: %v", errs)
	}
}

func TestNoValidatorForUnknownKind(t *testing.T) {
	if HasValidator("NonExistentKind") {
		t.Error("expected no validator for unknown kind")
	}
}

func TestValidateNilOldObj(t *testing.T) {
	ctx := context.Background()
	deny := v3.Deny

	// Create validation (nil oldObj) should work.
	tier := &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: v3.TierSpec{
			DefaultAction: &deny,
		},
	}

	errs := Validate(ctx, tier, nil)
	if len(errs) > 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateEmptyKind(t *testing.T) {
	ctx := context.Background()
	deny := v3.Deny

	// Object with no Kind set should return nil (no validation).
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: v3.TierSpec{
			DefaultAction: &deny,
		},
	}

	errs := Validate(ctx, tier, nil)
	if len(errs) > 0 {
		t.Errorf("expected no errors for object without Kind, got: %v", errs)
	}
}
