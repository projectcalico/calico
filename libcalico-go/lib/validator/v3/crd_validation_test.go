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
	"strings"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// crdTestCase defines a single CRD validation test. Each case passes a
// runtime.Object through the full Validate() path and checks whether an
// error containing errSubstr is produced.
type crdTestCase struct {
	name      string
	obj       runtime.Object
	errSubstr string // empty means no error expected
}

// runCRDTests is the shared test runner for CRD validation test tables.
func runCRDTests(t *testing.T, tests []crdTestCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.obj)
			if tt.errSubstr == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			verr, ok := err.(errors.ErrorValidation)
			if !ok {
				t.Fatalf("expected ErrorValidation, got %T: %v", err, err)
			}
			for _, f := range verr.ErroredFields {
				if strings.Contains(f.Reason, tt.errSubstr) {
					return
				}
			}
			t.Errorf("expected error containing %q, got: %v", tt.errSubstr, err)
		})
	}
}

// TestCRDValidation_Tier tests CEL x-kubernetes-validations on Tier resources.
func TestCRDValidation_Tier(t *testing.T) {
	defaultOrder := apiv3.DefaultTierOrder
	kubeAdminOrder := apiv3.KubeAdminTierOrder
	customOrder := float64(100)
	deny := apiv3.Deny
	pass := apiv3.Pass

	runCRDTests(t, []crdTestCase{
		{
			name: "default tier with Deny passes",
			obj: &apiv3.Tier{
				TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       apiv3.TierSpec{Order: &defaultOrder, DefaultAction: &deny},
			},
		},
		{
			name: "default tier with Pass fails",
			obj: &apiv3.Tier{
				TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       apiv3.TierSpec{Order: &defaultOrder, DefaultAction: &pass},
			},
			errSubstr: "default",
		},
		{
			name: "kube-admin tier with Pass passes",
			obj: &apiv3.Tier{
				TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{Name: "kube-admin"},
				Spec:       apiv3.TierSpec{Order: &kubeAdminOrder, DefaultAction: &pass},
			},
		},
		{
			name: "kube-admin tier with Deny fails",
			obj: &apiv3.Tier{
				TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{Name: "kube-admin"},
				Spec:       apiv3.TierSpec{Order: &kubeAdminOrder, DefaultAction: &deny},
			},
			errSubstr: "kube-admin",
		},
		{
			name: "custom tier with any action passes",
			obj: &apiv3.Tier{
				TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{Name: "my-tier"},
				Spec:       apiv3.TierSpec{Order: &customOrder, DefaultAction: &pass},
			},
		},
		{
			// CRD validation should work even without TypeMeta set,
			// since we infer Kind from the Go type.
			name: "without TypeMeta still validates",
			obj: &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       apiv3.TierSpec{Order: &defaultOrder, DefaultAction: &pass},
			},
			errSubstr: "default",
		},
	})
}

// TestCRDValidation_BGPPeer tests OpenAPI schema enum constraints on BGPPeer.
func TestCRDValidation_BGPPeer(t *testing.T) {
	validMode := apiv3.NextHopMode(apiv3.NextHopModeAuto)
	invalidMode := apiv3.NextHopMode("Invalid")

	runCRDTests(t, []crdTestCase{
		{
			name: "valid nextHopMode passes",
			obj: &apiv3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "test-peer"},
				Spec:       apiv3.BGPPeerSpec{NextHopMode: &validMode},
			},
		},
		{
			name: "invalid nextHopMode fails enum",
			obj: &apiv3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "test-peer"},
				Spec:       apiv3.BGPPeerSpec{NextHopMode: &invalidMode},
			},
			errSubstr: "supported values",
		},
	})
}

// TestCRDValidation_BGPPeer_ASNumber tests CEL rules involving asNumber, which
// is a uint32 Go type. Verifies the JSON round-trip in toUnstructured() produces
// the correct int type for CEL evaluation.
func TestCRDValidation_BGPPeer_ASNumber(t *testing.T) {
	runCRDTests(t, []crdTestCase{
		{
			name: "localWorkloadSelector with asNumber passes",
			obj: &apiv3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "test-peer"},
				Spec: apiv3.BGPPeerSpec{
					LocalWorkloadSelector: "color == 'red'",
					ASNumber:              numorstring.ASNumber(65401),
				},
			},
		},
		{
			name: "localWorkloadSelector without asNumber fails",
			obj: &apiv3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "test-peer"},
				Spec: apiv3.BGPPeerSpec{
					LocalWorkloadSelector: "color == 'red'",
				},
			},
			errSubstr: "asNumber is required",
		},
		{
			name: "peerSelector with asNumber fails",
			obj: &apiv3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "test-peer"},
				Spec: apiv3.BGPPeerSpec{
					PeerSelector: "has(label)",
					ASNumber:     numorstring.ASNumber(65401),
				},
			},
			errSubstr: "asNumber must be empty",
		},
	})
}

// TestCRDValidation_IPPool tests OpenAPI schema enum constraints on IPPool.
func TestCRDValidation_IPPool(t *testing.T) {
	runCRDTests(t, []crdTestCase{
		{
			name: "valid ipipMode passes",
			obj: &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pool"},
				Spec: apiv3.IPPoolSpec{
					CIDR:     "10.0.0.0/24",
					IPIPMode: apiv3.IPIPModeAlways,
				},
			},
		},
		{
			name: "invalid ipipMode fails enum",
			obj: &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pool"},
				Spec: apiv3.IPPoolSpec{
					CIDR:     "10.0.0.0/24",
					IPIPMode: apiv3.IPIPMode("BadMode"),
				},
			},
			errSubstr: "supported values",
		},
		{
			name: "invalid vxlanMode fails enum",
			obj: &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pool"},
				Spec: apiv3.IPPoolSpec{
					CIDR:      "10.0.0.0/24",
					VXLANMode: apiv3.VXLANMode("BadMode"),
				},
			},
			errSubstr: "supported values",
		},
	})
}

// TestCRDDefaults_Tier verifies that Validate() applies CRD schema defaults
// to Tier objects. The CRD defaults spec.defaultAction to "Deny", which also
// satisfies the CEL rule requiring the 'default' tier to have action "Deny".
func TestCRDDefaults_Tier(t *testing.T) {
	defaultOrder := apiv3.DefaultTierOrder
	tier := &apiv3.Tier{
		TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: &defaultOrder},
	}

	// Without defaulting this would fail CEL validation (default tier
	// requires defaultAction == "Deny").
	if err := Validate(tier); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if tier.Spec.DefaultAction == nil || *tier.Spec.DefaultAction != apiv3.Deny {
		t.Errorf("expected DefaultAction %q after defaulting, got %v", apiv3.Deny, tier.Spec.DefaultAction)
	}
}

// TestCRDDefaults_IPPool verifies that Validate() defaults
// spec.assignmentMode to "Automatic".
func TestCRDDefaults_IPPool(t *testing.T) {
	pool := &apiv3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pool"},
		Spec:       apiv3.IPPoolSpec{CIDR: "10.0.0.0/24"},
	}

	// IPPool has other struct validation issues but assignmentMode should
	// still be defaulted.
	_ = Validate(pool)

	if pool.Spec.AssignmentMode == nil || *pool.Spec.AssignmentMode != apiv3.Automatic {
		t.Errorf("expected AssignmentMode %q after defaulting, got %v", apiv3.Automatic, pool.Spec.AssignmentMode)
	}
}

// TestCRDDefaults_DoesNotOverwrite verifies that explicit values are not
// overwritten by CRD defaults.
func TestCRDDefaults_DoesNotOverwrite(t *testing.T) {
	customOrder := float64(100)
	allow := apiv3.Allow
	tier := &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tier"},
		Spec:       apiv3.TierSpec{Order: &customOrder, DefaultAction: &allow},
	}

	_ = Validate(tier)

	if *tier.Spec.DefaultAction != apiv3.Allow {
		t.Errorf("expected DefaultAction to remain %q, got %q", apiv3.Allow, *tier.Spec.DefaultAction)
	}
}

// TestCRDDefaults_NetworkPolicy verifies that string fields get defaulted.
// The NetworkPolicy CRD defaults spec.tier to "default".
func TestCRDDefaults_NetworkPolicy(t *testing.T) {
	np := &apiv3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec:       apiv3.NetworkPolicySpec{},
	}

	_ = Validate(np)

	if np.Spec.Tier != "default" {
		t.Errorf("expected Tier %q after defaulting, got %q", "default", np.Spec.Tier)
	}
}

// TestCRDDefaults_BGPConfiguration verifies that Validate() defaults
// logSeverityScreen to "Info".
func TestCRDDefaults_BGPConfiguration(t *testing.T) {
	bgp := &apiv3.BGPConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.BGPConfigurationSpec{},
	}

	_ = Validate(bgp)

	if bgp.Spec.LogSeverityScreen != "Info" {
		t.Errorf("expected LogSeverityScreen %q after defaulting, got %q", "Info", bgp.Spec.LogSeverityScreen)
	}
}

// TestCRDDefaults_FelixConfiguration verifies that Validate() defaults
// nftablesMode to "Auto".
func TestCRDDefaults_FelixConfiguration(t *testing.T) {
	fc := &apiv3.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.FelixConfigurationSpec{},
	}

	_ = Validate(fc)

	if fc.Spec.NFTablesMode == nil || *fc.Spec.NFTablesMode != apiv3.NFTablesModeAuto {
		t.Errorf("expected NFTablesMode %q after defaulting, got %v", apiv3.NFTablesModeAuto, fc.Spec.NFTablesMode)
	}
}

// TestCRDDefaults_StagedGlobalNetworkPolicy verifies that multiple defaults
// are applied to the same resource. The CRD defaults both stagedAction to
// "Set" and tier to "default".
func TestCRDDefaults_StagedGlobalNetworkPolicy(t *testing.T) {
	sgnp := &apiv3.StagedGlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-staged-policy"},
		Spec:       apiv3.StagedGlobalNetworkPolicySpec{},
	}

	_ = Validate(sgnp)

	if sgnp.Spec.StagedAction != apiv3.StagedActionSet {
		t.Errorf("expected StagedAction %q after defaulting, got %q", apiv3.StagedActionSet, sgnp.Spec.StagedAction)
	}
	if sgnp.Spec.Tier != "default" {
		t.Errorf("expected Tier %q after defaulting, got %q", "default", sgnp.Spec.Tier)
	}
}

// TestCRDDefaults_StringFieldDoesNotOverwrite verifies that a non-empty
// string field is not overwritten by the CRD default.
func TestCRDDefaults_StringFieldDoesNotOverwrite(t *testing.T) {
	np := &apiv3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec:       apiv3.NetworkPolicySpec{Tier: "my-custom-tier"},
	}

	_ = Validate(np)

	if np.Spec.Tier != "my-custom-tier" {
		t.Errorf("expected Tier to remain %q, got %q", "my-custom-tier", np.Spec.Tier)
	}
}

// TestCRDValidation_CombinedWithStructValidation verifies that both Go struct
// validation errors and CRD validation errors are reported together.
func TestCRDValidation_CombinedWithStructValidation(t *testing.T) {
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
		t.Errorf("expected at least 2 errored fields (struct + CRD), got %d: %v", len(verr.ErroredFields), verr.ErroredFields)
	}

	foundCEL := false
	for _, f := range verr.ErroredFields {
		if strings.Contains(f.Reason, "default") && strings.Contains(f.Reason, "Deny") {
			foundCEL = true
			break
		}
	}
	if !foundCEL {
		t.Errorf("expected CEL error about default tier needing Deny, got: %v", err)
	}
}
