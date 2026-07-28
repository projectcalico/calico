// Copyright 2026 Tigera, Inc.
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

package rbac

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	fakecalicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

// MockDecider is a mock implementation of the Decider interface.
type MockDecider struct {
	mock.Mock
}

func (m *MockDecider) Authorize(ctx context.Context, req tierauth.Request) tierauth.Result {
	args := m.Called(ctx, req)
	res, ok := args.Get(0).(tierauth.Result)
	if !ok {
		return tierauth.Result{Decision: tierauth.DecisionDenied, Reason: "mock misconfigured"}
	}
	return res
}

func init() {
	// Add Calico v3 types to the scheme for parsePolicy to work.
	utilruntime.Must(v3.AddToScheme(utils.Scheme))
}

func TestTierFromPolicy(t *testing.T) {
	testCases := []struct {
		name     string
		obj      any
		expected string
		ok       bool
	}{
		{
			name: "NetworkPolicy with tier",
			obj: &v3.NetworkPolicy{
				Spec: v3.NetworkPolicySpec{
					Tier: "default",
				},
			},
			expected: "default",
			ok:       true,
		},
		{
			name: "GlobalNetworkPolicy with tier",
			obj: &v3.GlobalNetworkPolicy{
				Spec: v3.GlobalNetworkPolicySpec{
					Tier: "admin",
				},
			},
			expected: "admin",
			ok:       true,
		},
		{
			name: "StagedNetworkPolicy with tier",
			obj: &v3.StagedNetworkPolicy{
				Spec: v3.StagedNetworkPolicySpec{
					Tier: "trusted",
				},
			},
			expected: "trusted",
			ok:       true,
		},
		{
			name: "StagedGlobalNetworkPolicy with tier",
			obj: &v3.StagedGlobalNetworkPolicy{
				Spec: v3.StagedGlobalNetworkPolicySpec{
					Tier: "trusted-global",
				},
			},
			expected: "trusted-global",
			ok:       true,
		},
		{
			name: "StagedKubernetesNetworkPolicy without tier",
			obj: &v3.StagedKubernetesNetworkPolicy{
				Spec: v3.StagedKubernetesNetworkPolicySpec{},
			},
			ok: false,
		},
		{
			name: "Object without Spec",
			obj:  &struct{}{},
			ok:   false,
		},
		{
			name: "Object with Spec but no Tier",
			obj: &struct {
				Spec struct{}
			}{},
			ok: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tier, ok := names.TierFromPolicy(tc.obj)
			assert.Equal(t, tc.ok, ok)
			if ok {
				assert.Equal(t, tc.expected, tier)
			}
		})
	}
}

func TestParsePolicy(t *testing.T) {
	h := &tieredRBACHook{}

	np := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindNetworkPolicy,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-np",
		},
		Spec: v3.NetworkPolicySpec{
			Tier: "default",
		},
	}
	npRaw, err := json.Marshal(np)
	assert.NoError(t, err)

	gnp := &v3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindGlobalNetworkPolicy,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-gnp",
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier: "admin",
		},
	}
	gnpRaw, err := json.Marshal(gnp)
	assert.NoError(t, err)

	snp := &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-snp",
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier: "trusted",
		},
	}
	snpRaw, err := json.Marshal(snp)
	assert.NoError(t, err)

	sgnp := &v3.StagedGlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedGlobalNetworkPolicy,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-sgnp",
		},
		Spec: v3.StagedGlobalNetworkPolicySpec{
			Tier: "trusted-global",
		},
	}
	sgnpRaw, err := json.Marshal(sgnp)
	assert.NoError(t, err)

	sknp := &v3.StagedKubernetesNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedKubernetesNetworkPolicy,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-sknp",
		},
		Spec: v3.StagedKubernetesNetworkPolicySpec{},
	}
	sknpRaw, err := json.Marshal(sknp)
	assert.NoError(t, err)

	testCases := []struct {
		name         string
		kind         string
		body         []byte
		expectedTier string
		expectError  bool
	}{
		{
			name:         "Valid NetworkPolicy",
			kind:         v3.KindNetworkPolicy,
			body:         npRaw,
			expectedTier: "default",
			expectError:  false,
		},
		{
			name:         "Valid GlobalNetworkPolicy",
			kind:         v3.KindGlobalNetworkPolicy,
			body:         gnpRaw,
			expectedTier: "admin",
			expectError:  false,
		},
		{
			name:         "Valid StagedNetworkPolicy",
			kind:         v3.KindStagedNetworkPolicy,
			body:         snpRaw,
			expectedTier: "trusted",
			expectError:  false,
		},
		{
			name:         "Valid StagedGlobalNetworkPolicy",
			kind:         v3.KindStagedGlobalNetworkPolicy,
			body:         sgnpRaw,
			expectedTier: "trusted-global",
			expectError:  false,
		},
		{
			name:         "StagedKubernetesNetworkPolicy (no tier field, defaults to default)",
			kind:         v3.KindStagedKubernetesNetworkPolicy,
			body:         sknpRaw,
			expectedTier: "default",
			expectError:  false,
		},
		{
			name:        "Unsupported kind",
			kind:        "Unknown",
			body:        npRaw,
			expectError: true,
		},
		{
			name:        "Invalid JSON",
			kind:        v3.KindNetworkPolicy,
			body:        []byte("{invalid}"),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obj, tier, err := h.parsePolicy(tc.kind, tc.body)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedTier, tier)
				assert.NotNil(t, obj)
			}
		})
	}
}

func TestNewTieredRBACHook(t *testing.T) {
	mockDecider := &MockDecider{}
	fakeCS := fakecalicoclient.NewClientset()
	h := NewTieredRBACHook(mockDecider, fakeCS.ProjectcalicoV3().Tiers())
	assert.NotNil(t, h)

	handler := h.Handler()
	assert.NotNil(t, handler.ProcessV1Review)
}

// forTier matches an Authorize call for the given policy name, tier, verb, resource,
// namespace and requesting user. A wrong or missing field here (e.g. an empty Resource)
// changes the decision tierauth returns, so the fixtures that use this must set all of them.
func forTier(name, tier, verb, resource, namespace, user string) any {
	return mock.MatchedBy(func(req tierauth.Request) bool {
		return req.Name == name &&
			req.Tier == tier &&
			req.Verb == verb &&
			req.Resource == resource &&
			req.Namespace == namespace &&
			req.User.GetName() == user
	})
}

func TestAuthorize(t *testing.T) {
	np := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindNetworkPolicy,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-np",
			Namespace: "test-ns",
		},
		Spec: v3.NetworkPolicySpec{
			Tier: "default",
		},
	}
	npRaw, _ := json.Marshal(np)

	defaultTier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	securityTier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "security"},
	}
	terminatingTier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "terminating",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers:        []string{"test-finalizer"},
		},
	}

	npResource := metav1.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"}

	testCases := []struct {
		name           string
		ar             v1.AdmissionReview
		tiers          []runtime.Object
		setupMock      func(d *MockDecider)
		expectedAllow  bool
		expectedReason metav1.StatusReason
	}{
		{
			name: "Authorized CREATE",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "123",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "default", "create", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
			},
			expectedAllow: true,
		},
		{
			name: "Authorized DELETE uses OldObject",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "1234",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					OldObject: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Delete,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "default", "delete", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
			},
			expectedAllow: true,
		},
		{
			name: "Authorized UPDATE with tier change",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "456",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: func() []byte {
							newNP := np.DeepCopy()
							newNP.Spec.Tier = "security"
							raw, _ := json.Marshal(newNP)
							return raw
						}(),
					},
					OldObject: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Update,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier, securityTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "security", "update", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
				d.On("Authorize", mock.Anything, forTier("test-np", "default", "update", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
			},
			expectedAllow: true,
		},
		{
			name: "Unauthorized UPDATE - no permission on new tier",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "457",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: func() []byte {
							newNP := np.DeepCopy()
							newNP.Spec.Tier = "security"
							raw, _ := json.Marshal(newNP)
							return raw
						}(),
					},
					OldObject: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Update,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier, securityTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "security", "update", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionDenied, Reason: "unauthorized"}).Once()
			},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonForbidden,
		},
		{
			name: "Unauthorized UPDATE - no permission on old tier",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "458",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: func() []byte {
							newNP := np.DeepCopy()
							newNP.Spec.Tier = "security"
							raw, _ := json.Marshal(newNP)
							return raw
						}(),
					},
					OldObject: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Update,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier, securityTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "security", "update", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
				d.On("Authorize", mock.Anything, forTier("test-np", "default", "update", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionDenied, Reason: "unauthorized"}).Once()
			},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonForbidden,
		},
		{
			name: "Authorized UPDATE without tier change skips old tier check",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "459",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: npRaw,
					},
					OldObject: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Update,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "default", "update", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
			},
			expectedAllow: true,
		},
		{
			name: "Unauthorized CREATE",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "123",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "default", "create", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionDenied, Reason: "unauthorized"}).Once()
			},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonForbidden,
		},
		{
			name: "CREATE with non-existent tier",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "500",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: func() []byte {
							newNP := np.DeepCopy()
							newNP.Spec.Tier = "nonexistent"
							raw, _ := json.Marshal(newNP)
							return raw
						}(),
					},
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "nonexistent", "create", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
			},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonForbidden,
		},
		{
			name: "CREATE with terminating tier",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "501",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: func() []byte {
							newNP := np.DeepCopy()
							newNP.Spec.Tier = "terminating"
							raw, _ := json.Marshal(newNP)
							return raw
						}(),
					},
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{terminatingTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "terminating", "create", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
			},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonForbidden,
		},
		{
			name: "UPDATE to non-existent tier",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "502",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: func() []byte {
							newNP := np.DeepCopy()
							newNP.Spec.Tier = "nonexistent"
							raw, _ := json.Marshal(newNP)
							return raw
						}(),
					},
					OldObject: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Update,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "nonexistent", "update", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionPermitted}).Once()
			},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonForbidden,
		},
		{
			name: "Tier authorization returns no opinion is denied, not allowed",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "503",
					Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Resource:  npResource,
					Namespace: "test-ns",
					Object: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			tiers: []runtime.Object{defaultTier},
			setupMock: func(d *MockDecider) {
				d.On("Authorize", mock.Anything, forTier("test-np", "default", "create", "networkpolicies", "test-ns", "test-user")).Return(tierauth.Result{Decision: tierauth.DecisionNotApplicable, Reason: "not a tiered policy resource"}).Once()
			},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonInternalError,
		},
		{
			name: "No object in request",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "123",
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			setupMock:      func(d *MockDecider) {},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name: "Invalid kind in request",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:  "123",
					Kind: metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "InvalidKind"},
					Object: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			setupMock:      func(d *MockDecider) {},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDecider := &MockDecider{}
			fakeCS := fakecalicoclient.NewClientset(tc.tiers...)
			h := &tieredRBACHook{decider: mockDecider, tierGetter: fakeCS.ProjectcalicoV3().Tiers()}
			tc.setupMock(mockDecider)
			resp := h.authorize(tc.ar)
			assert.Equal(t, tc.expectedAllow, resp.Allowed)
			if !tc.expectedAllow && tc.expectedReason != "" {
				assert.Equal(t, tc.expectedReason, resp.Result.Reason)
			}
			mockDecider.AssertExpectations(t)
		})
	}
}

func TestUpdateMovingTiersAuthorizesBothTiers(t *testing.T) {
	oldPolicy := &v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "deny-external"},
		Spec:       v3.NetworkPolicySpec{Tier: "staging"},
	}
	newPolicy := &v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "deny-external"},
		Spec:       v3.NetworkPolicySpec{Tier: "production"},
	}

	oldRaw, err := json.Marshal(oldPolicy)
	require.NoError(t, err)
	newRaw, err := json.Marshal(newPolicy)
	require.NoError(t, err)

	d := &MockDecider{}
	// Authorized for the destination tier but not the source: the move must be refused.
	d.On("Authorize", mock.Anything, mock.MatchedBy(func(req tierauth.Request) bool {
		return req.Tier == "production"
	})).Return(tierauth.Result{Decision: tierauth.DecisionPermitted})
	d.On("Authorize", mock.Anything, mock.MatchedBy(func(req tierauth.Request) bool {
		return req.Tier == "staging"
	})).Return(tierauth.Result{Decision: tierauth.DecisionDenied, Reason: "not authorized for tier \"staging\""})

	calicoClient := fakecalicoclient.NewClientset(&v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "production"}})
	hook := NewTieredRBACHook(d, calicoClient.ProjectcalicoV3().Tiers())

	response := hook.Handler().ProcessV1Review(v1.AdmissionReview{
		Request: &v1.AdmissionRequest{
			UID:       "test-uid",
			Operation: v1.Update,
			Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "NetworkPolicy"},
			Resource:  metav1.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"},
			Name:      "deny-external",
			Namespace: "ns1",
			UserInfo:  authv1.UserInfo{Username: "alice"},
			Object:    runtime.RawExtension{Raw: newRaw},
			OldObject: runtime.RawExtension{Raw: oldRaw},
		},
	})

	assert.False(t, response.Allowed, "moving a policy out of a tier the user cannot write must be refused")
	d.AssertExpectations(t)
}
