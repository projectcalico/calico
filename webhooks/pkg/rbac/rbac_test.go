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
	"fmt"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

// MockTierAuthorizer is a mock implementation of authorizer.TierAuthorizer
type MockTierAuthorizer struct {
	mock.Mock
}

func (m *MockTierAuthorizer) AuthorizeTierOperation(ctx context.Context, policyName string, tierName string) error {
	args := m.Called(ctx, policyName, tierName)
	return args.Error(0)
}

func init() {
	// Add Calico v3 types to the scheme for parsePolicy to work.
	v3.AddToScheme(utils.Scheme)
}

func TestGetTier(t *testing.T) {
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
			tier, ok := getTier(tc.obj)
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
	npRaw, _ := json.Marshal(np)

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
	gnpRaw, _ := json.Marshal(gnp)

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
	snpRaw, _ := json.Marshal(snp)

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
	sgnpRaw, _ := json.Marshal(sgnp)

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
	sknpRaw, _ := json.Marshal(sknp)

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
			name:        "StagedKubernetesNetworkPolicy (no tier)",
			kind:        v3.KindStagedKubernetesNetworkPolicy,
			body:        sknpRaw,
			expectError: true,
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
	mockAuthz := &MockTierAuthorizer{}
	h := NewTieredRBACHook(mockAuthz)
	assert.NotNil(t, h)

	handler := h.Handler()
	assert.NotNil(t, handler.ProcessV1Review)
}

func TestAugmentContextWithUserInfo(t *testing.T) {
	ctx := context.Background()
	req := &v1.AdmissionRequest{
		UserInfo: authv1.UserInfo{
			Username: "test-user",
			UID:      "user-123",
			Groups:   []string{"group1", "group2"},
			Extra:    map[string]authv1.ExtraValue{"foo": {"bar"}},
		},
		Operation: v1.Create,
	}
	obj := &v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-np",
			Namespace: "test-ns",
		},
	}

	newCtx, err := augmentContextWithUserInfo(ctx, req, obj)
	assert.NoError(t, err)
	assert.NotNil(t, newCtx)

	u, ok := genericapirequest.UserFrom(newCtx)
	assert.True(t, ok)
	assert.Equal(t, "test-user", u.GetName())
	assert.Equal(t, "user-123", u.GetUID())
	assert.ElementsMatch(t, []string{"group1", "group2"}, u.GetGroups())

	ri, ok := genericapirequest.RequestInfoFrom(newCtx)
	assert.True(t, ok)
	assert.Equal(t, "networkpolicies", ri.Resource)
	assert.Equal(t, "test-np", ri.Name)
	assert.Equal(t, "test-ns", ri.Namespace)
	assert.Equal(t, "create", ri.Verb)
}

func TestAuthorize(t *testing.T) {
	mockAuthz := &MockTierAuthorizer{}
	h := NewTieredRBACHook(mockAuthz).(*tieredRBACHook)

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

	testCases := []struct {
		name           string
		ar             v1.AdmissionReview
		setupMock      func()
		expectedAllow  bool
		expectedReason metav1.StatusReason
	}{
		{
			name: "Authorized request",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:  "123",
					Kind: metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Object: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			setupMock: func() {
				mockAuthz.On("AuthorizeTierOperation", mock.Anything, "test-np", "default").Return(nil).Once()
			},
			expectedAllow: true,
		},
		{
			name: "Authorized request (DELETE uses OldObject)",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:  "1234",
					Kind: metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					OldObject: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Delete,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			setupMock: func() {
				mockAuthz.On("AuthorizeTierOperation", mock.Anything, "test-np", "default").Return(nil).Once()
			},
			expectedAllow: true,
		},
		{
			name: "Unauthorized request",
			ar: v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:  "123",
					Kind: metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindNetworkPolicy},
					Object: runtime.RawExtension{
						Raw: npRaw,
					},
					Operation: v1.Create,
					UserInfo:  authv1.UserInfo{Username: "test-user"},
				},
			},
			setupMock: func() {
				mockAuthz.On("AuthorizeTierOperation", mock.Anything, "test-np", "default").Return(fmt.Errorf("unauthorized")).Once()
			},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonForbidden,
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
			setupMock:      func() {},
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
			setupMock:      func() {},
			expectedAllow:  false,
			expectedReason: metav1.StatusReasonInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupMock()
			resp := h.authorize(tc.ar)
			assert.Equal(t, tc.expectedAllow, resp.Allowed)
			if !tc.expectedAllow && tc.expectedReason != "" {
				assert.Equal(t, tc.expectedReason, resp.Result.Reason)
			}
			mockAuthz.AssertExpectations(t)
		})
	}
}
