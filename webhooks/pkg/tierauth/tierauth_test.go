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

package tierauth

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
)

// fakeTierAuthorizer allows the tiers named in allowed, and denies everything else.
// An empty tier name represents the "unrestricted by tier" check.
type fakeTierAuthorizer struct {
	allowed map[string]bool
	calls   []string
}

func (f *fakeTierAuthorizer) AuthorizeTierOperation(ctx context.Context, policyName string, tierName string) error {
	f.calls = append(f.calls, fmt.Sprintf("%s/%s", tierName, policyName))
	if f.allowed[tierName] {
		return nil
	}
	return fmt.Errorf("not authorized for tier %q", tierName)
}

type fakeResolver struct {
	tiers map[string]string
	err   error
}

func (f *fakeResolver) TierForPolicy(ctx context.Context, resource, namespace, name string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	tier, ok := f.tiers[namespace+"/"+name]
	if !ok {
		return "", ErrPolicyNotFound
	}
	return tier, nil
}

func testUser(name string) user.Info {
	return &user.DefaultInfo{Name: name, Groups: []string{"system:authenticated"}}
}

func TestAuthorize(t *testing.T) {
	testCases := []struct {
		name     string
		allowed  map[string]bool
		resolver *fakeResolver
		req      Request
		expected Decision
	}{
		{
			name:     "not a tiered policy resource",
			allowed:  map[string]bool{},
			resolver: &fakeResolver{},
			req: Request{
				User:     testUser("alice"),
				Verb:     "list",
				Resource: "hostendpoints",
			},
			expected: DecisionNotApplicable,
		},
		{
			name:     "selectored list, tier authorized",
			allowed:  map[string]bool{"production": true},
			resolver: &fakeResolver{},
			req: Request{
				User:     testUser("alice"),
				Verb:     "list",
				Resource: "networkpolicies",
				Tier:     "production",
			},
			expected: DecisionPermitted,
		},
		{
			name:     "selectored list, tier not authorized",
			allowed:  map[string]bool{"staging": true},
			resolver: &fakeResolver{},
			req: Request{
				User:     testUser("alice"),
				Verb:     "list",
				Resource: "networkpolicies",
				Tier:     "production",
			},
			expected: DecisionDenied,
		},
		{
			name:     "unselectored list, user unrestricted by tier",
			allowed:  map[string]bool{"": true},
			resolver: &fakeResolver{},
			req: Request{
				User:     testUser("admin"),
				Verb:     "list",
				Resource: "networkpolicies",
			},
			expected: DecisionPermitted,
		},
		{
			name:     "unselectored list, user restricted to a tier",
			allowed:  map[string]bool{"production": true},
			resolver: &fakeResolver{},
			req: Request{
				User:     testUser("alice"),
				Verb:     "list",
				Resource: "networkpolicies",
			},
			expected: DecisionDenied,
		},
		{
			name:    "named get resolves tier from cache and is authorized",
			allowed: map[string]bool{"production": true},
			resolver: &fakeResolver{
				tiers: map[string]string{"ns1/deny-external": "production"},
			},
			req: Request{
				User:      testUser("alice"),
				Verb:      "get",
				Resource:  "networkpolicies",
				Namespace: "ns1",
				Name:      "deny-external",
			},
			expected: DecisionPermitted,
		},
		{
			name:    "named get resolves tier from cache and is denied",
			allowed: map[string]bool{"staging": true},
			resolver: &fakeResolver{
				tiers: map[string]string{"ns1/deny-external": "production"},
			},
			req: Request{
				User:      testUser("alice"),
				Verb:      "get",
				Resource:  "networkpolicies",
				Namespace: "ns1",
				Name:      "deny-external",
			},
			expected: DecisionDenied,
		},
		{
			name:     "named get on a policy that does not exist",
			allowed:  map[string]bool{},
			resolver: &fakeResolver{tiers: map[string]string{}},
			req: Request{
				User:      testUser("alice"),
				Verb:      "get",
				Resource:  "networkpolicies",
				Namespace: "ns1",
				Name:      "missing",
			},
			expected: DecisionNotApplicable,
		},
		{
			name:     "resolver failure denies, because we are fail-closed",
			allowed:  map[string]bool{"production": true},
			resolver: &fakeResolver{err: errors.New("apiserver unreachable")},
			req: Request{
				User:      testUser("alice"),
				Verb:      "get",
				Resource:  "networkpolicies",
				Namespace: "ns1",
				Name:      "deny-external",
			},
			expected: DecisionDenied,
		},
		{
			name:     "cluster-scoped global policy resolves with an empty namespace",
			allowed:  map[string]bool{"production": true},
			resolver: &fakeResolver{tiers: map[string]string{"/deny-all": "production"}},
			req: Request{
				User:     testUser("alice"),
				Verb:     "get",
				Resource: "globalnetworkpolicies",
				Name:     "deny-all",
			},
			expected: DecisionPermitted,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fa := &fakeTierAuthorizer{allowed: tc.allowed}
			a := New(fa, tc.resolver)

			result := a.Authorize(context.Background(), tc.req)

			assert.Equal(t, tc.expected, result.Decision, "reason: %s", result.Reason)
			if result.Decision != DecisionPermitted {
				assert.NotEmpty(t, result.Reason, "non-permitted decisions must carry a reason")
			}
		})
	}
}

func TestUnselectoredListDenyReasonNamesTheSelector(t *testing.T) {
	fa := &fakeTierAuthorizer{allowed: map[string]bool{"production": true}}
	a := New(fa, &fakeResolver{})

	result := a.Authorize(context.Background(), Request{
		User:     testUser("alice"),
		Verb:     "list",
		Resource: "networkpolicies",
	})

	require.Equal(t, DecisionDenied, result.Decision)
	assert.Contains(t, result.Reason, "projectcalico.org/tier")
}

func TestUnselectoredListUsesAnUnnamedCheck(t *testing.T) {
	fa := &fakeTierAuthorizer{allowed: map[string]bool{"": true}}
	a := New(fa, &fakeResolver{})

	a.Authorize(context.Background(), Request{
		User:     testUser("admin"),
		Verb:     "list",
		Resource: "networkpolicies",
	})

	// Both the tier and the policy name must be empty, so that RBAC matches only
	// rules that carry no resourceNames.
	assert.Equal(t, []string{"/"}, fa.calls)
}

func TestIsTieredPolicyResource(t *testing.T) {
	for _, resource := range []string{
		"networkpolicies",
		"globalnetworkpolicies",
		"stagednetworkpolicies",
		"stagedglobalnetworkpolicies",
		"stagedkubernetesnetworkpolicies",
	} {
		assert.True(t, IsTieredPolicyResource(resource), resource)
	}
	for _, resource := range []string{"tiers", "hostendpoints", "networksets", ""} {
		assert.False(t, IsTieredPolicyResource(resource), resource)
	}
}
