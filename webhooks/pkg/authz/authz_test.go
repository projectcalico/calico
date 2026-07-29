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

package authz

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
)

// recordingDecider returns a fixed result and records what it was asked.
type recordingDecider struct {
	result tierauth.Result
	got    []tierauth.Request
}

func (d *recordingDecider) Authorize(ctx context.Context, req tierauth.Request) tierauth.Result {
	d.got = append(d.got, req)
	return d.result
}

// blockingDecider mimics what tierauth does when a tier lookup outruns the decision budget: it
// waits on the context it was handed and denies once that expires.
type blockingDecider struct {
	deadline time.Time
}

func (d *blockingDecider) Authorize(ctx context.Context, req tierauth.Request) tierauth.Result {
	d.deadline, _ = ctx.Deadline()
	<-ctx.Done()
	return tierauth.Result{Decision: tierauth.DecisionDenied, Reason: "could not determine the tier"}
}

func sarFor(ra *authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReview {
	return authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:               "alice",
			Groups:             []string{"system:authenticated"},
			ResourceAttributes: ra,
		},
	}
}

func TestNoOpinionOnRequestsWeDoNotHandle(t *testing.T) {
	testCases := []struct {
		name string
		sar  authorizationv1.SubjectAccessReview
	}{
		{
			name: "non-resource request",
			sar:  sarFor(nil),
		},
		{
			name: "other API group",
			sar: sarFor(&authorizationv1.ResourceAttributes{
				Group:    "networking.k8s.io",
				Resource: "networkpolicies",
				Verb:     "list",
			}),
		},
		{
			name: "not a tiered policy resource",
			sar: sarFor(&authorizationv1.ResourceAttributes{
				Group:    "projectcalico.org",
				Resource: "hostendpoints",
				Verb:     "list",
			}),
		},
		{
			name: "mutating verb belongs to the admission webhook",
			sar: sarFor(&authorizationv1.ResourceAttributes{
				Group:    "projectcalico.org",
				Resource: "networkpolicies",
				Verb:     "create",
			}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// A Denied result from the decider proves we never consulted it.
			d := &recordingDecider{result: tierauth.Result{Decision: tierauth.DecisionDenied, Reason: "should not be reached"}}

			status := NewHook(d).Authorize(tc.sar)

			assert.False(t, status.Allowed, "the webhook must never return Allowed")
			assert.False(t, status.Denied)
			assert.Empty(t, d.got, "the decider must not be consulted")
		})
	}
}

func TestPermittedMapsToNoOpinion(t *testing.T) {
	d := &recordingDecider{result: tierauth.Result{Decision: tierauth.DecisionPermitted, Reason: "authorized for tier"}}

	status := NewHook(d).Authorize(sarFor(&authorizationv1.ResourceAttributes{
		Group:    "projectcalico.org",
		Resource: "networkpolicies",
		Verb:     "list",
	}))

	// Permitted must be NoOpinion, not Allow: an Allow would bypass RBAC's base
	// resource permission check entirely.
	assert.False(t, status.Allowed)
	assert.False(t, status.Denied)
}

func TestDeniedMapsToDeniedWithReason(t *testing.T) {
	d := &recordingDecider{result: tierauth.Result{Decision: tierauth.DecisionDenied, Reason: "nope, try --selector"}}

	status := NewHook(d).Authorize(sarFor(&authorizationv1.ResourceAttributes{
		Group:    "projectcalico.org",
		Resource: "networkpolicies",
		Verb:     "list",
	}))

	assert.False(t, status.Allowed)
	assert.True(t, status.Denied)
	assert.Equal(t, "nope, try --selector", status.Reason)
}

func TestTierExtractedFromFieldSelector(t *testing.T) {
	d := &recordingDecider{result: tierauth.Result{Decision: tierauth.DecisionPermitted}}

	NewHook(d).Authorize(sarFor(&authorizationv1.ResourceAttributes{
		Group:    "projectcalico.org",
		Resource: "networkpolicies",
		Verb:     "list",
		FieldSelector: &authorizationv1.FieldSelectorAttributes{
			Requirements: []metav1.FieldSelectorRequirement{
				{
					Key:      "spec.tier",
					Operator: metav1.FieldSelectorOpIn,
					Values:   []string{"production"},
				},
			},
		},
	}))

	require.Len(t, d.got, 1)
	assert.Equal(t, "production", d.got[0].Tier)
}

func TestTierExtractedFromLabelSelector(t *testing.T) {
	d := &recordingDecider{result: tierauth.Result{Decision: tierauth.DecisionPermitted}}

	NewHook(d).Authorize(sarFor(&authorizationv1.ResourceAttributes{
		Group:    "projectcalico.org",
		Resource: "networkpolicies",
		Verb:     "list",
		LabelSelector: &authorizationv1.LabelSelectorAttributes{
			Requirements: []metav1.LabelSelectorRequirement{
				{
					Key:      "projectcalico.org/tier",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"production"},
				},
			},
		},
	}))

	require.Len(t, d.got, 1)
	assert.Equal(t, "production", d.got[0].Tier, "the deny message tells users to pass a label selector, so we must honor one")
}

func TestNoTierWhenSelectorIsAmbiguous(t *testing.T) {
	d := &recordingDecider{result: tierauth.Result{Decision: tierauth.DecisionPermitted}}

	NewHook(d).Authorize(sarFor(&authorizationv1.ResourceAttributes{
		Group:    "projectcalico.org",
		Resource: "networkpolicies",
		Verb:     "list",
		FieldSelector: &authorizationv1.FieldSelectorAttributes{
			Requirements: []metav1.FieldSelectorRequirement{
				{
					Key:      "spec.tier",
					Operator: metav1.FieldSelectorOpIn,
					Values:   []string{"production", "staging"},
				},
			},
		},
	}))

	require.Len(t, d.got, 1)
	assert.Empty(t, d.got[0].Tier, "two tiers in one selector is not a single-tier request; fall through to the unrestricted check")
}

func TestUserInfoIsPassedThrough(t *testing.T) {
	d := &recordingDecider{result: tierauth.Result{Decision: tierauth.DecisionPermitted}}

	sar := sarFor(&authorizationv1.ResourceAttributes{
		Group:     "projectcalico.org",
		Resource:  "networkpolicies",
		Verb:      "get",
		Name:      "deny-external",
		Namespace: "ns1",
	})
	sar.Spec.UID = "uid-1"
	sar.Spec.Extra = map[string]authorizationv1.ExtraValue{"scopes": {"a", "b"}}

	NewHook(d).Authorize(sar)

	require.Len(t, d.got, 1)
	req := d.got[0]
	assert.Equal(t, "alice", req.User.GetName())
	assert.Equal(t, "uid-1", req.User.GetUID())
	assert.Equal(t, []string{"system:authenticated"}, req.User.GetGroups())
	assert.Equal(t, []string{"a", "b"}, req.User.GetExtra()["scopes"])
	assert.Equal(t, "deny-external", req.Name)
	assert.Equal(t, "ns1", req.Namespace)
}

func TestSlowDecisionDeniesOneRequestRatherThanTimingOutTheWebhook(t *testing.T) {
	original := decisionTimeout
	decisionTimeout = 50 * time.Millisecond
	t.Cleanup(func() { decisionTimeout = original })

	d := &blockingDecider{}
	start := time.Now()

	status := NewHook(d).Authorize(sarFor(&authorizationv1.ResourceAttributes{
		Group:     "projectcalico.org",
		Resource:  "networkpolicies",
		Verb:      "get",
		Namespace: "ns1",
		Name:      "deny-external",
	}))

	assert.False(t, status.Allowed, "the webhook must never return Allowed")
	assert.True(t, status.Denied, "an overrunning decision must produce a scoped deny")
	assert.Less(t, time.Since(start), time.Second,
		"the decision has to give up before the API server's webhook timeout, or the deny stops being scoped")
	require.False(t, d.deadline.IsZero(), "the decider must be handed a deadline")
	// A little slack: the deadline is set a moment after start is read.
	assert.False(t, d.deadline.After(start.Add(decisionTimeout+100*time.Millisecond)),
		"the deadline handed to the decider must be decisionTimeout, not something longer")
}
