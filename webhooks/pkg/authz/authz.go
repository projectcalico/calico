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

// Package authz serves the Kubernetes authorization webhook. It decodes
// SubjectAccessReviews, hands the request to tierauth, and encodes the verdict. It holds no
// authorization logic of its own beyond deciding which requests it handles at all.
package authz

import (
	"context"
	"net/http"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
)

// HandleAuthzFn takes an AuthzHandler and returns an http.HandlerFunc.
type HandleAuthzFn func(handler AuthzHandler) func(http.ResponseWriter, *http.Request)

// AuthzHandler processes SubjectAccessReview requests and returns a response.
type AuthzHandler interface {
	Authorize(authorizationv1.SubjectAccessReview) *authorizationv1.SubjectAccessReviewStatus
}

// Decider makes the tier authorization decision. Implemented by tierauth.Authorizer.
type Decider interface {
	Authorize(ctx context.Context, req tierauth.Request) tierauth.Result
}

// readVerbs are the verbs this webhook handles. Mutating verbs are the admission webhook's,
// which unlike this one can see the object body.
var readVerbs = map[string]bool{
	"get":   true,
	"list":  true,
	"watch": true,
}

// decisionTimeout bounds a single authorization decision, including any fallback GET. It must stay
// below the webhook timeout in webhooks/config/authorization-configuration.yaml, so a slow decision
// denies one request rather than failing the webhook; a drift test asserts it. A var so the
// overrun test can shorten it.
var decisionTimeout = 2 * time.Second

// RegisterHook registers the /authz HTTP handler.
func RegisterHook(decider Decider, handleFn HandleAuthzFn) {
	logrus.WithField("path", "/authz").Info("Registering authorization webhook")
	http.HandleFunc("/authz", handleFn(NewHook(decider)))
}

// RegisterDisabledHook registers /authz answering NoOpinion for every request.
//
// Registered rather than left off, because an unregistered path returns 404, the API server reads
// that as a webhook failure, and under failurePolicy: Deny that denies every projectcalico.org
// request in the cluster. So an operator who sets --authorization-config without enabling the
// feature gets the pre-webhook status quo instead of an outage.
func RegisterDisabledHook(handleFn HandleAuthzFn) {
	logrus.WithField("path", "/authz").Warn(
		"Authorization webhook is disabled: answering NoOpinion for every request. " +
			"Pass --authz-enabled to enforce tier RBAC on reads")
	http.HandleFunc("/authz", handleFn(disabledHook{}))
}

// disabledHook answers NoOpinion for every request.
type disabledHook struct{}

func (disabledHook) Authorize(authorizationv1.SubjectAccessReview) *authorizationv1.SubjectAccessReviewStatus {
	return noOpinion("the Calico authorization webhook is disabled")
}

// Hook adapts SubjectAccessReview traffic onto a Decider.
type Hook struct {
	decider Decider
}

// NewHook returns a Hook that decides via decider.
func NewHook(decider Decider) *Hook {
	return &Hook{decider: decider}
}

// Authorize processes a SubjectAccessReview. It returns Denied or NoOpinion, never Allowed:
// this authorizer runs ahead of RBAC, so an Allow would grant base permissions the user does
// not have.
func (h *Hook) Authorize(sar authorizationv1.SubjectAccessReview) *authorizationv1.SubjectAccessReviewStatus {
	ra := sar.Spec.ResourceAttributes
	if ra == nil {
		return noOpinion("non-resource request")
	}
	if ra.Group != v3.SchemeGroupVersion.Group {
		return noOpinion("not the projectcalico.org group")
	}
	if !tierauth.IsTieredPolicyResource(ra.Resource) {
		return noOpinion("not a tiered policy resource")
	}
	if !readVerbs[strings.ToLower(ra.Verb)] {
		return noOpinion("mutating verb handled by the admission webhook")
	}

	ctx, cancel := context.WithTimeout(context.Background(), decisionTimeout)
	defer cancel()

	result := h.decider.Authorize(ctx, tierauth.Request{
		User:      userInfo(sar.Spec),
		Verb:      strings.ToLower(ra.Verb),
		Resource:  ra.Resource,
		Namespace: ra.Namespace,
		Name:      ra.Name,
		Tier:      extractTierFromSelectors(ra),
	})

	// tierauth.Authorize already logs the deny with every field this hook could add, so
	// there is no logging here: doing it at both layers would print every deny twice.
	if result.Decision == tierauth.DecisionDenied {
		return deny(result.Reason)
	}

	return noOpinion(result.Reason)
}

// extractTierFromSelectors returns the single tier the request is scoped to, or empty if the
// request is not scoped to exactly one tier. Both the spec.tier field selector and the
// projectcalico.org/tier label selector count, since the deny message points users at the latter.
//
// The API server only populates these fields when the AuthorizeWithSelectors feature gate is on,
// which it is by default from Kubernetes 1.32; the README declares that as the floor.
func extractTierFromSelectors(ra *authorizationv1.ResourceAttributes) string {
	if ra.FieldSelector != nil {
		for _, req := range ra.FieldSelector.Requirements {
			if req.Key == "spec.tier" && req.Operator == metav1.FieldSelectorOpIn && len(req.Values) == 1 {
				return req.Values[0]
			}
		}
	}
	if ra.LabelSelector != nil {
		for _, req := range ra.LabelSelector.Requirements {
			if req.Key != v3.LabelTier || len(req.Values) != 1 {
				continue
			}
			if req.Operator == metav1.LabelSelectorOpIn {
				return req.Values[0]
			}
		}
	}
	return ""
}

// userInfo converts the SubjectAccessReview's user fields into a user.Info.
func userInfo(spec authorizationv1.SubjectAccessReviewSpec) user.Info {
	extra := make(map[string][]string, len(spec.Extra))
	for k, v := range spec.Extra {
		extra[k] = []string(v)
	}
	return &user.DefaultInfo{
		Name:   spec.User,
		UID:    spec.UID,
		Groups: spec.Groups,
		Extra:  extra,
	}
}

func noOpinion(reason string) *authorizationv1.SubjectAccessReviewStatus {
	return &authorizationv1.SubjectAccessReviewStatus{
		Allowed: false,
		Denied:  false,
		Reason:  reason,
	}
}

func deny(reason string) *authorizationv1.SubjectAccessReviewStatus {
	return &authorizationv1.SubjectAccessReviewStatus{
		Allowed: false,
		Denied:  true,
		Reason:  reason,
	}
}
