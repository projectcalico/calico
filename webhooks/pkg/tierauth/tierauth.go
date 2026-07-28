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

// Package tierauth makes Calico tier-based RBAC decisions independently of how the
// request arrived. Both the admission webhook (which sees object bodies) and the
// authorization webhook (which does not) call into it, so that the two cannot drift.
package tierauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/webhooks/pkg/metrics"
)

// Decision is the outcome of a tier authorization check.
type Decision int

const (
	// DecisionPermitted means the user is authorized for the tier in question. On the
	// authorization path this still maps to NoOpinion on the wire, so that RBAC gets to
	// check base resource permission. See the never-Allow invariant in the design doc.
	DecisionPermitted Decision = iota

	// DecisionDenied means the request must be rejected.
	DecisionDenied

	// DecisionNotApplicable means tier authorization has nothing to say about this request.
	DecisionNotApplicable
)

// String returns the metric label for a decision.
func (d Decision) String() string {
	switch d {
	case DecisionPermitted:
		return "permitted"
	case DecisionDenied:
		return "denied"
	default:
		return "not_applicable"
	}
}

// Result is a Decision plus a human-readable reason. The reason is surfaced to the
// client in the Forbidden message, so it is user-facing text.
type Result struct {
	Decision Decision
	Reason   string
}

// Request describes a policy access to authorize. Tier is empty when the caller could
// not determine one, which for a list or watch means the request was unselectored.
type Request struct {
	User user.Info

	Verb      string
	Resource  string
	Namespace string
	Name      string

	Tier string
}

// PolicyTierResolver reports which tier a named policy belongs to.
type PolicyTierResolver interface {
	TierForPolicy(ctx context.Context, resource, namespace, name string) (string, error)
}

// ErrPolicyNotFound is returned by a PolicyTierResolver when the policy does not exist.
var ErrPolicyNotFound = errors.New("policy not found")

// tieredPolicyResources is the set of resources whose access is scoped by tier.
var tieredPolicyResources = map[string]bool{
	"networkpolicies":                 true,
	"globalnetworkpolicies":           true,
	"stagednetworkpolicies":           true,
	"stagedglobalnetworkpolicies":     true,
	"stagedkubernetesnetworkpolicies": true,
}

// IsTieredPolicyResource reports whether the named resource is scoped by tier.
func IsTieredPolicyResource(resource string) bool {
	return tieredPolicyResources[resource]
}

// Authorizer decides tier access. Construct one per process and share it between hooks.
type Authorizer struct {
	tiers    authorizer.TierAuthorizer
	resolver PolicyTierResolver
}

// New returns an Authorizer that authorizes via tiers and resolves policy tiers via resolver.
func New(tiers authorizer.TierAuthorizer, resolver PolicyTierResolver) *Authorizer {
	return &Authorizer{tiers: tiers, resolver: resolver}
}

// Authorize decides whether req is permitted by tier-based RBAC.
func (a *Authorizer) Authorize(ctx context.Context, req Request) Result {
	start := time.Now()
	result := a.authorize(ctx, req)

	metrics.DecisionDuration.WithLabelValues(req.Resource, req.Verb).Observe(time.Since(start).Seconds())
	metrics.DecisionsTotal.WithLabelValues(result.Decision.String(), req.Resource, req.Verb).Inc()

	return result
}

// authorize is the decision logic proper. Authorize wraps it to record metrics uniformly
// across every return path, without scattering instrumentation through the branches below.
func (a *Authorizer) authorize(ctx context.Context, req Request) Result {
	if !IsTieredPolicyResource(req.Resource) {
		return Result{Decision: DecisionNotApplicable, Reason: "not a tiered policy resource"}
	}

	logCtx := logrus.WithFields(logrus.Fields{
		"user":      req.User.GetName(),
		"verb":      req.Verb,
		"resource":  req.Resource,
		"namespace": req.Namespace,
		"name":      req.Name,
		"tier":      req.Tier,
	})

	tier := req.Tier

	// A named request with no tier from the caller: look the policy up. Only the
	// authorization webhook hits this, since the admission webhook reads spec.tier
	// straight out of the object body.
	if tier == "" && req.Name != "" {
		resolved, err := a.resolver.TierForPolicy(ctx, req.Resource, req.Namespace, req.Name)
		switch {
		case errors.Is(err, ErrPolicyNotFound):
			// Let RBAC run so the API server can return its usual 404.
			return Result{Decision: DecisionNotApplicable, Reason: "policy does not exist"}
		case err != nil:
			reason := fmt.Sprintf("could not determine the tier of policy %q", req.Name)
			logCtx.WithError(err).WithField("reason", reason).Warn("Denied: failed to resolve policy tier")
			return Result{Decision: DecisionDenied, Reason: reason}
		}
		tier = resolved
		logCtx = logCtx.WithField("resolvedTier", tier)
	}

	// An empty tier and an empty name reach AuthorizeTierOperation as an unnamed check,
	// which RBAC matches only against rules that carry no resourceNames. That is exactly
	// "is this user unrestricted by tier".
	if err := a.tiers.AuthorizeTierOperation(a.withAttributes(ctx, req), req.Name, tier); err != nil {
		reason := a.denyReason(req, tier, err)
		logCtx.WithField("resolvedTier", tier).WithField("reason", reason).Info("Denied tier access")
		return Result{Decision: DecisionDenied, Reason: reason}
	}

	return Result{Decision: DecisionPermitted, Reason: "authorized for tier"}
}

// denyReason builds the message the client sees. For an unselectored list or watch we can
// tell the user how to make the request succeed, which is the only actionable case.
func (a *Authorizer) denyReason(req Request, tier string, err error) string {
	if tier == "" && req.Name == "" {
		return fmt.Sprintf(
			"%v: reading %s across all tiers requires tier-unrestricted access; "+
				"select a single tier instead, e.g. --selector %s=<tier>",
			err, req.Resource, v3.LabelTier,
		)
	}
	return err.Error()
}

// withAttributes attaches the user and request info that AuthorizeTierOperation reads back
// out of the context via filters.GetAuthorizerAttributes. Consolidated here so that the two
// hooks cannot build these attributes differently.
func (a *Authorizer) withAttributes(ctx context.Context, req Request) context.Context {
	path := fmt.Sprintf("/apis/%s/%s/%s", v3.SchemeGroupVersion.Group, v3.SchemeGroupVersion.Version, req.Resource)
	if req.Namespace != "" {
		path = fmt.Sprintf(
			"/apis/%s/%s/namespaces/%s/%s",
			v3.SchemeGroupVersion.Group,
			v3.SchemeGroupVersion.Version,
			req.Namespace,
			req.Resource,
		)
		ctx = genericapirequest.WithNamespace(ctx, req.Namespace)
	}
	if req.Name != "" {
		path = path + "/" + req.Name
	}

	ctx = genericapirequest.WithUser(ctx, req.User)

	return genericapirequest.WithRequestInfo(ctx, &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Path:              path,
		Verb:              strings.ToLower(req.Verb),
		APIGroup:          v3.SchemeGroupVersion.Group,
		APIVersion:        v3.SchemeGroupVersion.Version,
		Resource:          req.Resource,
		Name:              req.Name,
		Namespace:         req.Namespace,
	})
}
