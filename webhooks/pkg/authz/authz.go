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

package authz

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	kauth "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/cel"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook/metrics"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
)

// HandleAuthzFn is a function type that takes an AuthzHandler and returns an http.HandlerFunc.
type HandleAuthzFn func(handler AuthzHandler) func(http.ResponseWriter, *http.Request)

// AuthzHandler processes SubjectAccessReview requests and returns a response.
type AuthzHandler interface {
	Authorize(authorizationv1.SubjectAccessReview) *authorizationv1.SubjectAccessReviewStatus
}

// tieredPolicyResources is the set of resources that are tiered policy resources.
var tieredPolicyResources = map[string]bool{
	"networkpolicies":                 true,
	"globalnetworkpolicies":           true,
	"stagednetworkpolicies":           true,
	"stagedglobalnetworkpolicies":     true,
	"stagedkubernetesnetworkpolicies": true,
}

// readVerbs is the set of verbs handled by this authorization webhook.
// Mutating verbs (create, update, patch, delete, deletecollection) are left to the
// admission webhook, which already enforces tier-based RBAC for those operations.
var readVerbs = map[string]bool{
	"get":   true,
	"list":  true,
	"watch": true,
}

// RegisterHook creates a new authorization webhook handler and registers the /authz HTTP handler.
func RegisterHook(cs kubernetes.Interface, handleFn HandleAuthzFn) {
	logrus.WithFields(logrus.Fields{
		"path": "/authz",
	}).Info("Registering authorization webhook")

	// Create a new Kubernetes authorizer.
	bo := webhook.DefaultRetryBackoff()
	m := &metrics.NoopAuthorizerMetrics{}
	compl := cel.NewDefaultCompiler()

	authz, err := webhook.NewFromInterface(cs.AuthorizationV1(), 5*time.Second, 5*time.Second, *bo, kauth.DecisionDeny, m, compl)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create webhook authorizer")
	}
	handler := &authzHook{authz: authorizer.NewTierAuthorizer(authz)}

	http.HandleFunc("/authz", handleFn(handler))
}

// authzHook is an authorization webhook that enforces tier-based RBAC.
type authzHook struct {
	authz authorizer.TierAuthorizer
}

// Authorize processes a SubjectAccessReview and returns a status indicating
// whether the request is allowed, denied, or has no opinion.
func (h *authzHook) Authorize(sar authorizationv1.SubjectAccessReview) *authorizationv1.SubjectAccessReviewStatus {
	spec := sar.Spec

	// We only handle resource requests for tiered policy resources in the projectcalico.org API group.
	if spec.ResourceAttributes == nil {
		return noOpinion("non-resource request")
	}
	ra := spec.ResourceAttributes
	if ra.Group != v3.SchemeGroupVersion.Group {
		return noOpinion("not projectcalico.org group")
	}
	if !tieredPolicyResources[ra.Resource] {
		return noOpinion("not a tiered policy resource")
	}
	if !readVerbs[strings.ToLower(ra.Verb)] {
		// Mutating verbs (create, update, patch, delete) are handled by the admission webhook.
		return noOpinion("mutating verb handled by admission webhook")
	}

	logCtx := logrus.WithFields(logrus.Fields{
		"user":      spec.User,
		"verb":      ra.Verb,
		"resource":  ra.Resource,
		"name":      ra.Name,
		"namespace": ra.Namespace,
	})
	logCtx.Debug("Handling authorization review for tiered policy")

	// Extract the tier from the field selector on the request.
	tier := extractTierFromFieldSelector(ra)
	if tier == "" {
		logCtx.Debug("Could not determine tier, returning NoOpinion")
		return noOpinion("tier could not be determined")
	}

	logCtx = logCtx.WithField("tier", tier)

	// Build context with user info and request info for the TierAuthorizer.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = augmentContext(ctx, spec, ra)

	// Check if the user is authorized to access the tier.
	if err := h.authz.AuthorizeTierOperation(ctx, ra.Name, tier); err != nil {
		logCtx.WithError(err).Warn("User is not authorized for tier")
		return deny(fmt.Sprintf("Authorization failed: %v", err))
	}

	// User is authorized for the tier — return NoOpinion so that RBAC can
	// still check base resource permissions.
	logCtx.Debug("User is authorized for tier, returning NoOpinion")
	return noOpinion("tier access authorized, deferring to RBAC for base permission")
}

// extractTierFromFieldSelector extracts the tier from the field selector on the
// resource attributes. Returns the tier name, or empty string if no spec.tier
// field selector is present.
func extractTierFromFieldSelector(ra *authorizationv1.ResourceAttributes) string {
	if ra.FieldSelector != nil {
		for _, req := range ra.FieldSelector.Requirements {
			if req.Key == "spec.tier" && req.Operator == metav1.FieldSelectorOpIn && len(req.Values) == 1 {
				return req.Values[0]
			}
		}
	}
	return ""
}

// augmentContext creates a context with user info and request info needed by the TierAuthorizer.
func augmentContext(ctx context.Context, spec authorizationv1.SubjectAccessReviewSpec, ra *authorizationv1.ResourceAttributes) context.Context {
	// Build user info.
	extra := map[string][]string{}
	for k, v := range spec.Extra {
		extra[k] = []string(v)
	}
	info := &user.DefaultInfo{
		Name:   spec.User,
		UID:    spec.UID,
		Groups: spec.Groups,
		Extra:  extra,
	}

	// Build request info.
	path := fmt.Sprintf("/apis/projectcalico.org/v3/%s", ra.Resource)
	if ra.Namespace != "" {
		path = fmt.Sprintf("/apis/projectcalico.org/v3/namespaces/%s/%s", ra.Namespace, ra.Resource)
	}
	if ra.Name != "" {
		path = path + "/" + ra.Name
	}

	ri := &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Path:              path,
		Verb:              strings.ToLower(ra.Verb),
		APIGroup:          v3.SchemeGroupVersion.Group,
		APIVersion:        v3.SchemeGroupVersion.Version,
		Resource:          ra.Resource,
		Name:              ra.Name,
		Namespace:         ra.Namespace,
	}

	if ra.Namespace != "" {
		ctx = genericapirequest.WithNamespace(ctx, ra.Namespace)
	}
	ctx = genericapirequest.WithUser(ctx, info)
	ctx = genericapirequest.WithRequestInfo(ctx, ri)
	return ctx
}

// noOpinion returns a SubjectAccessReviewStatus indicating no opinion.
func noOpinion(reason string) *authorizationv1.SubjectAccessReviewStatus {
	return &authorizationv1.SubjectAccessReviewStatus{
		Allowed: false,
		Denied:  false,
		Reason:  reason,
	}
}

// deny returns a SubjectAccessReviewStatus denying the request.
func deny(reason string) *authorizationv1.SubjectAccessReviewStatus {
	return &authorizationv1.SubjectAccessReviewStatus{
		Allowed: false,
		Denied:  true,
		Reason:  reason,
	}
}
