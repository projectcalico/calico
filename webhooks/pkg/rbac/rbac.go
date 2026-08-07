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
	"fmt"
	"net/http"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admission/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

// TierGetter is an interface for retrieving Tier resources.
type TierGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v3.Tier, error)
}

// Decider makes the tier authorization decision. Implemented by tierauth.Authorizer.
type Decider interface {
	Authorize(ctx context.Context, req tierauth.Request) tierauth.Result
}

// RegisterHook registers the /rbac admission webhook handler.
func RegisterHook(decider Decider, tierGetter TierGetter, handleFn utils.HandleFn) {
	logrus.WithField("path", "/rbac").Info("Registering RBAC admission webhook")
	http.HandleFunc("/rbac", handleFn(NewTieredRBACHook(decider, tierGetter).Handler()))
}

// NewTieredRBACHook returns the tiered RBAC admission webhook backend.
//
// This hook covers only mutating operations. Unlike an authorization webhook it can read the
// object body, which is what lets it authorize a CREATE whose tier is only knowable from
// spec.tier. It is never called for GET, LIST or WATCH; those are the authorization webhook's.
func NewTieredRBACHook(decider Decider, tierGetter TierGetter) utils.HandlerProvider {
	return &tieredRBACHook{decider: decider, tierGetter: tierGetter}
}

// tieredRBACHook is an admission webhook that enforces tier-based RBAC on mutations.
type tieredRBACHook struct {
	decider    Decider
	tierGetter TierGetter
}

// Handler returns an AdmissionReviewHandler that processes admission reviewes for tiered policies and checks whether the user is authorized to
// perform the operation. It is the main entry point for the webhook.
func (h *tieredRBACHook) Handler() utils.AdmissionReviewHandler {
	return utils.NewDelegateToV1AdmitHandler(h.authorize)
}

func (h *tieredRBACHook) authorize(ar v1.AdmissionReview) *v1.AdmissionResponse {
	logCtx := logrus.WithFields(logrus.Fields{
		"uid":       ar.Request.UID,
		"kind":      ar.Request.Kind,
		"resource":  ar.Request.Resource,
		"operation": ar.Request.Operation,
		"name":      ar.Request.Name,
		"namespace": ar.Request.Namespace,
		"user":      ar.Request.UserInfo.Username,
	})
	logCtx.Debug("Handling admission review")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Parse the new object (from Object.Raw) and old object (from OldObject.Raw) to extract
	// tier information. CREATE/UPDATE have Object.Raw; UPDATE/DELETE have OldObject.Raw.
	var (
		obj              client.Object
		newTier, oldTier string
		err              error
	)

	if len(ar.Request.Object.Raw) > 0 {
		obj, newTier, err = h.parsePolicy(ar.Request.Kind.Kind, ar.Request.Object.Raw)
		if err != nil {
			logCtx.WithError(err).Error("Failed to parse policy")
			return &v1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Message: fmt.Sprintf("Failed to parse policy: %v", err),
					Reason:  metav1.StatusReasonInvalid,
				},
			}
		}
	}
	if len(ar.Request.OldObject.Raw) > 0 {
		var oldObj client.Object
		oldObj, oldTier, err = h.parsePolicy(ar.Request.Kind.Kind, ar.Request.OldObject.Raw)
		if err != nil {
			logCtx.WithError(err).Error("Failed to parse old policy")
			return &v1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Message: fmt.Sprintf("Failed to parse old policy: %v", err),
					Reason:  metav1.StatusReasonInvalid,
				},
			}
		}
		if obj == nil {
			// DELETE: no new object, use the old object for context.
			obj = oldObj
		}
	}
	if obj == nil {
		logCtx.Warn("No object in admission request")
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: "No object in admission request",
				Reason:  metav1.StatusReasonBadRequest,
			},
		}
	}

	// Authorize the new tier for CREATE/UPDATE, or the old tier for DELETE.
	tier := newTier
	if tier == "" {
		tier = oldTier
	}
	logCtx = logCtx.WithFields(logrus.Fields{"newTier": newTier, "oldTier": oldTier})

	if resp := h.authorizeTier(ctx, logCtx, ar.Request, obj, tier, ""); resp != nil {
		return resp
	}

	// For CREATE and UPDATE, verify the target tier exists and is not being deleted.
	if newTier != "" {
		if resp := h.checkTierExists(ctx, logCtx, newTier); resp != nil {
			return resp
		}
	}

	// A tier change needs permission on the old tier too, to take the policy out of it.
	if newTier != "" && oldTier != "" && oldTier != newTier {
		if resp := h.authorizeTier(ctx, logCtx, ar.Request, obj, oldTier, "old tier"); resp != nil {
			return resp
		}
	}

	// If validation passes, return an allowed response
	logCtx.Debug("User is authorized")
	return &v1.AdmissionResponse{Allowed: true}
}

// checkTierExists verifies the tier exists and is not terminating. Returns an AdmissionResponse if
// the tier is invalid, or nil if the tier is valid.
func (h *tieredRBACHook) checkTierExists(ctx context.Context, logCtx *logrus.Entry, tierName string) *v1.AdmissionResponse {
	tier, err := h.tierGetter.Get(ctx, tierName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			logCtx.WithField("tier", tierName).Warn("Tier does not exist")
			return &v1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Message: fmt.Sprintf("Tier %q does not exist", tierName),
					Reason:  metav1.StatusReasonForbidden,
				},
			}
		}
		logCtx.WithError(err).Error("Failed to get tier")
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("Failed to verify tier existence: %v", err),
				Reason:  metav1.StatusReasonInternalError,
			},
		}
	}
	if tier.DeletionTimestamp != nil {
		logCtx.WithField("tier", tierName).Warn("Tier is being deleted")
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("Tier %q is being deleted", tierName),
				Reason:  metav1.StatusReasonForbidden,
			},
		}
	}
	return nil
}

// parsePolicy decodes the raw JSON of the policy object from the admission request and extracts the tier information.
func (h *tieredRBACHook) parsePolicy(kind string, body []byte) (client.Object, string, error) {
	// Create an empty object of the appropriate type.
	var obj client.Object
	switch kind {
	case v3.KindNetworkPolicy:
		obj = &v3.NetworkPolicy{}
	case v3.KindGlobalNetworkPolicy:
		obj = &v3.GlobalNetworkPolicy{}
	case v3.KindStagedNetworkPolicy:
		obj = &v3.StagedNetworkPolicy{}
	case v3.KindStagedGlobalNetworkPolicy:
		obj = &v3.StagedGlobalNetworkPolicy{}
	case v3.KindStagedKubernetesNetworkPolicy:
		obj = &v3.StagedKubernetesNetworkPolicy{}
	default:
		return nil, "", fmt.Errorf("unsupported kind: %s", kind)
	}

	// Decode the object into the appropriate type.
	deserializer := utils.Codecs.UniversalDeserializer()
	_, _, err := deserializer.Decode(body, nil, obj)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode object: %v", err)
	}

	// Extract the tier from the policy's Spec.Tier field. StagedKubernetesNetworkPolicy
	// doesn't have a Tier field — it's always implicitly in the default tier.
	tier, ok := names.TierFromPolicy(obj)
	if !ok {
		if kind == v3.KindStagedKubernetesNetworkPolicy {
			return obj, names.DefaultTierName, nil
		}
		return nil, "", fmt.Errorf("object does not have a Spec.Tier field")
	}
	return obj, tier, nil
}

// authorizeTier calls the decider for tier and returns a non-nil admission response if the
// request must be refused. label identifies which tier this check is for in the denial
// message ("old tier", or "" for the primary check), since a tier move needs both.
func (h *tieredRBACHook) authorizeTier(ctx context.Context, logCtx *logrus.Entry, req *v1.AdmissionRequest, obj client.Object, tier, label string) *v1.AdmissionResponse {
	result := h.decider.Authorize(ctx, h.request(req, obj, tier))
	switch result.Decision {
	case tierauth.DecisionPermitted:
		return nil
	case tierauth.DecisionDenied:
		logCtx.WithField("reason", result.Reason).Warn("User is not authorized")
		return forbidden(label, result.Reason)
	default:
		// DecisionNotApplicable means the decider didn't recognize this as a tiered policy
		// request, which should be unreachable here — this hook only registers for the 5
		// tiered policy kinds. Deny rather than trust that unreachability holds.
		logCtx.WithField("reason", result.Reason).Error("Tier authorization returned no opinion for a tiered policy resource; denying")
		return internalError(fmt.Sprintf("could not determine tier authorization: %s", result.Reason))
	}
}

// request builds a tierauth.Request from an admission request and the tier in question.
func (h *tieredRBACHook) request(req *v1.AdmissionRequest, obj client.Object, tier string) tierauth.Request {
	extra := make(map[string][]string, len(req.UserInfo.Extra))
	for k, v := range req.UserInfo.Extra {
		extra[k] = []string(v)
	}

	return tierauth.Request{
		User: &user.DefaultInfo{
			Name:   req.UserInfo.Username,
			UID:    req.UserInfo.UID,
			Groups: req.UserInfo.Groups,
			Extra:  extra,
		},
		Verb:      strings.ToLower(string(req.Operation)),
		Resource:  req.Resource.Resource,
		Namespace: req.Namespace,
		Name:      obj.GetName(),
		Tier:      tier,
	}
}

// forbidden builds a Denied admission response. label distinguishes which tier check
// produced reason, e.g. "old tier" for the source side of a tier move.
func forbidden(label, reason string) *v1.AdmissionResponse {
	msg := fmt.Sprintf("Authorization failed: %s", reason)
	if label != "" {
		msg = fmt.Sprintf("Authorization failed for %s: %s", label, reason)
	}
	return &v1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: msg,
			Reason:  metav1.StatusReasonForbidden,
		},
	}
}

func internalError(msg string) *v1.AdmissionResponse {
	return &v1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: msg,
			Reason:  metav1.StatusReasonInternalError,
		},
	}
}
