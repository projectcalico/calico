// Copyright 2026 Tigera, Inc.
//
// Copyright 2018 The Kubernetes Authors.
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
	"reflect"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	kauth "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/cel"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook/metrics"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

// RegisterHook creates a new teired RBAC admission webhook authorizer and registers the necessary HTTP handler.
func RegisterHook(cs kubernetes.Interface, handleFn utils.HandleFn) {
	// Create a new Kubernetes authorizer.
	bo := webhook.DefaultRetryBackoff()
	m := &metrics.NoopAuthorizerMetrics{}
	compl := cel.NewDefaultCompiler()

	authz, err := webhook.NewFromInterface(cs.AuthorizationV1(), 5*time.Second, 5*time.Second, *bo, kauth.DecisionDeny, m, compl)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create webhook authorizer")
	}
	handler := NewTieredRBACHook(authorizer.NewTierAuthorizer(authz)).Handler()

	// Register the webhook handlers and a readiness endpoint.
	http.HandleFunc("/rbac", handleFn(handler))
}

// NewTieredRBACHook returns a new instance of the tiered RBAC admission webhook backend, which uses
// the provided TierAuthorizer to perform authorization checks.
func NewTieredRBACHook(authz authorizer.TierAuthorizer) utils.HandlerProvider {
	return &tieredRBACHook{authz: authz}
}

// tieredRBACHook is an admission webhook that uses RBAC to authorize requests based on tier.
type tieredRBACHook struct {
	calc  rbac.Calculator
	authz authorizer.TierAuthorizer
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

	// Extract the raw object from the admission request. In some cases (e.g., DELETE), the object may be in
	// the OldObject field instead of the Object field, so we check both.
	raw := ar.Request.Object.Raw
	if len(raw) == 0 {
		raw = ar.Request.OldObject.Raw
	}
	if len(raw) == 0 {
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

	// Parse the raw JSON.
	obj, tier, err := h.parsePolicy(ar.Request.Kind.Kind, raw)
	if err != nil {
		logCtx.WithError(err).Error("Failed to parse policy metadata")
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("Failed to parse policy metadata: %v", err),
				Reason:  metav1.StatusReasonInvalid,
			},
		}
	}

	// Log the tier being used for authorization.
	logCtx = logCtx.WithField("tier", tier)

	// Create a context with the necessary information to pass to the RBAC authorizer.
	// This includes the user info from the admission request.
	ctx, err = augmentContextWithUserInfo(ctx, ar.Request, obj)
	if err != nil {
		logCtx.WithError(err).Error("Failed to build authorization context")
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("Failed to build authorization context: %v", err),
				Reason:  metav1.StatusReasonInternalError,
			},
		}
	}

	// Run the RBAC authorizer to check if the user is authorized to perform the operation.
	if err = h.authz.AuthorizeTierOperation(ctx, obj.GetName(), tier); err != nil {
		logCtx.WithError(err).Warn("User is not authorized")
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("Authorization failed: %v", err),
				Reason:  metav1.StatusReasonForbidden,
			},
		}
	}

	// If validation passes, return an allowed response
	logCtx.Debug("User is authorized")
	return &v1.AdmissionResponse{Allowed: true}
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

	// Use reflection to access the Spec.Tier field.
	if tier, ok := getTier(obj); ok {
		return obj, tier, nil
	}
	return nil, "", fmt.Errorf("object does not have a Spec.Tier field")
}

// getTier uses reflection to access the Spec.Tier field of the given object, if it has one.
// It returns the tier and a boolean indicating whether the tier was successfully retrieved.
func getTier(obj any) (string, bool) {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	spec := v.FieldByName("Spec")
	if !spec.IsValid() {
		return "", false
	}
	tier := spec.FieldByName("Tier")
	if !tier.IsValid() {
		return "", false
	}
	if tier.Kind() != reflect.String {
		return "", false
	}
	return tier.String(), true
}

// augmentContextWithUserInfo adds the necessary user and request information from the admission request to the context so that it can
// be accessed by the RBAC authorizer.
func augmentContextWithUserInfo(ctx context.Context, req *v1.AdmissionRequest, obj client.Object) (context.Context, error) {
	// Create a user.Info object from the AdmissionRequest's UserInfo.
	extra := map[string][]string{}
	for k, v := range req.UserInfo.Extra {
		extra[k] = v
	}
	info := user.DefaultInfo{
		Name:   req.UserInfo.Username,
		UID:    req.UserInfo.UID,
		Groups: req.UserInfo.Groups,
		Extra:  extra,
	}

	var resource string
	switch obj.(type) {
	case *v3.NetworkPolicy:
		resource = "networkpolicies"
	case *v3.GlobalNetworkPolicy:
		resource = "globalnetworkpolicies"
	case *v3.StagedNetworkPolicy:
		resource = "stagednetworkpolicies"
	case *v3.StagedGlobalNetworkPolicy:
		resource = "stagedglobalnetworkpolicies"
	case *v3.StagedKubernetesNetworkPolicy:
		resource = "stagedkubernetesnetworkpolicies"
	default:
		return nil, fmt.Errorf("unsupported object type: %T", obj)
	}

	// Get the resource path.
	path := fmt.Sprintf("/apis/projectcalico.org/v3/%s/%s", resource, obj.GetName())
	if obj.GetNamespace() != "" {
		path = fmt.Sprintf("/apis/projectcalico.org/v3/namespaces/%s/%s/%s", obj.GetNamespace(), resource, obj.GetName())
	}

	// Create a RequestInfo object from the AdmissionRequest.
	ri := &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Path:              path,
		Verb:              strings.ToLower(string(req.Operation)),
		APIGroup:          v3.SchemeGroupVersion.Group,
		APIVersion:        v3.SchemeGroupVersion.Version,
		Resource:          resource,
		Name:              obj.GetName(),
		Namespace:         obj.GetNamespace(),
	}
	if req.Operation == v1.Connect {
		ri.Name = ""
	}

	// Create a context with the user info and request info.
	if obj.GetNamespace() != "" {
		ctx = genericapirequest.WithNamespace(ctx, obj.GetNamespace())
	}
	ctx = genericapirequest.WithUser(ctx, &info)
	ctx = genericapirequest.WithRequestInfo(ctx, ri)
	return ctx, nil
}
