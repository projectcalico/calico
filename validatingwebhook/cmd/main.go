// Copyright 2025 Tigera, Inc.
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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	kauth "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/cel"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook/metrics"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/cli"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/crypto/pkg/tls"
)

var (
	certFile string
	keyFile  string
	port     int
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func addToScheme(scheme *runtime.Scheme) {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(admissionv1.AddToScheme(scheme))
	utilruntime.Must(admissionregistrationv1.AddToScheme(scheme))
}

// CmdWebhook is used by agnhost Cobra.
var CmdWebhook = &cobra.Command{
	Use:   "webhook",
	Short: "Starts an HTTP server for Calicco admission webhooks.",
	Long:  `Starts an HTTP server for Calicco admission webhooks.`,
	Args:  cobra.MaximumNArgs(0),
	Run:   serveTLS,
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(os.Stdout)

	rootCmd := &cobra.Command{Use: "webhook"}
	rootCmd.AddCommand(CmdWebhook)

	os.Exit(cli.Run(rootCmd))
}

func init() {
	addToScheme(scheme)
	CmdWebhook.Flags().StringVar(&certFile, "tls-cert-file", "", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert).")
	CmdWebhook.Flags().StringVar(&keyFile, "tls-private-key-file", "", "File containing the default x509 private key matching --tls-cert-file.")
	CmdWebhook.Flags().IntVar(&port, "port", 6443, "Secure port that the webhook listens on")
}

type v1AdmissionFunc func(v1.AdmissionReview) *v1.AdmissionResponse

// admissionReviewHandler is a handler, for both validators and mutators, that supports multiple admission review versions
type admissionReviewHandler struct {
	processV1Review v1AdmissionFunc
}

func newDelegateToV1AdmitHandler(f v1AdmissionFunc) admissionReviewHandler {
	return admissionReviewHandler{processV1Review: f}
}

func serveTLS(cmd *cobra.Command, args []string) {
	cfg, err := tls.NewTLSConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create TLS config")
	}

	// Create a new rbacHook.
	rc, err := rest.InClusterConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create in-cluster config")
	}

	// Create a clientset for the Kubernetes API.
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create clientset")
	}

	// Create a nwe Kubernetes authorizer.
	bo := webhook.DefaultRetryBackoff()
	m := &metrics.NoopAuthorizerMetrics{}
	compl := cel.NewDefaultCompiler()
	a, err := webhook.NewFromInterface(cs.AuthorizationV1(), 5*time.Second, 5*time.Second, *bo, kauth.DecisionDeny, m, compl)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create webhook authorizer")
	}

	// Define
	hook := &tieredRBACHook{authz: authorizer.NewTierAuthorizer(a)}

	http.HandleFunc("/", hook.Authorize)
	http.HandleFunc("/readyz", func(w http.ResponseWriter, req *http.Request) { w.Write([]byte("ok")) })

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: cfg,
	}

	err = server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to start webhook server on port %d", port)
	}
}

// tieredRBACHook is an admission webhook that uses RBAC to authorize requests based on the tier of the policy being created/updated/deleted.
type tieredRBACHook struct {
	calc  rbac.Calculator
	authz authorizer.TierAuthorizer
}

func (h *tieredRBACHook) Authorize(w http.ResponseWriter, r *http.Request) {
	handleRequest(w, r, newDelegateToV1AdmitHandler(h.authorize))
}

func (h *tieredRBACHook) parsePolicyMetadata(kind string, body []byte) (client.Object, string, error) {
	// Create an empty object of the appropriate type.
	var obj client.Object
	switch kind {
	case "NetworkPolicy":
		obj = &v3.NetworkPolicy{}
	case "GlobalNetworkPolicy":
		obj = &v3.GlobalNetworkPolicy{}
	case "StagedNetworkPolicy":
		obj = &v3.StagedNetworkPolicy{}
	case "StagedGlobalNetworkPolicy":
		obj = &v3.StagedGlobalNetworkPolicy{}
	case "StagedKubernetesNetworkPolicy":
		obj = &v3.StagedKubernetesNetworkPolicy{}
	default:
		return nil, "", fmt.Errorf("unsupported kind: %s", kind)
	}

	// Decode the object into the appropriate type.
	deserializer := codecs.UniversalDeserializer()
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

func getTier(obj any) (string, bool) {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
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

	obj, tier, err := h.parsePolicyMetadata(ar.Request.Kind.Kind, ar.Request.Object.Raw)
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
	ctx = requestContext(ar.Request, obj)

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

// handleRequest handles an incoming HTTP request, decodes the AdmissionReview, processes it, and writes the response.
func handleRequest(w http.ResponseWriter, r *http.Request, admit admissionReviewHandler) {
	// Decode the AdmissionReview request.
	obj, gvk, err := decodeAdmissionReview(r)
	if err != nil {
		logrus.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Process the AdmissionReview request.
	responseObj, err := processAdmissionReview(obj, gvk, admit)
	if err != nil {
		logrus.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Encode and send the AdmissionReview response.
	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		logrus.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		logrus.Error(err)
	}
}

func decodeAdmissionReview(r *http.Request) (runtime.Object, *schema.GroupVersionKind, error) {
	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	} else {
		return nil, nil, fmt.Errorf("empty body")
	}

	// Verify the content type is accurate
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		return nil, nil, fmt.Errorf("invalid Content-Type '%s', expected `application/json`", ct)
	}

	// Decoee the body into an AdmissionReview object, and check the
	// GroupVersionKind to ensure it's something we support.
	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Request could not be decoded: %v", err)
	}
	return obj, gvk, nil
}

func processAdmissionReview(obj runtime.Object, gvk *schema.GroupVersionKind, handler admissionReviewHandler) (*v1.AdmissionReview, error) {
	switch *gvk {
	case v1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1.AdmissionReview)
		if !ok {
			return nil, fmt.Errorf("Expected v1.AdmissionReview but got: %T", obj)
		}
		responseAdmissionReview := &v1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = handler.processV1Review(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		return responseAdmissionReview, nil
	default:
		return nil, fmt.Errorf("Unsupported group version kind: %v", gvk)
	}
}

func requestContext(req *v1.AdmissionRequest, obj client.Object) context.Context {
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
	}

	// Create a RequestInfo object from the AdmissionRequest.
	ri := &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Path:              fmt.Sprintf("/apis/projectcalico.org/v3/%s/%s", resource, obj.GetName()),
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
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, &info)
	ctx = genericapirequest.WithRequestInfo(ctx, ri)
	return ctx
}
