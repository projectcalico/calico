/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	kauth "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/cel"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook/metrics"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/cli"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/crypto/pkg/tls"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
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
	Short: "Starts a HTTP server, useful for testing MutatingAdmissionWebhook and ValidatingAdmissionWebhook",
	Long: `Starts a HTTP server, useful for testing MutatingAdmissionWebhook and ValidatingAdmissionWebhook.
After deploying it to Kubernetes cluster, the Administrator needs to create a ValidatingWebhookConfiguration
in the Kubernetes cluster to register remote webhook admission controllers.`,
	Args: cobra.MaximumNArgs(0),
	Run:  hook,
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(os.Stdout)

	rootCmd := &cobra.Command{
		Use: "webhook",
	}
	rootCmd.AddCommand(CmdWebhook)

	os.Exit(cli.Run(rootCmd))
}

func init() {
	addToScheme(scheme)
	CmdWebhook.Flags().StringVar(&certFile, "tls-cert-file", "", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert).")
	CmdWebhook.Flags().StringVar(&keyFile, "tls-private-key-file", "", "File containing the default x509 private key matching --tls-cert-file.")
	CmdWebhook.Flags().IntVar(&port, "port", 6443, "Secure port that the webhook listens on")
}

type admitv1Func func(v1.AdmissionReview) *v1.AdmissionResponse

// admitHandler is a handler, for both validators and mutators, that supports multiple admission review versions
type admitHandler struct {
	v1 admitv1Func
}

func newDelegateToV1AdmitHandler(f admitv1Func) admitHandler {
	return admitHandler{v1: f}
}

// serve handles the http portion of a request prior to handing to an admit
// function
func serve(w http.ResponseWriter, r *http.Request, admit admitHandler) {
	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		logrus.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	logrus.Info(fmt.Sprintf("handling request: %s", body))

	deserializer := codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		logrus.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case v1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1.AdmissionReview)
		if !ok {
			logrus.Errorf("Expected v1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &v1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.v1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		logrus.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	logrus.Info(fmt.Sprintf("sending response: %v", responseObj))
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

func hook(cmd *cobra.Command, args []string) {
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
	hook := &rbacHook{authz: authorizer.NewTierAuthorizer(a)}

	http.HandleFunc("/", hook.Validate)
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

type rbacHook struct {
	calc  rbac.Calculator
	authz authorizer.TierAuthorizer
}

func (h *rbacHook) Validate(w http.ResponseWriter, r *http.Request) {
	serve(w, r, newDelegateToV1AdmitHandler(h.handleValidate))
}

func (h *rbacHook) handleValidate(ar v1.AdmissionReview) *v1.AdmissionResponse {
	logrus.Infof("validate called with request: %v", ar.Request)
	ctx := context.TODO()

	// Unpack the AdmissionReview object into a struct.
	var obj client.Object
	switch ar.Request.Kind.Kind {
	case "NetworkPolicy":
		obj = &v3.NetworkPolicy{}
		deserializer := codecs.UniversalDeserializer()
		obj, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, obj)
		if err != nil {
			logrus.Errorf("Failed to decode object: %v", err)
			return &v1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Message: fmt.Sprintf("Failed to decode object: %v", err),
					Reason:  metav1.StatusReasonInvalid,
				},
			}
		}
		logrus.Infof("Decoded object: %T", obj)
		extra := map[string][]string{}
		for k, v := range ar.Request.UserInfo.Extra {
			extra[k] = v
		}
		info := user.DefaultInfo{
			Name:   ar.Request.UserInfo.Username,
			UID:    ar.Request.UserInfo.UID,
			Groups: ar.Request.UserInfo.Groups,
			Extra:  extra,
		}
		ctx = requestContext(ar.Request, &info)

		pol := obj.(*v3.NetworkPolicy)
		tier := pol.Spec.Tier
		if tier == "" {
			// Needed for delete since there is no spec - can we do this better?
			// Might need to query the existing object and get the tier from there.
			tier = "default"
		}
		if err = h.authz.AuthorizeTierOperation(ctx, pol.Name, tier); err != nil {
			logrus.Errorf("Authorization failed: %v", err)
			return &v1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Message: fmt.Sprintf("Authorization failed: %v", err),
					Reason:  metav1.StatusReasonForbidden,
				},
			}
		}
	case "GlobalNetworkPolicy":
	case "StagedNetworkPolicy":
	}

	// If validation passes, return an allowed response
	return &v1.AdmissionResponse{Allowed: true}
}

func NewCalicoResourceLister() rbac.CalicoResourceLister {
	// Create informers for Calico resources.
	rc, err := rest.InClusterConfig()
	if err != nil {
		panic(err)
	}
	v3c := clientset.NewForConfigOrDie(rc)

	return &calicoResourceLister{cli: v3c}
}

type calicoResourceLister struct {
	cli clientset.Interface
}

func (c *calicoResourceLister) ListTiers() ([]*v3.Tier, error) {
	l, err := c.cli.ProjectcalicoV3().Tiers().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	items := make([]*v3.Tier, len(l.Items))
	for i := range l.Items {
		items[i] = &l.Items[i]
	}
	return items, err
}

func requestContext(req *v1.AdmissionRequest, user user.Info) context.Context {
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, user)
	ri := &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Path:              "/apis/projectcalico.org/v3/networkpolicies/" + req.Name,
		Verb:              string(req.Operation),
		APIGroup:          "projectcalico.org",
		APIVersion:        "v3",
		Resource:          "networkpolicies",
		Name:              req.Name,
		Namespace:         req.Namespace,
	}
	if req.Operation == v1.Connect {
		ri.Name = ""
		ri.Path = "/apis/projectcalico.org/v3/networkpolicies"
	}
	ctx = genericapirequest.WithRequestInfo(ctx, ri)
	return ctx
}
