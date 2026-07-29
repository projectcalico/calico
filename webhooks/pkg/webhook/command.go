// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/admission/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kauth "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/cel"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook"
	authzmetrics "k8s.io/apiserver/plugin/pkg/authorizer/webhook/metrics"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	ctls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/webhooks/pkg/authz"
	"github.com/projectcalico/calico/webhooks/pkg/clusterinfo"
	"github.com/projectcalico/calico/webhooks/pkg/metrics"
	"github.com/projectcalico/calico/webhooks/pkg/policycache"
	"github.com/projectcalico/calico/webhooks/pkg/rbac"
	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

var (
	certFile     string
	keyFile      string
	clientCAFile string
	logLevel     string
	port         int
	authzEnabled bool
)

// NewCommand returns a cobra.Command that serves Calico admission webhooks.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhooks",
		Short: "Run the Calico admission webhook server",
	}

	webhookCmd := &cobra.Command{
		Use:   "webhook",
		Short: "Starts an HTTP server for Calico admission webhooks.",
		Long:  `Starts an HTTP server for Calico admission webhooks.`,
		Args:  cobra.MaximumNArgs(0),
		Run:   serveWebhookTLS,
	}
	webhookCmd.Flags().StringVar(&certFile, "tls-cert-file", "", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert).")
	webhookCmd.Flags().StringVar(&keyFile, "tls-private-key-file", "", "File containing the default x509 private key matching --tls-cert-file.")
	webhookCmd.Flags().StringVar(&clientCAFile, "client-ca-file", "", "If set, enables mTLS by requiring and verifying client certificates signed by this CA.")
	webhookCmd.Flags().IntVar(&port, "port", 6443, "Secure port that the webhook listens on")
	webhookCmd.Flags().StringVar(&logLevel, "log-level", "info", "Logrus log level to output (trace, debug, info, warning, error, fatal, panic)")
	webhookCmd.Flags().BoolVar(&authzEnabled, "authz-enabled", false,
		"Enforce tier RBAC on reads via the /authz authorization webhook, and run the policy tier cache it needs. "+
			"Off by default: it also requires --authorization-config on the kube-apiserver, so it is opt-in. "+
			"/authz is served either way, answering NoOpinion when this is off.")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Prints version information about the webhook server.",
		Long:  `Prints version information about the webhook server.`,
		Run: func(cmd *cobra.Command, args []string) {
			buildinfo.PrintVersion()
		},
	}

	cmd.AddCommand(webhookCmd)
	cmd.AddCommand(versionCmd)
	return cmd
}

func configureLogging() {
	// Set up logging.
	l, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.WithError(err).Fatalf("Invalid log level: %s", logLevel)
	}
	logrus.SetLevel(l)
	logutils.ConfigureFormatter("webhook")
	logrus.SetOutput(os.Stdout)
	logrus.Infof("Log level set to %s", logLevel)
}

func serveWebhookTLS(cmd *cobra.Command, args []string) {
	configureLogging()
	logrus.Info("Starting Calico admission webhook server")

	// Create a clientset to interact with the Kubernetes API.
	rc, err := rest.InClusterConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create in-cluster config")
	}

	// The client-go defaults (QPS 5 / burst 10) throttle the webhook under bursts of policy writes,
	// since every admission review issues a SubjectAccessReview. Match kube-controllers' higher
	// limits so a large batch of concurrent writes doesn't queue behind client-side rate limiting.
	rc.QPS = 100
	rc.Burst = 200

	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create Kubernetes clientset")
	}
	calicoCS, err := calicoclient.NewForConfig(rc)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create Calico clientset")
	}
	metadataClient, err := metadata.NewForConfig(rc)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create metadata client")
	}

	// The informers backing the policy cache must keep running for the life of the process,
	// not just through startup: a short-lived context would close their watches once it expired.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Register webhook handlers.
	registerHooks(ctx, cs, calicoCS, metadataClient)

	// Create and run the server.
	cfg, err := ctls.NewTLSConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create TLS config")
	}
	if clientCAFile != "" {
		caCert, err := os.ReadFile(clientCAFile)
		if err != nil {
			logrus.WithError(err).Fatalf("Failed to read client CA file %q", clientCAFile)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			logrus.Fatalf("Failed to parse client CA certificate from %q: file must contain PEM-encoded certificates", clientCAFile)
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = certPool
		logrus.Info("mTLS enabled: requiring and verifying client certificates")
	}
	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		TLSConfig:      cfg,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	logrus.Infof("Listening on port %d", port)
	err = server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to start webhook server on port %d", port)
	}
}

// registerHooks builds the shared authorizer and policy tier cache once, then hands them to
// both hooks so the admission and authorization paths cannot drift on the decision core they use.
func registerHooks(
	ctx context.Context,
	cs kubernetes.Interface,
	calicoCS calicoclient.Interface,
	metadataClient metadata.Interface,
) *policycache.Cache {
	bo := webhook.DefaultRetryBackoff()
	authorizerClient, err := webhook.NewFromInterface(
		cs.AuthorizationV1(),
		5*time.Second,
		5*time.Second,
		*bo,
		kauth.DecisionDeny,
		&authzmetrics.NoopAuthorizerMetrics{},
		cel.NewDefaultCompiler(),
	)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create webhook authorizer")
	}

	// The policy tier cache only serves the authorization path, and costs five cluster-wide
	// metadata watches, so it only runs when that path is enabled.
	var cache *policycache.Cache
	var resolver tierauth.PolicyTierResolver = disabledResolver{}
	if authzEnabled {
		// Resync 0: a periodic resync only re-delivers objects to event handlers, and this
		// cache registers none. It reads the store directly, which the watch already keeps
		// current.
		cache = policycache.New(metadataClient, calicoCS, 0)
		// Start does not wait for the initial list. The server listens straight away so
		// /readyz can answer 503 with a reason while the cache warms up; until it syncs,
		// TierForPolicy refuses to answer, which denies.
		cache.Start(ctx)
		resolver = cache
	}

	decider := tierauth.New(authorizer.NewTierAuthorizer(authorizerClient), resolver)

	rbac.RegisterHook(decider, calicoCS.ProjectcalicoV3().Tiers(), utils.HandleFn(handleFn))
	clusterinfo.RegisterHook(utils.HandleFn(handleFn))
	if authzEnabled {
		authz.RegisterHook(decider, authz.HandleAuthzFn(handleAuthzFn))
	} else {
		authz.RegisterDisabledHook(authz.HandleAuthzFn(handleAuthzFn))
	}

	// Register a readiness endpoint that can be used by Kubernetes to check the health of the webhook server.
	http.HandleFunc("/readyz", readyFn(cache))

	// Registration errors here are startup errors: a collector name collision or a bad
	// metric definition should fail loudly rather than run with half the metrics missing.
	if err := metrics.RegisterAll(prometheus.DefaultRegisterer); err != nil {
		logrus.WithError(err).Fatal("Failed to register metrics")
	}
	// /metrics is served on the same TLS listener as the admission and authorization
	// endpoints, so it is an HTTPS scrape target rather than a separate plaintext port.
	http.Handle("/metrics", promhttp.Handler())

	return cache
}

// disabledResolver stands in for the policy tier cache when the authorization webhook is off.
// The admission path shares the same tierauth.Authorizer but reads spec.tier out of the object
// body, so it never asks for a resolution; erroring rather than passing nil keeps any future
// path that does reach here fail-closed instead of panicking.
type disabledResolver struct{}

func (disabledResolver) TierForPolicy(_ context.Context, _, _, _ string) (string, error) {
	return "", errors.New("the policy tier cache is not running; the authorization webhook is disabled (--authz-enabled)")
}

// readyFn reports on the policy tier cache. cache is nil when the authorization webhook is
// disabled, in which case there is nothing to warm up and the server is ready once it listens.
func readyFn(cache *policycache.Cache) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if cache != nil && !cache.HasSynced() {
			// Reachable, unlike before: the listener comes up before the sync completes.
			http.Error(w, "policy tier cache has not synced", http.StatusServiceUnavailable)
			return
		}
		if _, err := w.Write([]byte("ok")); err != nil {
			logrus.WithError(err).Error("Failed to write readiness response")
		}
	}
}

// handleFn implements utils.HandleFn to allow registration of webhooks.
func handleFn(handler utils.AdmissionReviewHandler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, handler)
	}
}

// handleRequest handles an incoming HTTP request, decodes the AdmissionReview, processes it, and writes the response.
func handleRequest(w http.ResponseWriter, r *http.Request, handler utils.AdmissionReviewHandler) {
	// Decode the AdmissionReview request.
	obj, gvk, err := decodeAdmissionReview(w, r)
	if err != nil {
		logrus.Error(err)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	// Process the AdmissionReview request.
	responseObj, err := processAdmissionReview(obj, gvk, handler)
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

// maxRequestBodyBytes is the maximum size of an admission review request body.
// The Kubernetes API server limits API objects to 3MB, so an AdmissionReview
// wrapping a Calico resource will not legitimately exceed this.
const maxRequestBodyBytes = 3 << 20 // 3MB

// handleAuthzFn implements authz.HandleAuthzFn to allow registration of the authorization webhook.
func handleAuthzFn(handler authz.AuthzHandler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		handleAuthzRequest(w, r, handler)
	}
}

// handleAuthzRequest handles an incoming HTTP request, decodes the SubjectAccessReview, processes it, and writes the response.
func handleAuthzRequest(w http.ResponseWriter, r *http.Request, handler authz.AuthzHandler) {
	obj, gvk, err := decodeRequest(w, r)
	if err != nil {
		logrus.Error(err)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	// Ensure we received a SubjectAccessReview.
	expectedGVK := authorizationv1.SchemeGroupVersion.WithKind("SubjectAccessReview")
	if *gvk != expectedGVK {
		errMsg := fmt.Sprintf("unsupported group version kind: %v, expected %v", gvk, expectedGVK)
		logrus.Error(errMsg)
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	sar, ok := obj.(*authorizationv1.SubjectAccessReview)
	if !ok {
		errMsg := fmt.Sprintf("expected *authorizationv1.SubjectAccessReview but got: %T", obj)
		logrus.Error(errMsg)
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	// Process the authorization review.
	sar.Status = *handler.Authorize(*sar)

	// Encode and send the response.
	respBytes, err := json.Marshal(sar)
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

// decodeRequest reads and decodes an HTTP request body into a runtime.Object.
func decodeRequest(w http.ResponseWriter, r *http.Request) (runtime.Object, *schema.GroupVersionKind, error) {
	var body []byte
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		} else {
			return nil, nil, fmt.Errorf("could not read request body: %w", err)
		}
	} else {
		return nil, nil, fmt.Errorf("empty body")
	}

	// Verify the content type is accurate
	if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		return nil, nil, fmt.Errorf("invalid Content-Type '%s', expected `application/json`", ct)
	}

	deserializer := utils.Codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("request could not be decoded: %v", err)
	}
	return obj, gvk, nil
}

func decodeAdmissionReview(w http.ResponseWriter, r *http.Request) (runtime.Object, *schema.GroupVersionKind, error) {
	return decodeRequest(w, r)
}

func processAdmissionReview(obj runtime.Object, gvk *schema.GroupVersionKind, handler utils.AdmissionReviewHandler) (*v1.AdmissionReview, error) {
	switch *gvk {
	case v1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1.AdmissionReview)
		if !ok {
			return nil, fmt.Errorf("expected v1.AdmissionReview but got: %T", obj)
		}
		responseAdmissionReview := &v1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = handler.ProcessV1Review(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		return responseAdmissionReview, nil
	default:
		return nil, fmt.Errorf("unsupported group version kind: %v", gvk)
	}
}
