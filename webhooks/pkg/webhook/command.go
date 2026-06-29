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

package webhook

import (
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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	ctls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/webhooks/pkg/clusterinfo"
	"github.com/projectcalico/calico/webhooks/pkg/rbac"
	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

var (
	certFile     string
	keyFile      string
	clientCAFile string
	logLevel     string
	port         int
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
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create Kubernetes clientset")
	}
	calicoCS, err := calicoclient.NewForConfig(rc)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create Calico clientset")
	}

	// Register webhook handlers.
	registerHooks(cs, calicoCS)

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

func registerHooks(cs kubernetes.Interface, calicoCS calicoclient.Interface) {
	rbac.RegisterHook(cs, calicoCS.ProjectcalicoV3().Tiers(), utils.HandleFn(handleFn))
	clusterinfo.RegisterHook(utils.HandleFn(handleFn))

	// Register a readiness endpoint that can be used by Kubernetes to check the health of the webhook server.
	http.HandleFunc("/readyz", readyFn())
}

func readyFn() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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

func decodeAdmissionReview(w http.ResponseWriter, r *http.Request) (runtime.Object, *schema.GroupVersionKind, error) {
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

	// Decode the body into an AdmissionReview object, and check the
	// GroupVersionKind to ensure it's something we support.
	deserializer := utils.Codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("request could not be decoded: %v", err)
	}
	return obj, gvk, nil
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
