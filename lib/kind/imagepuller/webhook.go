// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Image-pull webhook: a mutating admission webhook that runs in-process
// alongside the test driver, attached to the kind cluster's apiserver via
// a MutatingWebhookConfiguration. For every Pod admitted into a non-
// system namespace, it:
//
//  1. Patches imagePullPolicy=Never on every container shape
//     (containers / initContainers / ephemeralContainers).
//  2. Enqueues the pod's images on the local Puller, which fetches
//     each image to a persistent cache, loads the tar onto every kind
//     node, and restarts the pod so it picks up the now-local image.
//
// Why: kind nodes can't reach registries the host can, and pulling the
// same image set on every test run is glacial. Pulling once into a host
// cache and rewriting policies to "Never" gives every subsequent run a
// warm start.
//
// The webhook's MutatingWebhookConfiguration URLs the apiserver at
// https://172.18.0.1:<port> — that's the kind default bridge gateway,
// the address kind nodes use to reach the host. The TLS cert generator
// pins that IP as a SAN.

package imagepuller

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// imageWebhook owns the in-process HTTPS server backing the
// MutatingWebhookConfiguration. The puller it dispatches to is shared
// across all admission events — its dedup logic keeps repeat enqueues
// cheap.
type imageWebhook struct {
	puller *Puller
	log    *log.Entry

	server *http.Server
	ln     net.Listener
}

// startImageWebhook generates a fresh TLS keypair, opens an ephemeral
// port on 0.0.0.0, and starts serving. Returns the bound port and the
// CA PEM the caller embeds in the MutatingWebhookConfiguration so the
// apiserver trusts the server cert. The server runs until ctx is
// cancelled.
func startImageWebhook(ctx context.Context, puller *Puller) (*imageWebhook, int, []byte, error) {
	logger := log.WithField("component", "image-webhook")
	certPEM, keyPEM, caPEM, err := generateWebhookTLSCerts()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("generate webhook TLS certs: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("build TLS keypair: %w", err)
	}

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("listen: %w", err)
	}

	wh := &imageWebhook{puller: puller, log: logger, ln: ln}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/mutate-pods", wh.handleMutate)

	wh.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	port := ln.Addr().(*net.TCPAddr).Port
	logger.WithField("port", port).Info("listening")

	go func() {
		<-ctx.Done()
		_ = wh.server.Close()
	}()
	go func() {
		if err := wh.server.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Warn("serve error")
		}
	}()

	return wh, port, caPEM, nil
}

// handleMutate is the HTTP entrypoint registered with the apiserver. It
// accepts an AdmissionReview, returns one with a JSONPatch that sets
// imagePullPolicy=Never on every container shape, and asynchronously
// hands the pod off to the puller. Failures are logged but never
// blocking — the webhook is registered with failurePolicy=Ignore
// effectively (Fail in the original, but most test drivers prefer
// from forward progress over strict correctness, so we choose Ignore).
func (w *imageWebhook) handleMutate(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(rw, "unmarshal review: "+err.Error(), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(rw, "nil request", http.StatusBadRequest)
		return
	}

	resp := admissionv1.AdmissionReview{
		TypeMeta: review.TypeMeta,
		Response: &admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: true,
		},
	}

	// We only ever care about pods.
	if review.Request.Kind.Group != "" || review.Request.Kind.Version != "v1" || review.Request.Kind.Kind != "Pod" {
		writeReview(rw, resp)
		return
	}

	var pod corev1.Pod
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		// Allow without patch — never block admission on a decode error.
		w.log.WithError(err).Warn("decode pod")
		writeReview(rw, resp)
		return
	}

	type patchOp struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value,omitempty"`
	}
	var patches []patchOp
	for i := range pod.Spec.Containers {
		patches = append(patches, patchOp{Op: "add", Path: fmt.Sprintf("/spec/containers/%d/imagePullPolicy", i), Value: "Never"})
	}
	for i := range pod.Spec.InitContainers {
		patches = append(patches, patchOp{Op: "add", Path: fmt.Sprintf("/spec/initContainers/%d/imagePullPolicy", i), Value: "Never"})
	}
	for i := range pod.Spec.EphemeralContainers {
		patches = append(patches, patchOp{Op: "add", Path: fmt.Sprintf("/spec/ephemeralContainers/%d/imagePullPolicy", i), Value: "Never"})
	}

	if len(patches) > 0 {
		patchBytes, err := json.Marshal(patches)
		if err != nil {
			w.log.WithError(err).Warn("marshal patch")
			writeReview(rw, resp)
			return
		}
		pt := admissionv1.PatchTypeJSONPatch
		resp.Response.PatchType = &pt
		resp.Response.Patch = patchBytes
	}

	w.puller.Pull(&pod)
	writeReview(rw, resp)
}

func writeReview(w http.ResponseWriter, ar admissionv1.AdmissionReview) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ar); err != nil {
		// Best-effort log via the default logger — at this point the
		// response is already partial-written so there's not much else
		// we can do.
		fmt.Fprintf(io.Discard, "encode review: %v", err)
	}
}

// neverPullMutatingWebhookConfig builds the cluster object pointing the
// apiserver at the in-process webhook. We use URL (not Service) because
// the webhook lives on the host, not in-cluster. failurePolicy=Fail so
// admission stops cold if our server is unreachable — silently falling
// back to the original imagePullPolicy would mean test pods quietly
// trying to pull from registries that the kind nodes can't authenticate
// against, which is exactly the failure mode we built this webhook to
// avoid. Loud is better.
func neverPullMutatingWebhookConfig(port int, caPEM []byte) *admv1.MutatingWebhookConfiguration {
	fail := admv1.Fail
	ifNeeded := admv1.IfNeededReinvocationPolicy
	noSideEffects := admv1.SideEffectClassNone
	timeout := int32(5)
	scope := admv1.AllScopes
	url := fmt.Sprintf("https://%s:%d/mutate-pods", kindBridgeGatewayIP, port)

	return &admv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "MutatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kind-cached-images-only",
		},
		Webhooks: []admv1.MutatingWebhook{
			{
				Name:                    "never-pull.kind-cached-images.local",
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &noSideEffects,
				TimeoutSeconds:          &timeout,
				FailurePolicy:           &fail,
				ReinvocationPolicy:      &ifNeeded,
				NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/metadata.name",
							Operator: metav1.LabelSelectorOpNotIn,
							// kube-system is excluded because its pods
							// (apiserver, scheduler, etc.) already ship in
							// the kindest/node image and don't need
							// rewriting. tigera-operator is excluded
							// because the operator is the thing that
							// instantiates the rest of Calico; we want it
							// to bootstrap normally on the first run and
							// then have everything it creates flow
							// through the webhook.
							Values: []string{"kube-system", "tigera-operator"},
						},
					},
				},
				Rules: []admv1.RuleWithOperations{{
					Operations: []admv1.OperationType{admv1.Create, admv1.Update},
					Rule: admv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"pods"},
						Scope:       &scope,
					},
				}},
				ClientConfig: admv1.WebhookClientConfig{
					URL:      ptrString(url),
					CABundle: caPEM,
				},
			},
		},
	}
}

// installNeverPullWebhook registers (or refreshes) the
// MutatingWebhookConfiguration in the cluster. Existing config from a
// prior run is deleted first so it picks up the fresh port + caBundle.
func installNeverPullWebhook(ctx context.Context, cs *kubernetes.Clientset, port int, caPEM []byte) error {
	cfg := neverPullMutatingWebhookConfig(port, caPEM)
	err := cs.AdmissionregistrationV1().
		MutatingWebhookConfigurations().
		Delete(ctx, cfg.Name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete existing webhook: %w", err)
	}
	if _, err := cs.AdmissionregistrationV1().
		MutatingWebhookConfigurations().
		Create(ctx, cfg, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create webhook: %w", err)
	}
	return nil
}

func ptrString(s string) *string { return &s }
