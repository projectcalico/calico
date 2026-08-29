// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package csr

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/tls"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// LabelName label that we set on our CSRs, this helps us exclude irrelevant CSRs.
const (
	controllerName = "csr-controller"
	LabelName      = "operator.tigera.io/csr"
)

var (
	extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	log         = logf.Log.WithName("controller_csr")
)

// relevantCSR returns true if a csr is relevant to this controller.
func relevantCSR(csr *certificatesv1.CertificateSigningRequest) bool {
	if csr.Spec.SignerName != certificatemanager.OperatorCSRSignerName {
		return false
	}
	if _, found := csr.Labels[LabelName]; !found {
		return false
	}
	for _, condition := range csr.Status.Conditions {
		if (condition.Type == certificatesv1.CertificateDenied || condition.Type == certificatesv1.CertificateFailed) && condition.Status == corev1.ConditionTrue {
			// These request statuses are deterministic/non-recoverable.
			return false
		}
	}
	// We are only interested in CSRs that have not been signed. This also excludes
	// us from watching our own updates and reconciling for no reason.
	return csr.Status.Certificate == nil
}

// Add creates a new CSR Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	reconciler, err := newReconciler(mgr, opts)
	if err != nil {
		return err
	}

	c, err := ctrlruntime.NewController(controllerName, mgr, ctrl.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	if err = opts.Extensions.CSR().Watches(c); err != nil {
		return fmt.Errorf("csr-controller failed to set up extension watches: %w", err)
	}

	if err = c.WatchObject(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("csr-controller failed to watch Installation: %w", err)
	}

	return utils.AddCSRWatchWithRelevancyFn(c, relevantCSR)
}

func newReconciler(mgr manager.Manager, opts options.ControllerOptions) (reconcile.Reconciler, error) {
	// Looks up HostEndpoints with a spec.node field selector. Serving that from the
	// manager's cache would need a registered field index and an informer holding every
	// HostEndpoint in the cluster, for a lookup that only ever wants one.
	calicoClient, err := calicoclient.NewForConfig(mgr.GetConfig())
	if err != nil {
		return nil, err
	}

	return &reconcileCSR{
		client:        mgr.GetClient(),
		clientset:     opts.K8sClientset,
		calicoClient:  calicoClient,
		scheme:        mgr.GetScheme(),
		provider:      opts.DetectedProvider,
		clusterDomain: opts.ClusterDomain,
		extensions:    opts.Extensions,
	}, nil
}

// blank assignment to verify that ReconcileCompliance implements reconcile.Reconciler
var _ reconcile.Reconciler = &reconcileCSR{}

// reconcileCSR Components created by the operator may submit certificate signing requests against k8s under certain
// conditions for signer name "tigera.io/operator-signer". This is the controller that monitors, approves and signs
// these CSRs. It will only sign requests that are pre-defined and reject others in order to avoid malicious requests.
type reconcileCSR struct {
	client        client.Client
	clientset     kubernetes.Interface
	calicoClient  calicoclient.Interface
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	clusterDomain string
	extensions    extensions.Extensions
}

func (r *reconcileCSR) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling CSR Controller")
	csrList := &certificatesv1.CertificateSigningRequestList{}

	instance := &operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	ci := controller.Inputs{
		RenderInputs: render.Inputs{Installation: &instance.Spec, ClusterDomain: r.clusterDomain},
		Client:       r.client,
		K8sClientset: r.clientset,
		CalicoClient: r.calicoClient,
	}
	ci, _, err := r.extensions.CSR().ExtendInputs(ctx, ci)
	if err != nil {
		return reconcile.Result{}, err
	}

	csrData := render.CSRDataFromInputs(ci.RenderInputs)

	needsCSRRole := instance.Spec.CertificateManagement != nil || csrData.RequiresSigningRole

	componentHandler := utils.NewComponentHandler(log, r.client, r.scheme, instance)
	var passthrough render.Component
	if needsCSRRole {
		// This controller creates the cluster role for any pod in the cluster that requires certificate management.
		passthrough = render.NewCreationPassthrough(certificatemanagement.CSRClusterRole())
		err := componentHandler.CreateOrUpdateOrDelete(ctx, passthrough, nil)
		if err != nil {
			return reconcile.Result{}, err
		}
	} else {
		passthrough = render.NewDeletionPassthrough(certificatemanagement.CSRClusterRole())
		reqLogger.V(5).Info("ending reconciliation, no CSRs have to be signed with the current configuration.")
		return reconcile.Result{}, componentHandler.CreateOrUpdateOrDelete(ctx, passthrough, nil)
	}

	// Filter out unnecessary CSRs. (Calico CSRs are guaranteed to have this label).
	requirement, err := labels.NewRequirement(LabelName, selection.Exists, []string{})
	if err != nil {
		return reconcile.Result{}, err
	}
	if err := r.client.List(ctx, csrList, &client.ListOptions{LabelSelector: labels.NewSelector().Add(*requirement)}); err != nil {
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, &instance.Spec, r.clusterDomain, common.OperatorNamespace(), certificatemanager.WithLogger(reqLogger))
	if err != nil {
		return reconcile.Result{}, err
	}

	for _, csr := range csrList.Items {
		if !relevantCSR(&csr) {
			// Not for us, or already signed.
			continue
		}

		reqLogger.V(5).Info("Inspecting CSR with name : %v.", csr.Name)
		var certificateTemplate *x509.Certificate
		subject, err := r.subject(ctx, &csr, csrData.ResolveSubject)
		if err == nil {
			certificateTemplate, err = validate(ctx, &csr, subject, csrData.AllowedAssets)
		}

		if err != nil {
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:    certificatesv1.CertificateDenied,
					Message: err.Error(),
					Reason:  err.Error(),
					Status:  corev1.ConditionTrue,
				},
			}
			reqLogger.Error(err, "Rejecting the CSR.")
			if err = r.client.SubResource("approval").Update(ctx, &csr); err != nil {
				return reconcile.Result{}, err
			}
			continue
		}
		csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
			{
				Type:    certificatesv1.CertificateApproved,
				Message: "Approved",
				Reason:  "Approved",
				Status:  corev1.ConditionTrue,
			},
		}
		err = r.client.SubResource("approval").Update(ctx, &csr)
		if err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.V(5).Info("Approved CSR with name : %v.", csr.Name)

		certificatePEM, err := certificateManager.SignCertificate(certificateTemplate)
		if err != nil {
			reqLogger.Error(err, "error signing certificate request")
			return reconcile.Result{}, err
		}
		csr.Status.Certificate = certificatePEM
		err = r.client.SubResource("status").Update(ctx, &csr)
		if err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.V(5).Info("Signed CSR with name : %v.", csr.Name)
	}
	return reconcile.Result{}, nil
}

// subject identifies the workload behind a CSR, deferring to the variant for
// requests that no pod issued.
func (r *reconcileCSR) subject(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, resolve render.CSRSubjectResolver) (*render.CSRSubject, error) {
	pod, err := r.getPod(ctx, csr)
	if err != nil {
		return nil, err
	}
	if pod != nil {
		return &render.CSRSubject{Name: pod.Name, IP: pod.Status.PodIP}, nil
	}
	if resolve == nil {
		return nil, nil
	}
	return resolve(ctx, csr)
}

// validate Criteria include:
// - Verify that the x509 request can be parsed and contains one request block.
// - Verify that the request name matches the deterministic name format that we expect. (More for practical reasons, than for security reasons.)
// - Verify that the service account is allowed to request the common name and/or SANs.
// - Verify that the issuer of the CSR (the pod) indeed is the pod that belongs to the IP in the CSR.
// - Verify that the CSR was not previously denied or failed.
// - Verify that the public key matches the signature on the CSR for the provider algorithm.
// - Key usages are fixed, so the CSR won't be able to affect these settings.
func validate(
	ctx context.Context,
	csr *certificatesv1.CertificateSigningRequest,
	subject *render.CSRSubject,
	allowedTLSAssets map[string]render.TLSAsset,
) (*x509.Certificate, error) {
	if subject == nil {
		return nil, fmt.Errorf("invalid: no object can be associated with CSR %s", csr.Name)
	}
	expectedName, expectedIP := subject.Name, subject.IP

	firstBlock, restBlocks := pem.Decode(csr.Spec.Request)
	if firstBlock == nil {
		return nil, fmt.Errorf("invalid: cannot parse certificate request for CSR with name %s", csr.Name)
	}
	if len(restBlocks) != 0 {
		return nil, fmt.Errorf("invalid: unexpected (multiple) pem blocks for CSR with name %s", csr.Name)
	}

	certificateRequest, err := x509.ParseCertificateRequest(firstBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if err = certificateRequest.CheckSignature(); err != nil {
		return nil, err
	}

	// The CSRName is formatted as follows:
	// - Pod: "<secretName>:<podName>"
	// - HostEndpoint: "<secretName>:<hostname>"
	nameChunks := strings.Split(csr.Name, ":")
	if len(nameChunks) != 2 || nameChunks[1] != expectedName {
		return nil, fmt.Errorf("invalid: CSR name does not match expected format: %s", csr.Name)
	}
	secretName := nameChunks[0]
	// Validate whether this is a CSR we monitor at all.
	asset, ok := allowedTLSAssets[secretName]
	if !ok {
		return nil, fmt.Errorf("invalid: this controller is not configured to sign secretName: %s", secretName)
	}

	// Validate whether the requestor of the CSR is registered for the given CSR
	if asset.Authorize != nil {
		if allowed, err := asset.Authorize(ctx, csr); err != nil {
			return nil, err
		} else if !allowed {
			return nil, fmt.Errorf("authorization failed: user %s is not allowed to create CSR %s", csr.Spec.Username, csr.Name)
		}
	} else if fmt.Sprintf("system:serviceaccount:%s:%s", asset.ServiceAccountNamespace, asset.ServiceAccountName) != csr.Spec.Username {
		return nil, fmt.Errorf("invalid requestor %s for CSR with name %s", csr.Spec.Username, csr.Name)
	}

	// Validate whether the DNS names are permitted for the request.
	for _, name := range append(certificateRequest.DNSNames, certificateRequest.Subject.CommonName) {
		var found bool
		for _, valid := range asset.ValidDNSNames {
			if valid == name {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid dns name \"%s\" found in CSR with name %s", name, csr.Name)
		}
	}

	if expectedIP != "" {
		if len(certificateRequest.IPAddresses) == 1 {
			if certificateRequest.IPAddresses[0].String() != expectedIP {
				return nil, fmt.Errorf("invalid pod IP for CSR with name %s", csr.Name)
			}
		} else if len(certificateRequest.IPAddresses) > 1 {
			return nil, fmt.Errorf("invalid: cannot request more than 1 IP for CSR with name %s", csr.Name)
		}
	} else if len(certificateRequest.IPAddresses) > 0 {
		// We don't expected IP Address in the CSR so we reject a CSR with IP addresses.
		return nil, fmt.Errorf("invalid: cannot request IP for CSR with name %s", csr.Name)
	}

	bigint, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	return &x509.Certificate{
		// We don't rely on any other part of the subject. Common name is validated already.
		Subject:            pkix.Name{CommonName: certificateRequest.Subject.CommonName},
		SerialNumber:       bigint,
		Version:            3,
		PublicKeyAlgorithm: certificateRequest.PublicKeyAlgorithm,
		PublicKey:          certificateRequest.PublicKey,
		NotBefore:          time.Now(),
		// We currently don't implement the Duration for certificate requests.
		NotAfter: time.Now().Add(tls.DefaultCertificateDuration),
		// For the time being we simply issue the standard usages. There are very few, if any, exceptions in our product.
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: extKeyUsage,
		DNSNames:    certificateRequest.DNSNames,
		IPAddresses: certificateRequest.IPAddresses,
	}, nil
}

// getPod fetches the pod that issued a CSR based on the information in the CSR.
// A CSR will contain immutable identity info set by k8s such as:
//
//	spec:
//	 extra:
//	   authentication.kubernetes.io/pod-name:
//	   - prometheus-calico-node-prometheus-0
//	   authentication.kubernetes.io/pod-uid:
//	   - 0993ca7a-3b0b-4e27-ba25-c4296620ea8d
//	 uid: 28610c0a-a4a4-4dc3-9e1d-e8564ce217f6
//	 username: system:serviceaccount:tigera-prometheus:prometheus
func (r *reconcileCSR) getPod(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (*corev1.Pod, error) {
	username := csr.Spec.Username
	if !strings.HasPrefix(username, "system:serviceaccount:") || strings.Count(username, ":") != 3 {
		// This CSR was not requested by a service account.
		return nil, nil
	}
	namespace := strings.Split(username, ":")[2]
	serviceaccountName := strings.Split(username, ":")[3]

	podNames, found := csr.Spec.Extra["authentication.kubernetes.io/pod-name"]
	if !found || len(podNames) != 1 {
		return nil, nil
	}
	podUIDs, found := csr.Spec.Extra["authentication.kubernetes.io/pod-uid"]
	if !found || len(podUIDs) != 1 {
		return nil, nil
	}

	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: podNames[0], Namespace: namespace}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if podUIDs[0] == string(pod.UID) && serviceaccountName == pod.Spec.ServiceAccountName {
		return pod, nil
	}

	return nil, nil
}
