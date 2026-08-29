// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package csr

import (
	"context"
	"errors"
	"fmt"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/enterprise/controller/monitor"
	rmonitor "github.com/tigera/operator/pkg/enterprise/render/monitor"
	eutils "github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// nonClusterHostLabel carries the hostname a non-cluster host requests a certificate for.
const nonClusterHostLabel = "nonclusterhost.tigera.io/hostname"

// Extension is the Calico Enterprise behavior for the CSR controller.
type Extension struct{}

var _ extensions.CSRExtension = &Extension{}

// New returns the CSR extension.
func New() *Extension {
	return &Extension{}
}

// ExtendInputs stashes the certificates Enterprise signs for, and whether anything
// will ask for one.
func (e *Extension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	requiresRole, err := e.requiresSigningRole(ctx, ci.Client)
	if err != nil {
		return ci, nil, err
	}

	ci.RenderInputs.Extension = render.CSRData{
		AllowedAssets:       allowedAssets(ci.RenderInputs.ClusterDomain, ci.K8sClientset),
		RequiresSigningRole: requiresRole,
		ResolveSubject:      nonClusterHostSubject(ci.CalicoClient),
	}
	return ci, nil, nil
}

// allowedAssets To prevent any abuse of this controller for obtaining a fraudulent certificate, this controller
// will only approve a pre-defined list of assets, based on their 'requestor', dns names and namespaces.
// Some of the information a CSR will contain:
//   - Name: The name is based on the secret name + a pod suffix. We use the secret name as the key to index the map.
//   - Requestor: this is the user identity tied to the request. This will be matched against the sa + namespace.
//   - DNS names: these will be checked against pre-defined dns names for that specific secret name.
//
// The combination of this information (among other checks) will help us reject/approve requests.
func allowedAssets(clusterDomain string, clientset kubernetes.Interface) map[string]render.TLSAsset {
	return map[string]render.TLSAsset{
		rmonitor.PrometheusServerTLSSecretName: {
			ServiceAccountName:      rmonitor.PrometheusServiceAccountName,
			ServiceAccountNamespace: rmonitor.TigeraPrometheusObjectName,
			ValidDNSNames:           monitor.PrometheusTLSServerDNSNames(clusterDomain),
		},
		// The node-certs-noncluster-host signing request originates from non-cluster hosts.
		// To accommodate our customers' use of different non-cluster service accounts,
		// we will perform a SubjectAccessReview to validate the requestor's permission.
		render.NodeTLSSecretNameNonClusterHost: {
			ValidDNSNames: []string{render.FelixCommonName + render.TyphaNonClusterHostSuffix},
			Authorize:     nonClusterHostAuthorizer(clientset),
		},
	}
}

// nonClusterHostSubject resolves a request from a non-cluster host to the host
// endpoint registered for it.
func nonClusterHostSubject(calicoClient calicoclient.Interface) render.CSRSubjectResolver {
	return func(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (*render.CSRSubject, error) {
		hostname, ok := csr.Labels[nonClusterHostLabel]
		if !ok {
			return nil, nil
		}
		if hostname == "" {
			return nil, errors.New("hostname can not be empty")
		}

		hepList, err := calicoClient.ProjectcalicoV3().HostEndpoints().List(ctx, metav1.ListOptions{FieldSelector: fmt.Sprintf("spec.node=%s", hostname)})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		if len(hepList.Items) == 0 {
			return nil, nil
		}
		return &render.CSRSubject{Name: hepList.Items[0].Spec.Node}, nil
	}
}

// nonClusterHostAuthorizer asks the API server whether the requestor may ask for the
// non-cluster host common name.
func nonClusterHostAuthorizer(clientset kubernetes.Interface) render.CSRAuthorizer {
	return func(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (bool, error) {
		review := &authv1.SubjectAccessReview{
			Spec: authv1.SubjectAccessReviewSpec{
				User:   csr.Spec.Username,
				Groups: csr.Spec.Groups,
				UID:    csr.Spec.UID,
				Extra:  convertExtraValue(csr.Spec.Extra),
				ResourceAttributes: &authv1.ResourceAttributes{
					Group:       "certificates.tigera.io",
					Resource:    "certificatesigningrequests",
					Subresource: "common-name",
					Verb:        "create",
					Name:        render.TyphaCommonName + render.TyphaNonClusterHostSuffix,
				},
			},
		}

		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		result, err := clientset.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}
		return result.Status.Allowed, nil
	}
}

func convertExtraValue(extra map[string]certificatesv1.ExtraValue) map[string]authv1.ExtraValue {
	res := make(map[string]authv1.ExtraValue)
	for k, v := range extra {
		res[k] = authv1.ExtraValue(v)
	}
	return res
}

// requiresSigningRole reports whether external Prometheus or a non-cluster host is
// configured. Both submit signing requests.
func (e *Extension) requiresSigningRole(ctx context.Context, c client.Client) (bool, error) {
	monitorCR := &operatorv1.Monitor{}
	if err := c.Get(ctx, utils.DefaultEnterpriseInstanceKey, monitorCR); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, err
		}
	} else if monitorCR.Spec.ExternalPrometheus != nil {
		return true, nil
	}

	// Non-cluster hosts generate CSRs to establish mTLS connections with the cluster.
	nonclusterhost, err := eutils.GetNonClusterHost(ctx, c)
	if err != nil {
		return false, err
	}
	return nonclusterhost != nil, nil
}

// Watches registers the CRs that decide whether the CSR role is needed.
func (e *Extension) Watches(c ctrlruntime.Controller) error {
	if err := c.WatchObject(&operatorv1.Monitor{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("csr-controller failed to watch Monitor: %w", err)
	}
	if err := c.WatchObject(&operatorv1.NonClusterHost{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("csr-controller failed to watch NonClusterHost: %w", err)
	}
	return nil
}
