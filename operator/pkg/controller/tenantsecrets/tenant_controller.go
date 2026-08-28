// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package tenantsecrets

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	entcertificatemanager "github.com/projectcalico/calico/operator/pkg/enterprise/certificatemanager"
	eutils "github.com/projectcalico/calico/operator/pkg/enterprise/utils"
	"github.com/projectcalico/calico/operator/pkg/render"
	rcertificatemanagement "github.com/projectcalico/calico/operator/pkg/render/certificatemanagement"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage/linseed"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// TenantControllers runs in multi-tenant mode and provisions a CA per-tenant, as well as generating
// a trusted bundle to place in each tenant's namespace.
type TenantController struct {
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	clusterDomain   string
	log             logr.Logger
	elasticExternal bool
}

func AddTenantController(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.MultiTenant {
		return nil
	}

	r := &TenantController{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		clusterDomain:   opts.ClusterDomain,
		elasticExternal: opts.ElasticExternal,
		status:          status.New(mgr.GetClient(), "secrets", opts.KubernetesVersion),
		log:             logf.Log.WithName("controller_tenant_secrets"),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("tenant-secrets-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	if err = c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tenant-secrets-controller failed to watch Tenant resource: %w", err)
	}

	if err = c.WatchObject(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tenant-controller failed to watch Installation resource: %w", err)
	}
	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("tenant-controller failed to watch cluster scoped CA secret %s: %w", certificatemanagement.CASecretName, err)
	}

	if err = utils.AddSecretsWatch(c, certificatemanagement.TenantCASecretName, ""); err != nil {
		return fmt.Errorf("tenant-controller failed to watch tenant CA Secret %s in all namespace: %w", certificatemanagement.TenantCASecretName, err)
	}

	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, "", &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tenant-controller failed to watch ConfigMap resource: %w", err)
	}
	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapNamePublic, "", &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tenant-controller failed to watch ConfigMap resource: %w", err)
	}

	return nil
}

func (r *TenantController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logc := r.log.WithValues("Request.Namespace", request.Namespace)
	if request.Namespace == "" {
		// Tenant resources are always within a namespace.
		return reconcile.Result{}, nil
	}

	// Get the Tenant.
	tenant, _, err := eutils.GetTenant(ctx, true, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		logc.V(1).Info("No Tenant in this Namespace, skip")
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, logc)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()

	// Get all Tenants so we can perform validation.
	tenants := operatorv1.TenantList{}
	if err = r.client.List(ctx, &tenants); err != nil {
		return reconcile.Result{}, err
	}
	for _, t := range tenants.Items {
		if t.Spec.ID == tenant.Spec.ID && t.Namespace != tenant.Namespace {
			// A tenant in a different namespace has the same ID as this tenant. This is not allowed.
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Multiple tenants with the ID '%s'", t.Spec.ID), err, logc)
			return reconcile.Result{}, nil
		}
		if t.Namespace == tenant.Namespace && t.Name != tenant.Name {
			// Multiple tenants in the same namespace. This is not allowed.
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Multiple Tenants in namespace '%s'", t.Namespace), err, logc)
			return reconcile.Result{}, nil
		}
	}
	// Get Installation resource.
	installationSpec, err := utils.GetComputedInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, logc)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, logc)
		return reconcile.Result{}, err
	}

	// Create a certificate manager for this tenant. This certificate manager will load the CA for this tenant, creating it if needed,
	// and can be used to sign any certificates needed for this tenant's components.
	opts := []certificatemanager.Option{
		certificatemanager.AllowCACreation(),
		certificatemanager.WithLogger(logc),
	}
	cm, err := entcertificatemanager.Create(r.client, installationSpec, r.clusterDomain, tenant.Namespace, tenant, opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create CA", err, logc)
		return reconcile.Result{}, err
	}
	cm.AddToStatusManager(r.status, tenant.Namespace)

	// Create the CA in the tenant's namespace.
	keyPairOptions := []rcertificatemanagement.KeyPairOption{
		rcertificatemanagement.NewKeyPairOption(cm.KeyPair(), true, false),
	}

	// Get upstream certificates that we need to trust.
	certs, err := r.upstreamCertificates(cm)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying upstream certificates for trusted bundle", err, logc)
		return reconcile.Result{}, err
	}

	// Create a trusted bundle for this tenant. This bundle is provided to the tenant pods so that they can verify
	// each other's certificates. Each tenant needs to trust:
	// - Certificates signed by its own CA
	// - Certificates signed by the cluster-scoped Tigera CA
	// - Certificates for external ES and Kibana, if configured.
	trustedBundle := cm.CreateTrustedBundle()
	trustedBundle.AddCertificates(certs...)

	// We also need a trusted bundle that includes the system root certificates in addition to the certificates
	// listed above, so that components that talk to public endpoints can verify them. In a multi-tenant cluster, this
	// bundle will co-exist in the same namespace as the default trusted bundle, but with a different name.
	trustedBundleWithSystemCAs, err := entcertificatemanager.CreateTenantBundleWithSystemRootCertificates(cm)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying system root certificates", err, logc)
		return reconcile.Result{}, err
	}
	trustedBundleWithSystemCAs.AddCertificates(certs...)

	component := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      tenant.Namespace,
		TruthNamespace: tenant.Namespace,
		ServiceAccounts: []string{
			linseed.ServiceAccountName,
			render.ManagerServiceAccount,
		},
		KeyPairOptions: keyPairOptions,
		TrustedBundle:  trustedBundle,
	})
	systemRootsComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      tenant.Namespace,
		TruthNamespace: tenant.Namespace,
		TrustedBundle:  trustedBundleWithSystemCAs,
	})

	hdler := utils.NewComponentHandler(logc, r.client, r.scheme, tenant)
	if err = hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
		return reconcile.Result{}, err
	}
	if err = hdler.CreateOrUpdateOrDelete(ctx, systemRootsComponent, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating trusted bundle with public CAs", err, logc)
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *TenantController) upstreamCertificates(cm certificatemanager.CertificateManager) ([]certificatemanagement.CertificateInterface, error) {
	toQuery := map[string]string{
		// By default, we only need the operator's CA cert.
		certificatemanagement.CASecretName: common.OperatorNamespace(),
	}

	if r.elasticExternal {
		// If configured to use external Elasticsearch, get the Elasticsearch public certs.
		toQuery[logstorage.ExternalESPublicCertName] = common.OperatorNamespace()
	}

	// Query each certificate.
	certs := []certificatemanagement.CertificateInterface{}
	for name, namespace := range toQuery {
		if cert, err := cm.GetCertificate(r.client, name, namespace); err != nil {
			return nil, fmt.Errorf("error querying certificate %s/%s: %w", namespace, name, err)
		} else if cert == nil {
			return nil, fmt.Errorf("certificate %s/%s not found", namespace, name)
		} else {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}
