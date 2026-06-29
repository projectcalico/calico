// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package manager

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
)

var (
	CloudManagerConfigOverrideName = "cloud-manager-config"
	CloudVoltronConfigOverrideName = "cloud-voltron-config"
)

func addCloudWatch(c ctrlruntime.Controller, eventHandler handler.EventHandler, elasticExternal bool) error {
	if elasticExternal {
		if err := utils.AddConfigMapWatch(c, cloudconfig.CloudConfigConfigMapName, common.OperatorNamespace(), eventHandler); err != nil {
			return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %v", err)
		}
	} else {
		if err := utils.AddConfigMapWatch(c, utils.CloudAuthConfig, common.OperatorNamespace(), eventHandler); err != nil {
			return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %v", err)
		}
	}

	if err := utils.AddConfigMapWatch(c, CloudVoltronConfigOverrideName, common.OperatorNamespace(), eventHandler); err != nil {
		return err
	}

	if err := utils.AddConfigMapWatch(c, CloudManagerConfigOverrideName, common.OperatorNamespace(), eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %v", err)
	}

	return nil
}

// handleCloudReconcile reconciles cloud resources and returns the cloud-ready certificate trusted bundle and resources.
// It returns a non-nil reconcile.Result when it's waiting for resources to be available.
func (r *ReconcileManager) handleCloudReconcile(
	ctx context.Context,
	reqLogger logr.Logger,
	helper utils.NamespaceHelper,
	tenant *operatorv1.Tenant,
	authenticationCR *operatorv1.Authentication,
	certificateManager certificatemanager.CertificateManager,
	bundleMaker certificatemanagement.TrustedBundle,
	trustedSecretNames []string,
	requestNamespace string,
) (certificatemanagement.TrustedBundle, render.ManagerCloudResources, *operatorv1.Tenant, *reconcile.Result, error) {

	if authenticationCR != nil && authenticationCR.Spec.OIDC != nil && authenticationCR.Spec.OIDC.Type == operatorv1.OIDCTypeTigera {
		var err error
		bundleMaker, err = certificateManager.CreateTrustedBundleWithSystemRootCertificates()
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "failed to create trusted bundle with system root certs", err, reqLogger)
			return nil, render.ManagerCloudResources{}, nil, nil, err
		}
	}

	for _, secret := range trustedSecretNames {
		certificate, err := certificateManager.GetCertificate(r.client, secret, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.CertificateError, fmt.Sprintf("Failed to retrieve %s", secret), err, reqLogger)
			return nil, render.ManagerCloudResources{}, nil, nil, err
		} else if certificate == nil {
			reqLogger.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secret))
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret '%s' to become available", secret), nil, reqLogger)
			// stop reconciler iteration with no error as it is waiting for a resource to become available
			return nil, render.ManagerCloudResources{}, nil, &reconcile.Result{}, nil
		}

		if bundleMaker != nil {
			bundleMaker.AddCertificates(certificate)
		}
	}

	mcr := render.ManagerCloudResources{
		VoltronMetricsEnabled:    true,
		VoltronInternalHttpsPort: 9444,
		ManagerExtraEnv:          map[string]string{},
	}

	if err := r.cloudConfigOverride(ctx, helper.TruthNamespace(), &mcr); err != nil {
		return nil, render.ManagerCloudResources{}, nil, nil, err
	}

	if !r.opts.MultiTenant {
		if r.opts.ElasticExternal {
			// For single-tenant clusters sharing an external ES, extract the tenant information from
			// the cloud config map.
			cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read cloud config", err, reqLogger)
				return nil, render.ManagerCloudResources{}, nil, nil, err
			}
			tenant = cloudConfig.ToTenant()
		} else {
			var err error
			tenant, err = utils.GetTenantFromCloudAuthConfig(ctx, r.client)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to fetch tenant information from config map", err, reqLogger)
			}
		}
	}

	return bundleMaker, mcr, tenant, nil, nil
}

// cloudConfigOverride set manager and voltron renderer env override
func (r *ReconcileManager) cloudConfigOverride(ctx context.Context, namespace string, mcr *render.ManagerCloudResources) error {
	var err error
	managerCfg, err := r.getConfigMapData(ctx, types.NamespacedName{Namespace: namespace, Name: CloudManagerConfigOverrideName})
	if err != nil {
		return err
	}
	for key, val := range managerCfg {
		switch key {
		case "portalAPIURL":
			// support legacy functionality where 'portalAPIURL' was a special field used to set
			// the portal url and enable support.
			mcr.ManagerExtraEnv["CNX_PORTAL_URL"] = val
			mcr.ManagerExtraEnv["ENABLE_PORTAL_SUPPORT"] = "true"

		// support legacy functionality where 'auth0OrgID' was a special field used to set the org ID
		case "auth0OrgID":
			mcr.ManagerExtraEnv["CNX_AUTH0_ORG_ID"] = val

		// special key used to control which image of manager is used
		case "managerImage":
			mcr.ManagerImage = val

		// add any other fields as-is
		default:
			mcr.ManagerExtraEnv[key] = val
		}
	}

	mcr.VoltronExtraEnv, err = r.getConfigMapData(ctx, types.NamespacedName{Namespace: namespace, Name: CloudVoltronConfigOverrideName})
	if err != nil {
		return err
	}

	return nil
}

func (r *ReconcileManager) getConfigMapData(ctx context.Context, name types.NamespacedName) (map[string]string, error) {
	configMap := &corev1.ConfigMap{}
	if err := r.client.Get(ctx, name, configMap); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to read %s ConfigMap: %s", name, err.Error())
		}
		return nil, nil
	}
	return configMap.Data, nil
}
