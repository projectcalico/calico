// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package kubecontrollers

import (
	"context"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// esGatewayAddCloudModificationsToConfig modifies the provided *esgateway.Config to include Calico Cloud specific configuration.
func (r *ESKubeControllersController) esGatewayAddCloudModificationsToConfig(c *esgateway.Config, esAdminUserSecret *corev1.Secret, reqLogger logr.Logger, ctx context.Context) (bool, error) {
	c.Cloud.Enabled = true
	c.Cloud.EsAdminUserSecret = esAdminUserSecret
	c.Cloud.ExternalElastic = true

	cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve tigera-secure-cloud-config config map", err, reqLogger)
			return false, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve tigera-secure-cloud-config config map", err, reqLogger)
		return false, err
	}

	c.Cloud.ExternalESDomain = cloudConfig.ExternalESDomain()
	c.Cloud.ExternalKibanaDomain = cloudConfig.ExternalKibanaDomain()

	if cloudConfig.EnableMTLS() {
		c.Cloud.ExternalCertsSecret, err = utils.GetSecret(ctx, r.client, logstorage.ExternalCertsSecret, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Waiting for external Elasticsearch certs secret to be available", err, reqLogger)
			return false, err
		}
		if c.Cloud.ExternalCertsSecret == nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Waiting for external Elasticsearch certs secret to be available", err, reqLogger)
			return false, nil
		}
		c.Cloud.EnableMTLS = cloudConfig.EnableMTLS()
	}

	if cloudConfig.TenantId() != "" {
		c.Cloud.TenantId = cloudConfig.TenantId()
	}

	return true, nil
}

// esKubeControllersAddCloudModificationsToConfig modifies the provided *kubecontrollers.KubeControllersConfiguration to include Calico Cloud specific configuration.
func (r *ESKubeControllersController) esKubeControllersAddCloudModificationsToConfig(c *kubecontrollers.KubeControllersConfiguration, reqLogger logr.Logger, ctx context.Context) (reconcile.Result, bool, error) {
	if r.cloud && r.elasticExternal && !r.multiTenant {
		cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
		if err != nil {
			if errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceReadError, "tigera-secure-cloud-config config map not found", err, reqLogger)
				return reconcile.Result{}, false, nil
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve tigera-secure-cloud-config config map", err, reqLogger)
			return reconcile.Result{}, false, err
		}

		if cloudConfig.TenantId() != "" {
			c.TenantId = cloudConfig.TenantId()
		}
	}

	return reconcile.Result{}, true, nil
}
