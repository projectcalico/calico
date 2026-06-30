// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package kubecontrollers

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	lscommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

func (r *ESKubeControllersController) createESGateway(
	ctx context.Context,
	helper utils.NamespaceHelper,
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	trustedBundle certificatemanagement.TrustedBundleRO,
	logStorage *operatorv1.LogStorage,
) error {
	// Get the ES admin user secret. For internal ES, this is provisioned by the ECK operator as part of installing Elasticsearch,
	// and so may not be immediately available.
	adminSecretNamespace := render.ElasticsearchNamespace
	if r.elasticExternal {
		// For external ES, we don't run ECK. Instead, this is provided to us by the cluster provisioner in the tigera-operator namespace.
		adminSecretNamespace = common.OperatorNamespace()
	}
	esAdminUserSecret, err := utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, adminSecretNamespace)
	if err != nil {
		reqLogger.Error(err, "failed to get Elasticsearch admin user secret")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch admin user secret", err, reqLogger)
		return err
	} else if esAdminUserSecret == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for elasticsearch admin secret", nil, reqLogger)
		return nil
	}

	// This secret should only ever contain one key.
	if len(esAdminUserSecret.Data) != 1 {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Elasticsearch admin user secret contains too many entries", nil, reqLogger)
		return nil
	}

	var esAdminUserName string
	for k := range esAdminUserSecret.Data {
		esAdminUserName = k
		break
	}

	// Collect the certificates we need to provision ESGW. These will have been provisioned already by the ES secrets controller.
	cm, err := certificatemanager.Create(r.client, install, r.clusterDomain, helper.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return err
	}
	// For legacy reasons, es-gateway is sitting behind two services: tigera-secure-es-http (where originally ES resided)
	// and tigera-secure-es-gateway-http.
	gatewayDNSNames := append(
		dns.GetServiceDNSNames(render.ElasticsearchServiceName, helper.InstallNamespace(), r.clusterDomain),
		dns.GetServiceDNSNames(esgateway.ServiceName, helper.InstallNamespace(), r.clusterDomain)...,
	)
	gatewayKeyPair, err := cm.GetKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, helper.TruthNamespace(), gatewayDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Error getting TLS certificate", err, log)
		return err
	} else if gatewayKeyPair == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "es-gateway key pair not yet available", err, log)
		return err
	}

	kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, err := lscommon.CreateKubeControllersSecrets(ctx, esAdminUserSecret, esAdminUserName, r.client, helper)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create kube-controllers secrets for Elasticsearch gateway", err, reqLogger)
		return err
	}

	cfg := &esgateway.Config{
		Installation:               install,
		PullSecrets:                pullSecrets,
		TrustedBundle:              trustedBundle,
		KubeControllersUserSecrets: []*corev1.Secret{kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret},
		ClusterDomain:              r.clusterDomain,
		EsAdminUserName:            esAdminUserName,
		ESGatewayKeyPair:           gatewayKeyPair,
		Namespace:                  helper.InstallNamespace(),
		TruthNamespace:             helper.TruthNamespace(),
		LogStorage:                 logStorage,
	}

	// Calico Cloud modifications. Only applied for cloud external-ES installs.
	if r.cloud && r.elasticExternal {
		if proceed, err := r.esGatewayAddCloudModificationsToConfig(cfg, esAdminUserSecret, reqLogger, ctx); err != nil || !proceed {
			return err
		}
	}

	esGatewayComponent := esgateway.EsGateway(cfg)
	if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return err
	}

	for _, comp := range []render.Component{esGatewayComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return err
		}
	}
	return nil
}
