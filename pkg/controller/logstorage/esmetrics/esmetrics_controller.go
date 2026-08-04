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

package esmetrics

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_logstorage_esmetrics")

type ESMetricsSubController struct {
	client         client.Client
	scheme         *runtime.Scheme
	status         status.StatusManager
	provider       operatorv1.Provider
	clusterDomain  string
	variant        operatorv1.ProductVariant
	multiTenant    bool
	tierWatchReady *utils.ReadyFlag
}

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		return nil
	}

	// We don't consume the metrics exported by ES Metrics internally and multi-tenant clusters are not for customer
	// consumption, so we don't need to run this controller in multi-tenant mode
	if opts.MultiTenant {
		return nil
	}

	r := &ESMetricsSubController{
		client:         mgr.GetClient(),
		scheme:         mgr.GetScheme(),
		status:         status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageESMetrics, opts.KubernetesVersion),
		clusterDomain:  opts.ClusterDomain,
		variant:        opts.Variant,
		provider:       opts.DetectedProvider,
		tierWatchReady: &utils.ReadyFlag{},
	}
	r.status.Run(opts.ShutdownContext)

	c, err := ctrlruntime.NewController("log-storage-esmetrics-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("log-storage-esmetrics-controller failed to establish a connection to k8s: %w", err)
	}

	if err = c.WatchObject(&operatorv1.LogStorage{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-esmetrics-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("log-storage-esmetrics-controller failed to watch Installation resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-esmetrics-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, render.ElasticsearchNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-esmetrics-controller failed to watch the Service resource: %w", err)
	}

	secretsToWatch := []string{
		esmetrics.ElasticsearchMetricsSecret,
		esmetrics.ElasticsearchMetricsServerTLSSecret,
	}
	for _, name := range secretsToWatch {
		if err = utils.AddSecretsWatch(c, name, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-esmetrics-controller failed to watch Secret: %w", err)
		}
	}

	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, r.tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: esmetrics.ElasticsearchMetricsPolicyName, Namespace: render.ElasticsearchNamespace},
	})

	return nil
}

func (r *ESMetricsSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - ES Metrics")

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Only install ES metrics if this is not a managed cluster.
	if managementClusterConnection != nil {
		return reconcile.Result{}, nil
	}

	logStorage := &operatorv1.LogStorage{}
	key := utils.DefaultEnterpriseInstanceKey
	err = r.client.Get(ctx, key, logStorage)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.OnCRFound()

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if logStorage.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying calico-system tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	esMetricsSecret, err := utils.GetSecret(context.Background(), r.client, esmetrics.ElasticsearchMetricsSecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve Elasticsearch metrics user secret.", err, reqLogger)
		return reconcile.Result{}, err
	} else if esMetricsSecret == nil {
		reqLogger.Info("Waiting for elasticsearch metrics secrets to become available")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for elasticsearch metrics secrets to become available", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	installationSpec, err := utils.GetInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving the pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	cm, err := certificatemanager.Create(r.client, installationSpec, r.clusterDomain, common.OperatorNamespace(), certificatemanager.WithLogger(reqLogger))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get the ES metrics server keypair. This will have previously been created by the ES secrets controller.
	metricsDNSNames := dns.GetServiceDNSNames(esmetrics.ElasticsearchMetricsName, render.ElasticsearchNamespace, r.clusterDomain)
	serverKeyPair, err := cm.GetKeyPair(r.client, esmetrics.ElasticsearchMetricsServerTLSSecret, render.ElasticsearchNamespace, metricsDNSNames)
	if err != nil {
		r.status.SetDegraded(
			operatorv1.ResourceReadError,
			fmt.Sprintf("Error getting secret %s/%s", render.ElasticsearchNamespace, esmetrics.ElasticsearchMetricsServerTLSSecret),
			err,
			log,
		)
		return reconcile.Result{}, err
	} else if serverKeyPair == nil {
		// Possibly LogStorage was removed and caused the secret to have been deleted.
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret %s/%s to be created", render.ElasticsearchNamespace, esmetrics.ElasticsearchMetricsServerTLSSecret), nil, reqLogger)
		return reconcile.Result{}, nil
	}

	trustedBundle, err := cm.LoadTrustedBundle(ctx, r.client, render.ElasticsearchNamespace)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, reqLogger)
		return reconcile.Result{}, err
	}

	flowShards := logstoragecommon.CalculateFlowShards(logStorage.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
	clusterConfig := relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, logStorage.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)

	esMetricsCfg := &esmetrics.Config{
		Installation:         installationSpec,
		PullSecrets:          pullSecrets,
		ESConfig:             clusterConfig,
		ESMetricsCredsSecret: esMetricsSecret,
		ClusterDomain:        r.clusterDomain,
		ServerTLS:            serverKeyPair,
		TrustedBundle:        trustedBundle,
		LogStorage:           logStorage,
	}
	esMetricsComponent := esmetrics.ElasticsearchMetrics(esMetricsCfg)
	if err = imageset.ApplyImageSet(ctx, r.client, r.variant, esMetricsComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, logStorage)

	if err = hdler.CreateOrUpdateOrDelete(ctx, esMetricsComponent, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}
