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

package elastic

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/externalelasticsearch"
)

type ExternalESController struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
	status status.StatusManager
	opts   options.ControllerOptions
}

func AddExternalES(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}
	if !opts.ElasticExternal {
		return nil
	}

	// Create the reconciler
	r := &ExternalESController{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		status: status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageElastic, opts.KubernetesVersion),
		opts:   opts,
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("log-storage-external-es-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.WatchObject(&operatorv1.LogStorage{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch Installation resource: %w", err)
	}
	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ImageSet: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementCluster{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, initializer.TigeraStatusLogStorageElastic); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch logstorage Tigerastatus: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, "cloud-kibana-config", common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err = utils.AddNamespaceWatch(c, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch tigera-elasticsearch namespace: %w", err)
	}

	if opts.Cloud {
		// Watched so single-tenant external-ES clusters re-reconcile when the cloud config map changes.
		if err := utils.AddConfigMapWatch(c, cloudconfig.CloudConfigConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
		}
	}

	return nil
}

func (r *ExternalESController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

	ls := &operatorv1.LogStorage{}
	err := r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, ls)
	if err != nil {
		if !errors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}
	r.status.OnCRFound()

	_, installationSpec, err := utils.GetInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !utils.IsProjectCalicoV3Available(r.client, r.opts, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{}, err
	}

	esNamespace, err := utils.GetIfExists[v1.Namespace](ctx, client.ObjectKey{Name: render.ElasticsearchNamespace}, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving elasticsearch namespace", err, reqLogger)
		return reconcile.Result{}, err
	} else if esNamespace == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for elasticsearch namespace to be created", err, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	flowShards := logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
	clusterConfig := relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)

	// Calico Cloud addition. For Calico Cloud single-tenant management clusters connected to a
	// multi-tenant external ES, augment the cluster config with this management cluster's tenant ID.
	if r.opts.Cloud && !r.opts.MultiTenant {
		cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
		if err != nil {
			if errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve tigera-secure-cloud-config config map", err, reqLogger)
				return reconcile.Result{}, nil
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve tigera-secure-cloud-config config map", err, reqLogger)
			return reconcile.Result{}, err
		}
		if cloudConfig.TenantId() != "" {
			clusterConfig.AddTenantId(cloudConfig.TenantId())
		}
	}

	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
	externalElasticsearch := externalelasticsearch.ExternalElasticsearch(installationSpec, clusterConfig, pullSecrets, r.opts.MultiTenant)
	for _, component := range []render.Component{externalElasticsearch} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}
