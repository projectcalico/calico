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

package secrets

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	rcertificatemanagement "github.com/projectcalico/calico/operator/pkg/render/certificatemanagement"
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

type ClusterCAController struct {
	client        client.Client
	scheme        *runtime.Scheme
	clusterDomain string
	log           logr.Logger
}

func AddClusterCAController(mgr manager.Manager, opts options.ControllerOptions) error {
	r := &ClusterCAController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		clusterDomain: opts.ClusterDomain,
		log:           logf.Log.WithName("controller_cluster_ca"),
	}

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("cluster-ca-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for triggers.
	if err = c.WatchObject(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("cluster-ca-controller failed to watch primary resource: %w", err)
	}
	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("cluster-ca-controller failed to watch CA secret: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("cluster-ca-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (r *ClusterCAController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logc := r.log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)

	// Get Installation resource.
	installationSpec, err := utils.GetComputedInstallationSpec(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			logc.Info("Installation not found")
			return reconcile.Result{}, err
		}
		logc.Error(err, "Error querying installation")
		return reconcile.Result{}, err
	}

	// Create the cluster CA. This is done implicitly by initializing a certificate manager instance
	// and passing the "AllowCACreation" option. The cluster CA is used in single-tenant mode to sign all other certificates.
	// In multi-tenant mode, this certificate is used to sign certificates for components that do not belong to any one tenant.
	opts := []certificatemanager.Option{
		certificatemanager.AllowCACreation(),
		certificatemanager.WithLogger(logc),
	}
	cm, err := certificatemanager.Create(r.client, installationSpec, r.clusterDomain, common.OperatorNamespace(), opts...)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Provision the CA into the cluster.
	component := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      common.OperatorNamespace(),
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{rcertificatemanagement.NewKeyPairOption(cm.KeyPair(), true, false)},
	})

	ownerResource := &operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, ownerResource); err != nil {
		logc.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}

	hdler := utils.NewComponentHandler(logc, r.client, r.scheme, ownerResource)
	if err = hdler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
