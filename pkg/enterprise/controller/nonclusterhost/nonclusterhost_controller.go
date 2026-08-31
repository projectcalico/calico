// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package nonclusterhost

import (
	"context"
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	eutils "github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/render/nonclusterhost"
	"github.com/tigera/operator/pkg/url"
)

const controllerName = "nonclusterhost-controller"

var log = logf.Log.WithName("controller_nonclusterhost")

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	// create the reconciler
	reconciler := newReconciler(mgr, opts)

	// create a new controller
	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create nonclusterhost-controller: %w", err)
	}

	return add(mgr, c)
}

func newReconciler(mgr manager.Manager, opts options.ControllerOptions) reconcile.Reconciler {
	r := &ReconcileNonClusterHost{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		status: status.New(mgr.GetClient(), "non-cluster-hosts", opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

func add(mgr manager.Manager, c ctrlruntime.Controller) error {
	if err := c.WatchObject(&operatorv1.NonClusterHost{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch resource: %w", controllerName, err)
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileNonClusterHost{}

type ReconcileNonClusterHost struct {
	client client.Client
	scheme *runtime.Scheme
	status status.StatusManager
}

func (r *ReconcileNonClusterHost) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	logc.Info("Reconciling NonClusterHost")

	instance, err := eutils.GetNonClusterHost(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query NonClusterHost resource", err, logc)
		return reconcile.Result{}, err
	} else if instance == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	logc.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Validate endpoint fields
	_, _, _, err = url.ParseEndpoint(instance.Spec.Endpoint)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid endpoint", err, logc)
		return reconcile.Result{}, err
	}

	_, _, err = net.SplitHostPort(instance.Spec.TyphaEndpoint)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid Typha endpoint", err, logc)
		return reconcile.Result{}, err
	}

	config := &nonclusterhost.Config{
		NonClusterHost: instance.Spec,
	}
	component := nonclusterhost.NonClusterHost(config)

	ch := utils.NewComponentHandler(logc, r.client, r.scheme, instance)
	if err = ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
		return reconcile.Result{}, err
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	return reconcile.Result{}, nil
}
