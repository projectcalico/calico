// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package tiers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/render/tiers"
)

// The Tiers controller reconciles Tiers and NetworkPolicies that are shared across components or do not directly
// relate to any particular component.

var log = logf.Log.WithName("controller_tiers")

// Add creates a new Tiers Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	r := &ReconcileTiers{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		status: status.New(mgr.GetClient(), "tiers", opts.KubernetesVersion),
		opts:   opts,
	}
	r.status.Run(opts.ShutdownContext)

	c, err := ctrlruntime.NewController("tiers-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, nil)

	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: tiers.ClusterDNSPolicyName, Namespace: "openshift-dns"},
		{Name: tiers.ClusterDNSPolicyName, Namespace: "kube-system"},
	})

	if opts.MultiTenant {
		if err = c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("tiers-controller failed to watch Tenant resource: %w", err)
		}
	}

	if err := utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("tiers-controller failed to watch Installation resource: %v", err)
	}

	if err := utils.AddAPIServerWatch(c); err != nil {
		return fmt.Errorf("tiers-controller failed to watch APIServer resource: %v", err)
	}

	if err := utils.AddNodeLocalDNSWatch(c); err != nil {
		return fmt.Errorf("tiers-controller failed to watch node-local-dns daemonset: %v", err)
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileTiers{}

type ReconcileTiers struct {
	client             client.Client
	scheme             *runtime.Scheme
	status             status.StatusManager
	tierWatchReady     *utils.ReadyFlag
	policyWatchesReady *utils.ReadyFlag
	opts               options.ControllerOptions
}

func (r *ReconcileTiers) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Tiers")

	// Mark CR as found even though this controller is not associated with a CR, as OnCRFound() enables TigeraStatus reporting.
	r.status.OnCRFound()

	if !utils.IsProjectCalicoV3Available(r.client, r.opts, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	if r.opts.Cloud {
		if err := r.cloudPatchTier(ctx); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching tier", err, reqLogger)
			return reconcile.Result{}, nil
		}
	}

	tiersConfig, reconcileResult := r.prepareTiersConfig(ctx, reqLogger)
	if reconcileResult != nil {
		return *reconcileResult, nil
	}

	component := tiers.Tiers(tiersConfig)

	componentHandler := utils.NewComponentHandler(log, r.client, r.scheme, nil)
	err := componentHandler.CreateOrUpdateOrDelete(ctx, component, nil)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Try to delete allow-tigera deprecated tier
	err = componentHandler.CreateOrUpdateOrDelete(ctx, render.NewDeletionPassthrough(&v3.Tier{
		TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
	}), nil)
	if err != nil {
		log.V(1).Info("Unable to delete deprecated allow-tigera tier at this time", "error", err)
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}

func (r *ReconcileTiers) prepareTiersConfig(ctx context.Context, reqLogger logr.Logger) (*tiers.Config, *reconcile.Result) {
	tiersConfig := tiers.Config{
		OpenShift:      r.opts.DetectedProvider.IsOpenShift(),
		DNSEgressCIDRs: tiers.DNSEgressCIDR{},
	}

	// Determine the namespaces that should be allowed to access the DNS service. For single tenant clusters, this is a
	// well-known list of namespaces that contain product code.
	namespaces := []string{
		common.CalicoNamespace,
	}
	if r.opts.EnterpriseCRDExists {
		namespaces = append(namespaces,
			render.ComplianceNamespace,
			render.DexNamespace,
			render.ElasticsearchNamespace,
			render.IntrusionDetectionNamespace,
			kibana.Namespace,
			eck.OperatorNamespace,
			render.PacketCaptureNamespace,
			common.TigeraPrometheusNamespace,
			"tigera-skraper",
		)
	}
	if r.opts.MultiTenant {
		// For multi-tenant clusters, we need to include well-known namespaces as well as per-tenant namespaces.
		tenantNamespaces, err := utils.TenantNamespaces(ctx, r.client, nil)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying tenant namespaces", err, reqLogger)
			return nil, &reconcile.Result{RequeueAfter: utils.StandardRetry}
		}
		namespaces = append(namespaces, tenantNamespaces...)
	}
	tiersConfig.CalicoNamespaces = namespaces

	// node-local-dns is not supported on openshift
	if r.opts.DetectedProvider != operatorv1.ProviderOpenShift {
		nodeLocalDNSExists, err := utils.IsNodeLocalDNSAvailable(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying node-local-dns pods", err, reqLogger)
			return nil, &reconcile.Result{RequeueAfter: utils.StandardRetry}
		} else if nodeLocalDNSExists {
			dnsServiceIPs, err := utils.GetDNSServiceIPs(ctx, r.client, r.opts.DetectedProvider)
			if err != nil {
				if apierrors.IsNotFound(err) {
					r.status.SetDegraded(operatorv1.ResourceNotFound, "Unable to find DNS service", err, reqLogger)
				} else {
					r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying DNS service", err, reqLogger)
				}
				return nil, &reconcile.Result{RequeueAfter: utils.StandardRetry}
			}

			if len(dnsServiceIPs) > 0 {
				for _, IP := range dnsServiceIPs {
					var builder strings.Builder
					builder.WriteString(IP)
					if net.ParseIP(IP).To4() != nil {
						builder.WriteString("/32")
						tiersConfig.DNSEgressCIDRs.IPV4 = append(tiersConfig.DNSEgressCIDRs.IPV4, builder.String())
					} else {
						builder.WriteString("/128")
						tiersConfig.DNSEgressCIDRs.IPV6 = append(tiersConfig.DNSEgressCIDRs.IPV6, builder.String())
					}
				}
			} else {
				r.status.SetDegraded(operatorv1.ResourceReadError,
					"DNS service Spec.ClusterIPs is empty",
					errors.New("DNS service Spec.ClusterIPs is empty"),
					reqLogger)
			}

		}
	}

	return &tiersConfig, nil
}
