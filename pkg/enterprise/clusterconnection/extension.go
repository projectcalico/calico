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

package clusterconnection

import (
	"context"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("clusterconnection-controller")

// Extension is the Calico Enterprise behavior for the clusterconnection controller
// and the guardian components it renders.
type Extension struct {
	variant operatorv1.ProductVariant
}

var _ extensions.ClusterConnectionExtension = &Extension{}

// New returns the clusterconnection extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant) *Extension {
	return &Extension{variant: variant}
}

// Modify dispatches over the components the clusterconnection controller renders.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	switch t := c.(type) {
	case render.GuardianComponent:
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyGuardian(ri, t.GuardianConfig(), objs, del)
		})
	case render.GuardianPolicyComponent:
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyGuardianPolicy(ri, t.GuardianPolicyConfig(), objs, del)
		})
	default:
		return c
	}
}

// Watches registers the resources only Enterprise guardian renders from.
func (e *Extension) Watches(c ctrlruntime.Controller, cs kubernetes.Interface) error {
	// The license gates whether this controller reconciles network policy.
	go utils.WaitToAddLicenseKeyWatch(c, cs, log, nil)

	if err := c.WatchObject(&operatorv1.ManagementCluster{}, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}
	for _, secretName := range []string{
		render.PacketCaptureServerCert,
		monitor.PrometheusServerTLSSecretName,
		certificatemanagement.CASecretName,
	} {
		if err := utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return err
		}
	}
	return imageset.AddImageSetWatch(c)
}

// ValidateAndDefault accepts the Enterprise-only fields and defaults impersonation
// to empty lists so Guardian renders a stable config.
func (e *Extension) ValidateAndDefault(cr *operatorv1.ManagementClusterConnection) error {
	if cr.Spec.Impersonation == nil {
		cr.Spec.Impersonation = &operatorv1.Impersonation{
			Users:           []string{},
			Groups:          []string{},
			ServiceAccounts: []string{},
		}
	}
	return nil
}

func (e *Extension) validate(ctx context.Context, ci controller.Inputs) error {
	managementCluster, err := utils.GetManagementCluster(ctx, ci.Client)
	if err != nil {
		return fmt.Errorf("error reading ManagementCluster: %w", err)
	}
	if managementCluster != nil {
		return extensions.InvalidConfigf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
	}
	return nil
}

// ExtendInputs computes the Enterprise-specific Guardian inputs the controller
// reads back: the managed cluster version (CNXVersion) and whether the license
// permits the domain-based egress network policy. It creates no certificates, so it
// returns no managed keypairs. The OSS controller path supplies its own defaults
// when this hook is absent.
func (e *Extension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	if err := e.validate(ctx, ci); err != nil {
		return ci, nil, err
	}

	clusterInformation, err := utils.FetchClusterInformation(ctx, ci.Client)
	if err != nil {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error querying ClusterInformation: %s", err)
	}

	// Ensure the license can support enterprise policy before enabling the
	// domain-based egress rules. A missing license simply leaves them disabled.
	var includeEgressNetworkPolicy bool
	if license, err := utils.FetchLicenseKey(ctx, ci.Client); err == nil {
		includeEgressNetworkPolicy = utils.IsFeatureActive(license, common.EgressAccessControlFeature)
	} else if !k8serrors.IsNotFound(err) {
		return ci, nil, extensions.Degradedf(operatorv1.ResourceReadError, "error querying license: %s", err)
	}

	ci.RenderInputs.Extension = render.GuardianRenderData{
		Version:                    clusterInformation.Spec.CNXVersion,
		IncludeEgressNetworkPolicy: includeEgressNetworkPolicy,
	}
	return ci, nil, nil
}
