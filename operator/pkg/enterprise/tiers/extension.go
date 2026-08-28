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

package tiers

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ctrlruntime"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	eutils "github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
)

// Extension is the Enterprise hook into the tiers controller.
type Extension struct {
	opts eoptions.Options
}

func New(o eoptions.Options) extensions.TiersExtension {
	return &Extension{opts: o}
}

func (e *Extension) Watches(c ctrlruntime.Controller) error {
	if !e.opts.MultiTenant {
		return nil
	}
	return c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{})
}

func (e *Extension) DNSClientNamespaces(ctx context.Context, cli client.Client) ([]string, error) {
	namespaces := []string{
		render.DexNamespace,
		render.ElasticsearchNamespace,
		render.IntrusionDetectionNamespace,
		kibana.Namespace,
		eck.OperatorNamespace,
		render.PacketCaptureNamespace,
		common.TigeraPrometheusNamespace,
		"tigera-skraper",
	}
	if !e.opts.MultiTenant {
		return namespaces, nil
	}

	// For multi-tenant clusters, we need to include well-known namespaces as well as per-tenant namespaces.
	tenantNamespaces, err := eutils.TenantNamespaces(ctx, cli, nil)
	if err != nil {
		return nil, err
	}
	return append(namespaces, tenantNamespaces...), nil
}
