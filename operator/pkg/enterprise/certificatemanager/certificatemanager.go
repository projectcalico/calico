// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

// Package certificatemanager adapts the generic certificate manager for Enterprise
// controllers, which run in clusters that may host more than one tenant.
package certificatemanager

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Create returns a certificate manager for the given tenant. Multi-tenant clusters keep a
// per-tenant CA, so each tenant's manager signs with its own.
func Create(cli client.Client, installation *operatorv1.InstallationSpec, clusterDomain, ns string, tenant *operatorv1.Tenant, opts ...certificatemanager.Option) (certificatemanager.CertificateManager, error) {
	if tenant.MultiTenant() {
		opts = append(opts, certificatemanager.WithCASecretName(certificatemanagement.TenantCASecretName))
	}
	return certificatemanager.Create(cli, installation, clusterDomain, ns, opts...)
}

// CreateTenantBundleWithSystemRootCertificates creates the trusted bundle holding public CAs.
// A multi-tenant namespace needs both this and a bundle without them, so the two are stored
// under different names.
func CreateTenantBundleWithSystemRootCertificates(cm certificatemanager.CertificateManager, certificates ...certificatemanagement.CertificateInterface) (certificatemanagement.TrustedBundle, error) {
	return certificatemanagement.CreateTrustedBundleWithName(certificatemanagement.TrustedCertConfigMapNamePublic, true, cm.KeyPair(), certificates...)
}

// LoadTenantBundleWithSystemRootCertificates loads the bundle created by
// CreateTenantBundleWithSystemRootCertificates so another controller can mount it.
func LoadTenantBundleWithSystemRootCertificates(ctx context.Context, cm certificatemanager.CertificateManager, cli client.Client, ns string) (certificatemanagement.TrustedBundleRO, error) {
	return cm.LoadNamedTrustedBundle(ctx, cli, ns, certificatemanagement.TrustedCertConfigMapNamePublic)
}
