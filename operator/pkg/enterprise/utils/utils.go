// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
)

func LogStorageExists(ctx context.Context, cli client.Client) (bool, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, utils.DefaultEnterpriseInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func GetLogCollector(ctx context.Context, cli client.Client) (*operatorv1.LogCollector, error) {
	logCollector := &operatorv1.LogCollector{}
	err := cli.Get(ctx, utils.DefaultEnterpriseInstanceKey, logCollector)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return logCollector, nil
}

// Return the AplicationLayer CR if present. No error is returned if it was not
// found.
func GetApplicationLayer(ctx context.Context, c client.Client) (*operatorv1.ApplicationLayer, error) {
	applicationLayer := &operatorv1.ApplicationLayer{}

	err := c.Get(ctx, utils.DefaultEnterpriseInstanceKey, applicationLayer)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return applicationLayer, nil
}

// GetManager returns the Manager CR, or nil if it is not found. When
// multiTenant is true the tenant-scoped instance is read from ns; otherwise the
// cluster-scoped instance is read and ns is ignored. A NoMatchError (the
// Manager CRD is not registered) is returned to the caller rather than treated
// as not-found: absence of the CRD is distinct from the user not having created
// a Manager, and the caller decides how to handle it.
func GetManager(ctx context.Context, cli client.Client, multiTenant bool, ns string) (*operatorv1.Manager, error) {
	key := utils.DefaultEnterpriseInstanceKey
	if multiTenant {
		key.Namespace = ns
	}
	instance := &operatorv1.Manager{}
	if err := cli.Get(ctx, key, instance); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return instance, nil
}

// Return the ManagementCluster CR if present. No error is returned if it was not found.
func GetManagementCluster(ctx context.Context, c client.Client) (*operatorv1.ManagementCluster, error) {
	managementCluster := &operatorv1.ManagementCluster{}

	err := c.Get(ctx, utils.DefaultEnterpriseInstanceKey, managementCluster)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return managementCluster, nil
}

// GetNonClusterHost finds the NonClusterHost CR in your cluster.
func GetNonClusterHost(ctx context.Context, cli client.Client) (*operatorv1.NonClusterHost, error) {
	nonclusterhost := &operatorv1.NonClusterHost{}

	err := cli.Get(ctx, utils.DefaultEnterpriseInstanceKey, nonclusterhost)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return nonclusterhost, nil
}

// GetAuthentication finds the authentication CR in your cluster.
func GetAuthentication(ctx context.Context, cli client.Client) (*operatorv1.Authentication, error) {
	authentication := &operatorv1.Authentication{}
	err := cli.Get(ctx, utils.DefaultEnterpriseInstanceKey, authentication)
	if err != nil {
		return nil, err
	}

	return authentication, nil
}

// GetPacketCapture finds the PacketCapture CR in your cluster.
func GetPacketCaptureAPI(ctx context.Context, cli client.Client) (*operatorv1.PacketCaptureAPI, error) {
	pc := &operatorv1.PacketCaptureAPI{}
	err := cli.Get(ctx, utils.DefaultEnterpriseInstanceKey, pc)
	if err != nil {
		return nil, err
	}

	return pc, nil
}

func DexEnabled(authentication *operatorv1.Authentication) bool {
	enableDex := authentication != nil
	if enableDex && authentication.Spec.OIDC != nil && authentication.Spec.OIDC.Type == operatorv1.OIDCTypeTigera {
		enableDex = false
	}
	return enableDex
}

// GetTenant returns the Tenant instance in the given namespace.
func GetTenant(ctx context.Context, mt bool, cli client.Client, ns string) (*operatorv1.Tenant, string, error) {
	if !mt {
		// Multi-tenancy isn't enabled. Return nil.
		return nil, "", nil
	}

	key := client.ObjectKey{Name: "default", Namespace: ns}
	instance := &operatorv1.Tenant{}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, "", err
	}

	if instance.Spec.ID == "" {
		return nil, "", fmt.Errorf("tenant %s/%s has no ID specified", ns, instance.Name)
	}
	return instance, instance.Spec.ID, nil
}

// TenantFilter is a function that accepts a tenant and returns true if the Tenant should be included
// in the query, and false otherwise.
type TenantFilter func(*operatorv1.Tenant) bool

// TenantNamespaces returns all namespaces that contain a tenant.
// include is an optional filter function that returns true if the tenant should be included, false otherwise.
func TenantNamespaces(ctx context.Context, cli client.Client, include TenantFilter) ([]string, error) {
	namespaces := []string{}
	tenants := operatorv1.TenantList{}
	err := cli.List(ctx, &tenants)
	if err != nil {
		return nil, err
	}
	for _, t := range tenants.Items {
		if include == nil || include(&t) {
			namespaces = append(namespaces, t.Namespace)
		}
	}

	// Sort the namespaces, so that the output is deterministic.
	sort.Strings(namespaces)
	return namespaces, nil
}

// HelperNamespaces is TenantNamespaces for a component, returning the install namespace
// when the helper is single-tenant.
func HelperNamespaces(ctx context.Context, cli client.Client, helper NamespaceHelper, include TenantFilter) ([]string, error) {
	if !helper.MultiTenant() {
		return []string{helper.InstallNamespace()}, nil
	}
	return TenantNamespaces(ctx, cli, include)
}

// ManagedCalicoOnly is a TenantFilter that matches tenants who manage Calico OSS clusters.
func ManagedCalicoOnly(t *operatorv1.Tenant) bool {
	return t.ManagedClusterIsCalico()
}

// ManagedEnterpriseOnly is a TenantFilter that matches tenants who manage Calico Enterprise clusters.
func ManagedEnterpriseOnly(t *operatorv1.Tenant) bool {
	return t != nil && !t.ManagedClusterIsCalico()
}
