// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

	v1 "github.com/tigera/operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CloudAuthConfig is the name of the ConfigMap holding cloud authentication configuration
// (e.g. the tenantID) for a single-tenant cloud management cluster backed by internal Elasticsearch.
const CloudAuthConfig = "cloud-auth-config"

// GetCloudConfig retrieves the config map containing the configuration values needed to set up communications with
// external Elasticsearch and Kibana, such as the externalESDomain and externalKibanaDomain.
func GetCloudConfig(ctx context.Context, cli client.Client) (*cloudconfig.CloudConfig, error) {
	configMap := &corev1.ConfigMap{}
	if err := cli.Get(ctx, client.ObjectKey{Name: cloudconfig.CloudConfigConfigMapName, Namespace: common.OperatorNamespace()}, configMap); err != nil {
		return nil, err
	}

	return cloudconfig.NewCloudConfigFromConfigMap(configMap)
}

func GetTenantFromCloudAuthConfig(ctx context.Context, cli client.Client) (*v1.Tenant, error) {
	cm := &corev1.ConfigMap{}
	if err := cli.Get(ctx, types.NamespacedName{Name: CloudAuthConfig, Namespace: common.OperatorNamespace()}, cm); err != nil {
		return nil, fmt.Errorf("missing config map %s/%s: %w", common.OperatorNamespace(), CloudAuthConfig, err)
	}

	tenantID, ok := cm.Data["tenantID"]
	if !ok {
		return nil, fmt.Errorf("cloud config map %s/%s is missing the tenantID field", common.OperatorNamespace(), CloudAuthConfig)
	} else if tenantID == "" {
		return nil, fmt.Errorf("cloud config map %s/%s has empty tenantID field", common.OperatorNamespace(), CloudAuthConfig)
	}

	return &v1.Tenant{
		// We don't specify a Namespace for this tenant because it represents a singular tenant installed
		// in this management cluster. The signals to the render code that this is a single-tenant cluster and not
		// a cluster capable of multi-tenancy. We are also omitting elastic configuration since this setup maps
		// to internal elastic
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1.TenantSpec{
			ID: tenantID,
		},
	}, nil
}
