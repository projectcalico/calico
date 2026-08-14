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

	"github.com/tigera/operator/pkg/common"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getCloudKeyValidatorOption reads the cloud-auth-config ConfigMap (present only on Calico Cloud
// single-tenant management clusters) and returns an Option that configures the KeyValidatorConfig
// to require the cloud tenant claim. It is only called when cloud tenancy is enabled.
func getCloudKeyValidatorOption(ctx context.Context, cli client.Client) (tigerakvc.Option, error) {
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

	return tigerakvc.WithTenantClaim(tenantID), nil
}
