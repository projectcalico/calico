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

package manager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
)

func TestEnv(t *testing.T) {
	var (
		ctx = context.Background()
	)

	for _, tc := range []struct {
		name                 string
		configMapData        map[string]string
		expectedEnvVars      map[string]string
		expectedManagerImage string
	}{
		{
			name:            "no data",
			configMapData:   map[string]string{},
			expectedEnvVars: map[string]string{},
		},
		{
			name:                 "manager image",
			configMapData:        map[string]string{"managerImage": "tigera/manager:foo"},
			expectedEnvVars:      map[string]string{},
			expectedManagerImage: "tigera/manager:foo",
		},
		{
			name:            "arbitrary var set",
			configMapData:   map[string]string{"FOO": "BAR"},
			expectedEnvVars: map[string]string{"FOO": "BAR"},
		},
		{
			name:            "arbitrary known usage value set",
			configMapData:   map[string]string{"ENABLE_CC_USAGE": "true"},
			expectedEnvVars: map[string]string{"ENABLE_CC_USAGE": "true"},
		},
		{
			name:          "legacy portal api settings set",
			configMapData: map[string]string{"portalAPIURL": "test.calicocloud.io"},
			expectedEnvVars: map[string]string{
				"CNX_PORTAL_URL":        "test.calicocloud.io",
				"ENABLE_PORTAL_SUPPORT": "true",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				c = fake.NewClientBuilder().Build()

				rm = &ReconcileManager{
					client: c,
				}

				mcr = &render.ManagerCloudResources{
					ManagerExtraEnv: make(map[string]string),
				}
			)

			require.NoError(t, c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      CloudManagerConfigOverrideName,
					Namespace: common.OperatorNamespace(),
				},
				Data: tc.configMapData,
			}))

			err := rm.cloudConfigOverride(ctx, common.OperatorNamespace(), mcr)
			require.NoError(t, err)
			require.Equal(t, tc.expectedEnvVars, mcr.ManagerExtraEnv)
			require.Equal(t, tc.expectedManagerImage, mcr.ManagerImage)
		})
	}
}
