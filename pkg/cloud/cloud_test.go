// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package cloud

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	// stub the watcher for testing
	watch = func(cs kubernetes.Interface, cmData map[string]string) error { return nil }
}

func TestLoad(t *testing.T) {
	var (
		ctx = context.Background()

		// helper function to produce a fake kubernetes client which will return a configmap
		// containing the specified map data.
		clientWithConfigMapData = func(data map[string]string) kubernetes.Interface {
			return fake.NewSimpleClientset(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: common.OperatorNamespace(),
				},
				Data: data,
			})
		}
	)

	for _, tc := range []struct {
		name string
		// noConfigMap, when true, builds a client with no cloud-operator-config configmap at all.
		noConfigMap bool
		// env is a function to set desired env vars
		env func()
		// cmData is the map of data which the test harness should load into a configmap
		cmData map[string]string

		assert func(*testing.T, Options, error)
	}{
		{
			name:        "non-cloud when CALICO_CLOUD unset (even with configmap present)",
			noConfigMap: false,
			cmData:      map[string]string{"ELASTIC_EXTERNAL": "true"},
			assert: func(t *testing.T, opts Options, err error) {
				require.NoError(t, err)
				require.False(t, opts.Cloud)
				require.False(t, opts.ElasticExternal)
			},
		},
		{
			name: "error if CALICO_CLOUD is not a valid bool",
			env: func() {
				_ = os.Setenv(EnableCloudEnvVar, "yes-please")
			},
			noConfigMap: true,
			assert: func(t *testing.T, opts Options, err error) {
				require.ErrorContains(t, err, "unable to convert env CALICO_CLOUD")
			},
		},
		{
			name: "error if ELASTIC_EXTERNAL omitted",
			env: func() {
				_ = os.Setenv(EnableCloudEnvVar, "true")
			},
			cmData: map[string]string{},
			assert: func(t *testing.T, opts Options, err error) {
				require.ErrorContains(t, err, "value ELASTIC_EXTERNAL not found")
			},
		},
		{
			name: "ELASTIC_EXTERNAL parsed from configmap",
			env: func() {
				_ = os.Setenv(EnableCloudEnvVar, "true")
			},
			cmData: map[string]string{
				"ELASTIC_EXTERNAL": "true",
			},
			assert: func(t *testing.T, opts Options, err error) {
				require.NoError(t, err)
				require.True(t, opts.Cloud)
				require.True(t, opts.ElasticExternal)
			},
		},
		{
			name:        "ELASTIC_EXTERNAL parsed from env",
			noConfigMap: true,
			env: func() {
				_ = os.Setenv(EnableCloudEnvVar, "true")
				_ = os.Setenv("ELASTIC_EXTERNAL", "true")
			},
			assert: func(t *testing.T, opts Options, err error) {
				require.NoError(t, err)
				require.True(t, opts.Cloud)
				require.True(t, opts.ElasticExternal)
			},
		},
		{
			name: "ELASTIC_EXTERNAL errors if set to different value",
			env: func() {
				_ = os.Setenv(EnableCloudEnvVar, "true")
				_ = os.Setenv("ELASTIC_EXTERNAL", "false")
			},
			cmData: map[string]string{
				"ELASTIC_EXTERNAL": "true",
			},
			assert: func(t *testing.T, opts Options, err error) {
				require.ErrorContains(t, err, "value for ELASTIC_EXTERNAL differs: set to true in configmap and false in env")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Clearenv()

			var c kubernetes.Interface
			if tc.noConfigMap {
				c = fake.NewSimpleClientset()
			} else {
				c = clientWithConfigMapData(tc.cmData)
			}
			if tc.env != nil {
				tc.env()
			}

			opts, err := Load(ctx, c)
			tc.assert(t, opts, err)
		})
	}
}

func TestVerify(t *testing.T) {
	ctx := context.Background()

	t.Run("external-es", func(t *testing.T) {
		t.Run("pass verification to run if no secret present", func(t *testing.T) {
			err := verify(ctx, fake.NewSimpleClientset(), Options{ElasticExternal: true})
			require.NoError(t, err)
		})
		t.Run("pass verification to run if external-es secret is present", func(t *testing.T) {
			cs := fake.NewSimpleClientset(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      logstorage.ExternalCertsSecret,
					Namespace: render.ElasticsearchNamespace,
				},
			})
			err := verify(ctx, cs, Options{ElasticExternal: true})
			require.NoError(t, err)
		})

		t.Run("fail verification to run if internal-es secret is present", func(t *testing.T) {
			cs := fake.NewSimpleClientset(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.TigeraElasticsearchInternalCertSecret,
					Namespace: render.ElasticsearchNamespace,
				},
			})
			err := verify(ctx, cs, Options{ElasticExternal: true})
			require.ErrorContains(t, err, "refusing to run: operator configured as external-es")
		})
	})

	t.Run("internal-es", func(t *testing.T) {
		t.Run("pass verification to run if no external-es secret present", func(t *testing.T) {
			err := verify(ctx, fake.NewSimpleClientset(), Options{ElasticExternal: false})
			require.NoError(t, err)
		})

		t.Run("pass verification to run if internal-es secret is present", func(t *testing.T) {
			cs := fake.NewSimpleClientset(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.TigeraElasticsearchInternalCertSecret,
					Namespace: render.ElasticsearchNamespace,
				},
			})
			err := verify(ctx, cs, Options{ElasticExternal: false})
			require.NoError(t, err)
		})

		t.Run("fail verification to run if external-es secret is present", func(t *testing.T) {
			cs := fake.NewSimpleClientset(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      logstorage.ExternalCertsSecret,
					Namespace: render.ElasticsearchNamespace,
				},
			})
			err := verify(ctx, cs, Options{ElasticExternal: false})
			require.ErrorContains(t, err, "refusing to run: operator configured as internal-es but configmap")
		})
	})
}
