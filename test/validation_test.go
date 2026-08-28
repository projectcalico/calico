// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

var c client.Client

func testSetup(t *testing.T) func() {
	err := apis.AddToScheme(scheme.Scheme, false)
	require.NoError(t, err, "failed to add APIs to scheme")

	cfg, err := config.GetConfig()
	require.NoError(t, err, "failed to get kubeconfig")

	c, err = client.New(cfg, client.Options{})
	require.NoError(t, err, "failed to create k8s client")

	return func() {}
}

// TestNameValidation verifies that name validation logic works as expected, and that CRs with invalid names are rejected.
func TestNameValidation(t *testing.T) {
	type testCase struct {
		cr  client.Object
		err string
	}

	testCases := []testCase{
		// Valid test cases.
		{cr: &v1.Installation{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		{cr: &v1.Installation{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.Installation{ObjectMeta: metav1.ObjectMeta{Name: "overlay"}}},
		{cr: &v1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		{cr: &v1.Whisker{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		{cr: &v1.Goldmane{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		{cr: &v1.Monitor{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.LogCollector{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.PacketCaptureAPI{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.LogStorage{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.Authentication{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}, Spec: v1.AuthenticationSpec{ManagerDomain: "example.com"}}},
		{cr: &v1.ManagementCluster{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.ApplicationLayer{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.Manager{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.ManagementClusterConnection{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		{cr: &v1.GatewayAPI{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		{cr: &v1.PolicyRecommendation{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}},
		{cr: &v1.Istio{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},

		// Invalid test cases.
		{cr: &v1.Installation{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.Whisker{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.Goldmane{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.Monitor{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.LogCollector{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.PacketCaptureAPI{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.LogStorage{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.Authentication{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}, Spec: v1.AuthenticationSpec{ManagerDomain: "example.com"}}, err: "name must be"},
		{cr: &v1.ManagementCluster{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.ApplicationLayer{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.Manager{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.ManagementClusterConnection{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.GatewayAPI{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.PolicyRecommendation{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
		{cr: &v1.Istio{ObjectMeta: metav1.ObjectMeta{Name: "invalidname"}}, err: "name must be"},
	}

	for _, tc := range testCases {
		// build the test name.
		name := fmt.Sprintf("%T with name %q", tc.cr, tc.cr.GetName())
		if tc.err != "" {
			name += " should fail"
		} else {
			name += " should pass"
		}

		t.Run(name, func(t *testing.T) {
			defer testSetup(t)()

			err := c.Create(context.TODO(), tc.cr)
			if tc.err != "" {
				require.Error(t, err, "expected error but got none")
				require.Contains(t, err.Error(), tc.err, fmt.Sprintf("error message should contain %q", tc.err))
			} else {
				require.NoError(t, err, "expected no error but got one")

				// Clean up
				err = c.Delete(context.TODO(), tc.cr)
				require.NoError(t, err, "failed to delete CR")
			}
		})
	}
}
