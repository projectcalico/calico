// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package users

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apiv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
	tigeraelastic "github.com/tigera/operator/pkg/controller/logstorage/elastic"
	"github.com/tigera/operator/pkg/controller/logstorage/esutils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("LogStorage cleanup controller", func() {
	var (
		cli client.Client
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(operatorv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
	})

	It("should clean up Elastic users for tenants that no longer exist", func() {
		t := &testing.T{}
		ctrl := UsersCleanupController{
			client:     cli,
			esClientFn: tigeraelastic.MockESCLICreator,
		}
		testESClient := tigeraelastic.MockESClient{}
		ctx := context.WithValue(context.Background(), tigeraelastic.MockESClientKey("mockESClient"), &testESClient)

		clusterID1 := "cluster1"
		clusterID2 := "cluster2"

		tenantID1 := "tenant1"
		tenantID2 := "tenant2"

		staleLinseedUser := esutils.LinseedUser(clusterID1, tenantID1)
		staleDashboardsUser := esutils.DashboardUser(clusterID1, tenantID1)

		esTestUsers := []esutils.User{
			*staleLinseedUser,
			*staleDashboardsUser,
			*esutils.LinseedUser(clusterID1, tenantID2),
			*esutils.DashboardUser(clusterID1, tenantID2),
			*esutils.LinseedUser(clusterID2, tenantID1),
			*esutils.DashboardUser(clusterID2, tenantID1),
			*esutils.LinseedUser(clusterID2, tenantID2),
			*esutils.DashboardUser(clusterID2, tenantID2),
		}

		testESClient.On("GetUsers", ctx).Return(esTestUsers, nil)
		testESClient.On("DeleteUser", ctx, staleLinseedUser).Return(nil)
		testESClient.On("DeleteRoles", ctx, staleLinseedUser.Roles).Return(nil)

		cluster1IDConfigMap := corev1.ConfigMap{
			ObjectMeta: apiv1.ObjectMeta{
				Name:      "cluster-info",
				Namespace: "tigera-operator",
			},
			Data: map[string]string{
				"cluster-id": clusterID1,
			},
		}
		err := cli.Create(ctx, &cluster1IDConfigMap)
		Expect(err).NotTo(HaveOccurred())

		cluster1Tenant2 := operatorv1.Tenant{
			ObjectMeta: apiv1.ObjectMeta{
				Name: "default",
			},
			Spec: operatorv1.TenantSpec{
				ID: tenantID2,
			},
		}

		err = cli.Create(ctx, &cluster1Tenant2)
		Expect(err).NotTo(HaveOccurred())

		logr := logf.Log.WithName("cleanup-controller-test")
		err = ctrl.cleanupStaleUsers(ctx, logr)
		Expect(err).NotTo(HaveOccurred())

		Expect(testESClient.AssertExpectations(t))
	})
})
