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

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	corev1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"
	apiv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	tigeraelastic "github.com/projectcalico/calico/operator/pkg/controller/logstorage/elastic"
	"github.com/projectcalico/calico/operator/pkg/controller/logstorage/esutils"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/enterprise/cloudconfig"
	eutils "github.com/projectcalico/calico/operator/pkg/enterprise/utils"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage/dashboards"
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

		tenant1 := &operatorv1.Tenant{Spec: operatorv1.TenantSpec{ID: tenantID1}}
		tenant2 := &operatorv1.Tenant{Spec: operatorv1.TenantSpec{ID: tenantID2}}

		staleLinseedUser := esutils.LinseedUser(clusterID1, tenant1)
		staleDashboardsUser := esutils.DashboardUser(clusterID1, tenantID1)

		esTestUsers := []esutils.User{
			*staleLinseedUser,
			*staleDashboardsUser,
			*esutils.LinseedUser(clusterID1, tenant2),
			*esutils.DashboardUser(clusterID1, tenantID2),
			*esutils.LinseedUser(clusterID2, tenant1),
			*esutils.DashboardUser(clusterID2, tenantID1),
			*esutils.LinseedUser(clusterID2, tenant2),
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

// fakeESClient records the users provisioned against Elasticsearch.
type fakeESClient struct {
	created []*esutils.User
}

func (f *fakeESClient) SetILMPolicies(context.Context, *operatorv1.LogStorage, bool) error {
	return nil
}

func (f *fakeESClient) CreateUser(_ context.Context, user *esutils.User) error {
	f.created = append(f.created, user)
	return nil
}

func (f *fakeESClient) DeleteUser(context.Context, *esutils.User) error { return nil }

func (f *fakeESClient) GetUsers(context.Context) ([]esutils.User, error) { return nil, nil }

var _ = Describe("LogStorage users controller", func() {
	const (
		tenantID = "tenant-a"
	)

	var (
		cli      client.Client
		ctx      context.Context
		scheme   *runtime.Scheme
		esClient *fakeESClient
		r        *UserController

		// cloudConfigMap describes a single-tenant cluster sharing an external Elasticsearch.
		cloudConfigMap *corev1.ConfigMap
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(operatorv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(esv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		Expect(cli.Create(ctx, ls)).NotTo(HaveOccurred())

		// Note that no cluster-info ConfigMap is created here: single-tenant clusters don't have one,
		// and the controller must not require it.
		cloudConfigMap = cloudconfig.NewCloudConfig(tenantID, "tenant-a-name", "es.example.com", "kb.example.com", false).ConfigMap()
		Expect(cli.Create(ctx, cloudConfigMap)).NotTo(HaveOccurred())

		mockStatus := &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")
		mockStatus.On("ClearWarning", mock.Anything).Return()
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

		esClient = &fakeESClient{}
		r = &UserController{
			client: cli,
			scheme: scheme,
			status: mockStatus,
			esClientFn: func(_ client.Client, _ context.Context, _ string, _ bool) (esutils.ElasticClient, error) {
				return esClient, nil
			},
			multiTenant:     false,
			elasticExternal: true,
			useSingleIndex:  true,
		}
	})

	// singleTenant builds the Tenant that the controller derives from the cloud config ConfigMap created above.
	singleTenant := func(opts ...eutils.TenantOption) *operatorv1.Tenant {
		return eutils.TenantFromCloudConfig(cloudconfig.NewCloudConfig(tenantID, "tenant-a-name", "es.example.com", "kb.example.com", false), opts...)
	}

	// secretValue reads a value from a Secret. The fake client doesn't convert StringData into Data
	// the way the API server does, so we may find the value in either field.
	secretValue := func(name, namespace, key string) string {
		s := &corev1.Secret{}
		ExpectWithOffset(1, cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, s)).NotTo(HaveOccurred())
		if v, ok := s.StringData[key]; ok {
			return v
		}
		return string(s.Data[key])
	}

	It("should provision users for a single-tenant cluster using single-index storage", func() {
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		// The Linseed user should be created in ES with the name es-kube-controllers used, and with
		// privileges on the single-index calico_* indices.
		expected := esutils.LinseedUserSingleTenant(singleTenant(eutils.WithStandardIndices()), true)
		Expect(expected.Username).To(Equal("tigera-ee-linseed-tenant-a-secure"))
		Expect(esClient.created).To(HaveLen(2))
		Expect(esClient.created[0].Username).To(Equal(expected.Username))
		Expect(esClient.created[0].FullName).To(Equal(esutils.SystemUserFullName))
		Expect(esClient.created[0].Roles).To(Equal(expected.Roles))
		Expect(esClient.created[0].Roles[0].Name).To(Equal(expected.Username))
		Expect(esClient.created[0].Roles[0].Definition.Indices[0].Names).To(ContainElement("calico_flowlogs_standard*"))
		Expect(esClient.created[0].Roles[0].Definition.Indices[0].Names).To(HaveLen(len(operatorv1.DataTypes)))
		Expect(esClient.created[1].Username).To(Equal("tigera-ee-dashboards-installer-tenant-a-secure"))
		Expect(esClient.created[1].FullName).To(Equal(esutils.SystemUserFullName))

		// The credentials should be written to the Elasticsearch namespace for Linseed to consume.
		Expect(secretValue(render.ElasticsearchLinseedUserSecret, render.ElasticsearchNamespace, "username")).To(Equal(expected.Username))
		Expect(secretValue(render.ElasticsearchLinseedUserSecret, render.ElasticsearchNamespace, "password")).NotTo(BeEmpty())
		Expect(secretValue(dashboards.ElasticCredentialsSecret, render.ElasticsearchNamespace, "username")).To(Equal(esutils.DashboardUserSingleTenant(tenantID, true).Username))
	})

	It("should re-point existing credentials at the operator provisioned user", func() {
		// es-kube-controllers uses a different naming convention for the ES user.
		Expect(cli.Create(ctx, &corev1.Secret{
			ObjectMeta: apiv1.ObjectMeta{Name: render.ElasticsearchLinseedUserSecret, Namespace: common.OperatorNamespace()},
			Data:       map[string][]byte{"username": []byte("tigera-ee-linseed"), "password": []byte("existing-password")},
		})).NotTo(HaveOccurred())

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		expected := esutils.LinseedUserSingleTenant(singleTenant(eutils.WithStandardIndices()), true)
		Expect(secretValue(render.ElasticsearchLinseedUserSecret, common.OperatorNamespace(), "username")).To(Equal(expected.Username))
		Expect(secretValue(render.ElasticsearchLinseedUserSecret, render.ElasticsearchNamespace, "username")).To(Equal(expected.Username))

		// The existing password is preserved, and used for the user we provision.
		Expect(secretValue(render.ElasticsearchLinseedUserSecret, common.OperatorNamespace(), "password")).To(Equal("existing-password"))
		Expect(esClient.created[0].Username).To(Equal(expected.Username))
		Expect(esClient.created[0].Password).To(Equal("existing-password"))
	})

	It("should grant the Linseed user the multi-index names when not using single-index storage", func() {
		r.useSingleIndex = false

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		// The user keeps its name, but is only granted access to this tenant's multi-index format indices.
		expected := esutils.LinseedUserSingleTenant(singleTenant(), true)
		Expect(esClient.created[0].Username).To(Equal(expected.Username))
		Expect(esClient.created[0].Roles[0].Definition.Indices[0].Names).To(Equal([]string{"tigera_secure_ee_*.tenant-a.*.*", "calico_policy_activity*"}))
	})

	Context("single-tenant cluster on its own Elasticsearch", func() {
		BeforeEach(func() {
			// The two single-tenant flavours are mutually exclusive: a cluster on its own Elasticsearch
			// has no cloud config ConfigMap, and is described by the cloud auth ConfigMap instead.
			Expect(cli.Delete(ctx, cloudConfigMap)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: apiv1.ObjectMeta{Name: eutils.CloudAuthConfig, Namespace: common.OperatorNamespace()},
				Data:       map[string]string{"tenantID": tenantID},
			})).NotTo(HaveOccurred())

			// On its own Elasticsearch the controller waits for the ES cluster to be operational.
			es := &esv1.Elasticsearch{}
			es.Name = "tigera-secure"
			es.Namespace = render.ElasticsearchNamespace
			es.Status.Phase = esv1.ElasticsearchReadyPhase
			Expect(cli.Create(ctx, es)).NotTo(HaveOccurred())

			r.elasticExternal = false
		})

		It("should read the tenant from the cloud auth ConfigMap", func() {
			tenant, configMap, err := r.singleTenant(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(configMap).To(Equal(eutils.CloudAuthConfig))
			Expect(tenant.Spec.ID).To(Equal(tenantID))

			// The cloud auth config carries the tenant ID alone, so no indices are declared even though
			// useSingleIndex is set - a cluster on its own Elasticsearch does not migrate.
			Expect(tenant.Spec.Indices).To(BeEmpty())
			Expect(tenant.Spec.Elastic).To(BeNil())
		})

		It("should provision users against the internal Elasticsearch", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			// es-kube-controllers is given no tenant ID on a cluster running its own Elasticsearch, so the
			// users it provisioned there carry no tenant qualifier - and neither do ours.
			Expect(esClient.created).To(HaveLen(2))
			Expect(esClient.created[0].Username).To(Equal("tigera-ee-linseed-secure"))
			Expect(esClient.created[1].Username).To(Equal("tigera-ee-dashboards-installer-secure"))

			// Indices in the cluster's own Elasticsearch carry no tenant qualifier, so neither does the
			// pattern the Linseed user is granted.
			Expect(esClient.created[0].Roles[0].Definition.Indices[0].Names).To(Equal([]string{"tigera_secure_ee_*.*.*", "calico_policy_activity*"}))

			Expect(secretValue(render.ElasticsearchLinseedUserSecret, render.ElasticsearchNamespace, "username")).To(Equal("tigera-ee-linseed-secure"))
			Expect(secretValue(render.ElasticsearchLinseedUserSecret, render.ElasticsearchNamespace, "password")).NotTo(BeEmpty())
		})

		It("should wait when the cloud auth ConfigMap does not exist yet", func() {
			Expect(cli.Delete(ctx, &corev1.ConfigMap{
				ObjectMeta: apiv1.ObjectMeta{Name: eutils.CloudAuthConfig, Namespace: common.OperatorNamespace()},
			})).NotTo(HaveOccurred())

			// Waiting, not erroring - the ConfigMap is written out of band and we watch for it.
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
			Expect(esClient.created).To(BeEmpty())
		})
	})
})
