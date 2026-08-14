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

package esutils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/olivere/elastic/v7"
	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/tls"
)

const (
	baseURI   = "http://127.0.0.1:9200"
	indexName = "tigera_secure_ee_test_index"
)

var (
	newPolicies      bool
	updateToReadonly bool
	_                = Describe("Elasticsearch tests", func() {
		Context("Create elasticsearch client", func() {
			var (
				c      client.Client
				ctx    context.Context
				scheme *runtime.Scheme
			)

			BeforeEach(func() {
				// Create a Kubernetes client.
				scheme = runtime.NewScheme()
				err := apis.AddToScheme(scheme, false)
				Expect(err).NotTo(HaveOccurred())

				Expect(v1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
				Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
				Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

				c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
				ctx = context.Background()

				Expect(c.Create(ctx, &operatorv1.Installation{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
				})).ShouldNot(HaveOccurred())
			})

			It("creates an client for internal elastic", func() {
				Expect(c.Create(ctx, &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: common.OperatorNamespace(), Name: render.ElasticsearchAdminUserSecret},
					Data:       map[string][]byte{"elastic": []byte("anyPass")},
				})).ShouldNot(HaveOccurred())

				esInternalCert, err := secret.CreateTLSSecret(
					nil,
					render.TigeraElasticsearchInternalCertSecret,
					common.OperatorNamespace(),
					"tls.key",
					"tls.crt",
					tls.DefaultCertificateDuration,
					nil,
				)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(c.Create(ctx, esInternalCert)).ShouldNot(HaveOccurred())

				mockServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					writer.WriteHeader(http.StatusOK)
				}))
				defer mockServer.Close()

				_, err = NewElasticClient(c, ctx, mockServer.URL, false)
				Expect(err).NotTo(HaveOccurred())
			})

			It("creates an client for external elastic", func() {
				Expect(c.Create(ctx, &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: common.OperatorNamespace(), Name: render.ElasticsearchAdminUserSecret},
					Data:       map[string][]byte{"tigera-mgmt": []byte("anyPass")},
				})).ShouldNot(HaveOccurred())

				esExternalCert, err := secret.CreateTLSSecret(
					nil,
					logstorage.ExternalESPublicCertName,
					common.OperatorNamespace(),
					"tls.key",
					"tls.crt",
					tls.DefaultCertificateDuration,
					nil,
					"elastic.tigera.io",
				)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(c.Create(ctx, esExternalCert)).ShouldNot(HaveOccurred())

				clientCert, err := secret.CreateTLSSecret(
					nil,
					logstorage.ExternalCertsSecret,
					common.OperatorNamespace(),
					"client.key",
					"client.crt",
					tls.DefaultCertificateDuration,
					nil,
				)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(c.Create(ctx, clientCert)).ShouldNot(HaveOccurred())

				mockServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					writer.WriteHeader(http.StatusOK)
				}))
				defer mockServer.Close()

				_, err = NewElasticClient(c, ctx, mockServer.URL, true)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("ILM", func() {
			var (
				eClient     *esClient
				ctx         context.Context
				rolloverMax = resource.MustParse(fmt.Sprintf("%dGi", DefaultMaxIndexSizeGi))
				trt         *testRoundTripper
			)
			BeforeEach(func() {
				trt = &testRoundTripper{}
				client := &http.Client{
					Transport: http.RoundTripper(trt),
				}
				eClient = mockElasticClient(client, baseURI)
				ctx = context.Background()
			})

			It("max rollover size should be set if ES disk is large", func() {
				Expect(nil).Should(BeNil())
				defaultStorage := resource.MustParse(fmt.Sprintf("%dGi", 800))
				expectedRolloverSize := rolloverMax.Value()

				totalEsStorage := defaultStorage.Value()
				// using flow logs disk allocation value
				diskPercentage := 0.7
				diskForLogType := 0.9

				rolloverSize := calculateRolloverSize(totalEsStorage, diskPercentage, diskForLogType)
				Expect(rolloverSize).To(Equal(fmt.Sprintf("%db", expectedRolloverSize)))
			})
			It("rollover age", func() {
				By("for retention period lesser than retention factor")
				Expect("1d").To(Equal(calculateRolloverAge(2)))

				By("for retention period 0")
				Expect("1h").To(Equal(calculateRolloverAge(0)))
			})
			It("apply new lifecycle policy", func() {
				newPolicies = true
				totalDiskSize := resource.MustParse("100Gi")
				pd := buildILMPolicy(totalDiskSize.Value(), 0.7, .9, 10, true)

				err := eClient.createOrUpdatePolicies(ctx, map[string]policyDetail{
					indexName: pd,
				})
				Expect(err).To(BeNil())
			})
			It("update existing lifecycle policy", func() {
				newPolicies = false
				totalDiskSize := resource.MustParse("100Gi")
				pd := buildILMPolicy(totalDiskSize.Value(), 0.7, .9, 5, false)
				err := eClient.createOrUpdatePolicies(ctx, map[string]policyDetail{
					indexName: pd,
				})
				Expect(err).To(BeNil())
				Expect(trt.hasUpdatedPolicy).To(BeTrue())

				// Applying the same policy has no effect (since there is no change)
				trt.hasUpdatedPolicy = false
				trt.getPolicyOverride = "test_files/02_get_policy.json"
				pd = buildILMPolicy(totalDiskSize.Value(), 0.7, .9, 5, false)
				err = eClient.createOrUpdatePolicies(ctx, map[string]policyDetail{
					indexName: pd,
				})
				Expect(err).To(BeNil())
				Expect(trt.hasUpdatedPolicy).To(BeFalse())

				// Applying an updated policy (warm index writable) triggers an update (since there is a change)
				updateToReadonly = true
				pd = buildILMPolicy(totalDiskSize.Value(), 0.7, .9, 5, true)
				err = eClient.createOrUpdatePolicies(ctx, map[string]policyDetail{
					indexName: pd,
				})
				Expect(err).To(BeNil())
				Expect(trt.hasUpdatedPolicy).To(BeTrue())
			})
		})
	})
)

type testRoundTripper struct {
	e                 error
	hasUpdatedPolicy  bool
	getPolicyOverride string
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.e != nil {
		return nil, t.e
	}
	switch req.Method {
	case "HEAD":
		switch req.URL.String() {
		case baseURI:
			return &http.Response{
				StatusCode: 200,
				Request:    req,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
	case "GET":
		switch req.URL.String() {
		case baseURI + "/_ilm/policy/" + indexName + "_policy":
			if newPolicies {
				return &http.Response{
					StatusCode: 404,
					Request:    req,
				}, nil
			}
			getPolicyFile := "test_files/01_get_policy.json"
			if len(t.getPolicyOverride) > 0 {
				getPolicyFile = t.getPolicyOverride
			}
			return &http.Response{
				StatusCode: 200,
				Request:    req,
				Body:       mustOpen(getPolicyFile),
			}, nil
		}
	case "POST":
	case "PUT":
		switch req.URL.String() {
		case baseURI + "/_ilm/policy/" + indexName + "_policy":
			if newPolicies {
				actualBody, err := io.ReadAll(req.Body)
				Expect(err).To(BeNil())

				jsonFile, err := os.Open("test_files/01_put_policy.json")
				Expect(err).To(BeNil())
				defer func() { _ = jsonFile.Close() }()
				expectedBody, _ := io.ReadAll(jsonFile)
				Expect(actualBody).To(MatchJSON(expectedBody))

				return &http.Response{
					StatusCode: 200,
					Request:    req,
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
				}, nil
			}
			actualBody, err := io.ReadAll(req.Body)
			Expect(err).To(BeNil())

			jsonFile, err := os.Open("test_files/02_put_policy.json")
			if updateToReadonly {
				jsonFile, err = os.Open("test_files/02_put_policy_readonly.json")
			}
			Expect(err).To(BeNil())
			defer func() { _ = jsonFile.Close() }()
			expectedBody, _ := io.ReadAll(jsonFile)
			Expect(actualBody).To(MatchJSON(expectedBody))

			t.hasUpdatedPolicy = true
			return &http.Response{
				StatusCode: 200,
				Request:    req,
				Body:       io.NopCloser(bytes.NewBufferString("{}")),
			}, nil
		}
	}

	if os.Getenv("ELASTIC_TEST_DEBUG") == "yes" {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", req.Method, req.URL)
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()
			body := string(b)
			req.Body = io.NopCloser(bytes.NewReader(b))
			_, _ = fmt.Fprintln(os.Stderr, body)
		}
	}

	return &http.Response{
		Request:    req,
		StatusCode: 500,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func mustOpen(name string) io.ReadCloser {
	f, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	return f
}

func mockElasticClient(h *http.Client, url string) *esClient {
	options := []elastic.ClientOptionFunc{
		elastic.SetHttpClient(h),
		elastic.SetURL(url),
		elastic.SetSniff(false),
	}
	client, err := elastic.NewClient(options...)
	Expect(err).To(BeNil())

	ecl := esClient{}
	ecl.client = client
	return &ecl
}

var _ = Describe("Elasticsearch users and roles", func() {
	var (
		userPrefix = "test-es-prefix"
		clusterID  = "clusterUUID"
		tenantID   = "tenantID"
	)
	It("should generate usernames in expected format", func() {
		generatedESUsername := formatName(userPrefix, clusterID, tenantID)
		expectedESUsername := fmt.Sprintf("%s_%s_%s", userPrefix, clusterID, tenantID)
		Expect(generatedESUsername).To(Equal(expectedESUsername))
	})

	It("should generate Linseed ElasticUser with expected username and roles", func() {
		linseedUser := LinseedUser(clusterID, tenantID)
		expectedLinseedESName := fmt.Sprintf("%s_%s_%s", ElasticsearchUserNameLinseed, clusterID, tenantID)

		Expect(linseedUser.Username).To(Equal(expectedLinseedESName))
		Expect(len(linseedUser.Roles)).To(Equal(1))
		linseedRole := linseedUser.Roles[0]
		Expect(linseedRole.Name).To(Equal(expectedLinseedESName))

		expectedLinseedRoleDef := RoleDefinition{
			Cluster: []string{"monitor", "manage_index_templates", "manage_ilm"},
			Indices: []RoleIndex{
				{
					// Include both single-index and multi-index name formats.
					Names:      []string{indexPattern("tigera_secure_ee_*", "*", ".*", tenantID), "calico_*"},
					Privileges: []string{"create_index", "write", "manage", "read"},
				},
			},
		}

		Expect(*linseedRole.Definition).To(Equal(expectedLinseedRoleDef))
	})
})

var _ = Describe("Utils elasticsearch license type tests", func() {
	var (
		c      client.Client
		ctx    context.Context
		scheme *runtime.Scheme
		log    logr.Logger
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(v1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
		log = logf.Log.WithName("utils-test-logger")
	})

	It("Returns license type from elastic-licensing", func() {
		Expect(c.Create(ctx, &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: eck.OperatorNamespace, Name: eck.LicenseConfigMapName},
			Data:       map[string]string{"eck_license_level": "enterprise"},
		})).ShouldNot(HaveOccurred())
		license, err := GetElasticLicenseType(ctx, c, log)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(license).Should(Equal(render.ElasticsearchLicenseTypeEnterprise))
	})

	It("Return error if elastic-licensing not found", func() {
		license, err := GetElasticLicenseType(ctx, c, log)
		Expect(err).Should(HaveOccurred())
		Expect(license).Should(Equal(render.ElasticsearchLicenseTypeUnknown))
	})

	It("Return error if license type if missing", func() {
		Expect(c.Create(ctx, &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: eck.OperatorNamespace, Name: eck.LicenseConfigMapName},
		})).ShouldNot(HaveOccurred())
		_, err := GetElasticLicenseType(ctx, c, log)
		Expect(err).Should(HaveOccurred())
	})
})
