// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logcollector

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	rlogcollector "github.com/tigera/operator/pkg/render/logcollector"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/test"
)

var _ = Describe("LogCollector controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileLogCollector
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("RemoveDaemonsets", mock.Anything).Return()
		mockStatus.On("RemoveDeployments", mock.Anything).Return()
		mockStatus.On("AddCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
		mockStatus.On("ClearWarning", mock.Anything).Return()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileLogCollector{
			client:          c,
			scheme:          scheme,
			status:          mockStatus,
			licenseAPIReady: &utils.ReadyFlag{},
			tierWatchReady:  &utils.ReadyFlag{},
			opts: options.ControllerOptions{
				DetectedProvider: operatorv1.ProviderNone,
			},
		}

		// We start off with a 'standard' installation, with nothing special
		Expect(c.Create(
			ctx,
			&operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.InstallationSpec{
					Variant:  operatorv1.CalicoEnterprise,
					Registry: "some.registry.org/",
					ImagePullSecrets: []corev1.LocalObjectReference{{
						Name: "tigera-pull-secret",
					}},
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.CalicoEnterprise,
					Computed: &operatorv1.InstallationSpec{
						Registry: "my-reg",
						// The test is provider agnostic.
						KubernetesProvider: operatorv1.ProviderNone,
					},
				},
			})).NotTo(HaveOccurred())

		// Create resources LogCollector depends on
		Expect(c.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
		})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()}})).NotTo(HaveOccurred())
		certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.

		prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		linseedTLS, err := certificateManager.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, common.OperatorNamespace(), []string{render.LinseedServiceName})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, linseedTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Apply the logcollector CR to the fake cluster.
		Expect(c.Create(ctx, &operatorv1.LogCollector{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())

		// Mark that watches were successful.
		r.licenseAPIReady.MarkAsReady()
		r.tierWatchReady.MarkAsReady()
	})

	Context("image reconciliation", func() {
		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-fluent-bit",
					Namespace: render.LogCollectorNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			node := ds.Spec.Template.Spec.Containers[0]
			Expect(node).ToNot(BeNil())
			Expect(node.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentFluentBit.Image,
					components.ComponentFluentBit.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/fluent-bit", Digest: "sha256:fluentbithash"},
						{Image: "tigera/fluent-bit-windows", Digest: "sha256:fluentbitwindowshash"},
						{Image: "tigera/calico", Digest: "sha256:deadbeef0123456789"},
					},
				},
			})).ToNot(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "windows-node",
					Labels: map[string]string{
						"kubernetes.io/os": "windows",
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-fluent-bit",
					Namespace: render.LogCollectorNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			node := ds.Spec.Template.Spec.Containers[0]
			Expect(node).ToNot(BeNil())
			Expect(node.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentFluentBit.Image,
					"sha256:fluentbithash")))

			ds.Name = "calico-fluent-bit-windows"
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			node = ds.Spec.Template.Spec.Containers[0]
			Expect(node).ToNot(BeNil())
			Expect(node.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentFluentBitWindows.Image,
					"sha256:fluentbitwindowshash")))
		})

		It("should keep the non-cluster-host ingress rule on the fluent-bit policy when Windows nodes are present", func() {
			// The allow-calico-fluent-bit NetworkPolicy is rendered exactly once,
			// by the shared component; with Windows nodes present (both OS
			// components rendered) the policy must still carry the
			// non-cluster-host ingress rule (port 9880, voltron -> http input)
			// gated on NonClusterHost — a regression here would reintroduce the
			// per-OS render contention that used to flap this rule.
			Expect(c.Create(ctx, &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "windows-node",
					Labels: map[string]string{"kubernetes.io/os": "windows"},
				},
			})).ToNot(HaveOccurred())
			Expect(c.Create(ctx, &operatorv1.NonClusterHost{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec:       operatorv1.NonClusterHostSpec{Endpoint: "https://1.2.3.4:5678"},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policy := v3.NetworkPolicy{
				TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{Name: "calico-system.allow-calico-fluent-bit", Namespace: render.LogCollectorNamespace},
			}
			Expect(test.GetResource(c, &policy)).To(BeNil())
			// Metrics rule (2020) + non-cluster-host rule (9880). Without the fix the
			// Windows render (applied last) drops the 9880 rule, leaving only one.
			Expect(policy.Spec.Ingress).To(HaveLen(2))
		})

		It("should degrade when the syslog endpoint scheme is not tcp or udp", func() {
			lc := &operatorv1.LogCollector{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, lc)).NotTo(HaveOccurred())
			lc.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
				Syslog: &operatorv1.SyslogStoreSpec{
					Endpoint: "http://1.2.3.4:514",
					LogTypes: []operatorv1.SyslogLogType{operatorv1.SyslogLogFlows},
				},
			}
			Expect(c.Update(ctx, lc)).NotTo(HaveOccurred())
			By("Setting the license to export logs")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())

			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError,
				`Syslog config has invalid Endpoint scheme "http": only tcp:// and udp:// are supported`,
				mock.Anything, mock.Anything).Return()
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError,
				`Syslog config has invalid Endpoint scheme "http": only tcp:// and udp:// are supported`,
				mock.Anything, mock.Anything)
		})

		Context("Forward to S3", func() {
			s3Vars := []corev1.EnvVar{
				{
					Name:  "AWS_ACCESS_KEY_ID",
					Value: "",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "log-collector-s3-credentials",
							},
							Key: "key-id",
						},
					},
				},
				{
					Name:  "AWS_SECRET_ACCESS_KEY",
					Value: "",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "log-collector-s3-credentials",
							},
							Key: "key-secret",
						},
					},
				},
			}

			BeforeEach(func() {
				By("Specify s3 log storage")
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec: operatorv1.LogCollectorSpec{
						AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
							S3: &operatorv1.S3StoreSpec{
								BucketName: "s3Bucket",
								Region:     "s3Region",
								BucketPath: "s3Path",
							},
						},
					},
				})).NotTo(HaveOccurred())
				By("Setting the license to export logs")
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
				By("Creating the s3 secret")
				Expect(c.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "log-collector-s3-credentials",
						Namespace: "tigera-operator",
					},
					Data: map[string][]byte{
						"key-secret": []byte("secret"),
						"key-id":     []byte("id"),
					},
				})).NotTo(HaveOccurred())
			})

			It("should forward logs to s3", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				ds := appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "calico-fluent-bit",
						Namespace: render.LogCollectorNamespace,
					},
				}
				Expect(test.GetResource(c, &ds)).To(BeNil())
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				node := ds.Spec.Template.Spec.Containers[0]
				Expect(node).ToNot(BeNil())
				Expect(node.Env).To(ContainElements(s3Vars))

				// The bucket settings live in the rendered config rather than
				// env vars.
				cm := corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: rlogcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace},
				}
				Expect(test.GetResource(c, &cm)).To(BeNil())
				conf := cm.Data["fluent-bit.yaml"]
				Expect(conf).To(ContainSubstring(`"name": "s3"`))
				Expect(conf).To(ContainSubstring(`"bucket": "s3Bucket"`))
				Expect(conf).To(ContainSubstring(`"region": "s3Region"`))
			})

			Context("Disable feature via license", func() {
				BeforeEach(func() {
					By("Deleting the previous license")
					Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
					By("Creating a new license that does not contain export logs as a feature")
					Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				})

				It("should not forward logs to s3", func() {
					mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: export-logs", mock.Anything, mock.Anything).Return()
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "calico-fluent-bit",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).Should(HaveOccurred())
				})
			})

			AfterEach(func() {
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				})).NotTo(HaveOccurred())
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
			})
		})

		Context("Forward to Splunk", func() {
			splunkVars := []corev1.EnvVar{
				{
					Name: "SPLUNK_HEC_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "logcollector-splunk-credentials",
							},
							Key: "token",
						},
					},
				},
			}

			BeforeEach(func() {
				By("Specify splunk log storage")
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec: operatorv1.LogCollectorSpec{
						AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
							Splunk: &operatorv1.SplunkStoreSpec{
								Endpoint: "https://localhost:1234",
							},
						},
					},
				})).NotTo(HaveOccurred())
				By("Setting the license to export logs")
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
				By("Creating the splunk secret")
				Expect(c.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "logcollector-splunk-credentials",
						Namespace: "tigera-operator",
					},
					Data: map[string][]byte{
						"token": []byte("token"),
					},
				})).NotTo(HaveOccurred())
			})

			It("should forward logs to splunk", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				ds := appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "calico-fluent-bit",
						Namespace: render.LogCollectorNamespace,
					},
				}
				Expect(test.GetResource(c, &ds)).To(BeNil())
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				node := ds.Spec.Template.Spec.Containers[0]
				Expect(node).ToNot(BeNil())
				Expect(node.Env).To(ContainElements(splunkVars))

				// The endpoint settings live in the rendered config rather than
				// env vars.
				cm := corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: rlogcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace},
				}
				Expect(test.GetResource(c, &cm)).To(BeNil())
				conf := cm.Data["fluent-bit.yaml"]
				Expect(conf).To(ContainSubstring(`"name": "splunk"`))
				Expect(conf).To(ContainSubstring(`"host": "localhost"`))
				Expect(conf).To(ContainSubstring(`"splunk_token": "${SPLUNK_HEC_TOKEN}"`))
			})

			It("renders a user-supplied Splunk CA into fluent-bit's bundle", func() {
				caPEM := "-----BEGIN CERTIFICATE-----\nsplunk-user-ca\n-----END CERTIFICATE-----"
				Expect(c.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: rlogcollector.SplunkCAConfigMapName, Namespace: common.OperatorNamespace()},
					Data:       map[string]string{corev1.TLSCertKey: caPEM},
				})).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				bundle := corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit-ca-bundle-system-certs", Namespace: render.LogCollectorNamespace},
				}
				Expect(test.GetResource(c, &bundle)).To(BeNil())
				Expect(bundle.Data["tigera-ca-bundle.crt"]).To(ContainSubstring(caPEM))
			})

			It("does not load the Splunk CA for a plain-http endpoint", func() {
				lc := operatorv1.LogCollector{
					TypeMeta:   metav1.TypeMeta{Kind: "LogCollector", APIVersion: "operator.tigera.io/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				}
				Expect(test.GetResource(c, &lc)).To(BeNil())
				lc.Spec.AdditionalStores.Splunk.Endpoint = "http://localhost:1234"
				Expect(c.Update(ctx, &lc)).NotTo(HaveOccurred())
				caPEM := "-----BEGIN CERTIFICATE-----\nsplunk-user-ca\n-----END CERTIFICATE-----"
				Expect(c.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: rlogcollector.SplunkCAConfigMapName, Namespace: common.OperatorNamespace()},
					Data:       map[string]string{corev1.TLSCertKey: caPEM},
				})).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				bundle := corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit-ca-bundle-system-certs", Namespace: render.LogCollectorNamespace},
				}
				Expect(test.GetResource(c, &bundle)).To(BeNil())
				Expect(bundle.Data["tigera-ca-bundle.crt"]).NotTo(ContainSubstring(caPEM))
			})

			Context("Disable feature via license", func() {
				BeforeEach(func() {
					By("Deleting the previous license")
					Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
					By("Creating a new license that does not contain export logs as a feature")
					Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				})

				It("should not forward logs to splunk", func() {
					mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: export-logs", mock.Anything, mock.Anything).Return()

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "calico-fluent-bit",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).Should(HaveOccurred())
				})
			})

			AfterEach(func() {
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				})).NotTo(HaveOccurred())
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
			})
		})

		Context("Forward to Syslog", func() {
			BeforeEach(func() {
				By("Specify splunk log storage")
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec: operatorv1.LogCollectorSpec{
						AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
							Syslog: &operatorv1.SyslogStoreSpec{
								Endpoint:   "tcp://localhost:1234",
								PacketSize: new(int32),
								LogTypes: []operatorv1.SyslogLogType{
									operatorv1.SyslogLogAudit,
									operatorv1.SyslogLogDNS,
									operatorv1.SyslogLogFlows,
									operatorv1.SyslogLogL7,
									operatorv1.SyslogLogIDSEvents,
								},
							},
						},
					},
				})).NotTo(HaveOccurred())
				By("Setting the license to export logs")
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
			})

			It("should forward logs to syslog", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				ds := appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "calico-fluent-bit",
						Namespace: render.LogCollectorNamespace,
					},
				}
				Expect(test.GetResource(c, &ds)).To(BeNil())
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))

				// Syslog forwarding is fully config-driven (no env contract).
				cm := corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: rlogcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace},
				}
				Expect(test.GetResource(c, &cm)).To(BeNil())
				conf := cm.Data["fluent-bit.yaml"]
				Expect(conf).To(ContainSubstring(`"name": "syslog"`))
				Expect(conf).To(ContainSubstring(`"host": "localhost"`))
				Expect(conf).To(ContainSubstring(`"mode": "tcp"`))
				// The whole record ships as one JSON MSG via the lua packer.
				Expect(conf).To(ContainSubstring(`"call": "syslog_pack"`))
			})

			It("renders the syslog user CA into fluent-bit's own bundle, not the shared tigera-ca-bundle", func() {
				By("Switching the syslog store to TLS with a user-supplied CA")
				lc := operatorv1.LogCollector{
					TypeMeta:   metav1.TypeMeta{Kind: "LogCollector", APIVersion: "operator.tigera.io/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				}
				Expect(test.GetResource(c, &lc)).To(BeNil())
				lc.Spec.AdditionalStores.Syslog.Encryption = operatorv1.EncryptionTLS
				Expect(c.Update(ctx, &lc)).NotTo(HaveOccurred())
				caPEM := "-----BEGIN CERTIFICATE-----\nsyslog-user-ca\n-----END CERTIFICATE-----"
				Expect(c.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: rlogcollector.SyslogCAConfigMapName, Namespace: common.OperatorNamespace()},
					Data:       map[string]string{corev1.TLSCertKey: caPEM},
				})).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The bundle must be fluent-bit's own: the core Installation controller
				// renders calico-system's shared tigera-ca-bundle with a different
				// certificate set, so additions made there would be overwritten.
				bundle := corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-fluent-bit-ca-bundle-system-certs", Namespace: render.LogCollectorNamespace},
				}
				Expect(test.GetResource(c, &bundle)).To(BeNil())
				Expect(bundle.Data["tigera-ca-bundle.crt"]).To(ContainSubstring(caPEM))

				shared := corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: render.LogCollectorNamespace},
				}
				Expect(errors.IsNotFound(test.GetResource(c, &shared))).To(BeTrue(),
					"the logcollector controller must not render the shared tigera-ca-bundle")
			})

			Context("Disable feature via license", func() {
				BeforeEach(func() {
					By("Deleting the previous license")
					Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
					By("Creating a new license that does not contain export logs as a feature")
					Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				})

				It("should not forward logs to syslog", func() {
					mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: export-logs", mock.Anything, mock.Anything).Return()

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "calico-fluent-bit",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).Should(HaveOccurred())
				})
			})

			AfterEach(func() {
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				})).NotTo(HaveOccurred())
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
			})
		})
		Context("reconcile for Status condition update from tigerastatus", func() {
			generation := int64(2)
			It("should reconcile with one item ", func() {
				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "log-collector"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status: operatorv1.TigeraStatusStatus{
						Conditions: []operatorv1.TigeraStatusCondition{
							{
								Type:               operatorv1.ComponentAvailable,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.AllObjectsAvailable),
								Message:            "All Objects are available",
								ObservedGeneration: generation,
							},
						},
					},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "log-collector",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := GetLogCollector(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(1))
				Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
				Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
				Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
				Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
			})
			It("should reconcile with empty tigerastatus conditions", func() {
				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "log-collector"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status:     operatorv1.TigeraStatusStatus{},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "log-collector",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := GetLogCollector(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(0))
			})
			It("should reconcile with creating new status condition  with multiple conditions as true", func() {
				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "log-collector"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status: operatorv1.TigeraStatusStatus{
						Conditions: []operatorv1.TigeraStatusCondition{
							{
								Type:               operatorv1.ComponentAvailable,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.AllObjectsAvailable),
								Message:            "All Objects are available",
								ObservedGeneration: generation,
							},
							{
								Type:               operatorv1.ComponentProgressing,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.ResourceNotReady),
								Message:            "Progressing Installation.operatorv1.tigera.io",
								ObservedGeneration: generation,
							},
							{
								Type:               operatorv1.ComponentDegraded,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.ResourceUpdateError),
								Message:            "Error resolving ImageSet for components",
								ObservedGeneration: generation,
							},
						},
					},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "log-collector",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := GetLogCollector(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(3))
				Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
				Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
				Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
				Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

				Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
				Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.ResourceNotReady)))
				Expect(instance.Status.Conditions[1].Message).To(Equal("Progressing Installation.operatorv1.tigera.io"))
				Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

				Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
				Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.ResourceUpdateError)))
				Expect(instance.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
				Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
			})
			It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "log-collector"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status: operatorv1.TigeraStatusStatus{
						Conditions: []operatorv1.TigeraStatusCondition{
							{
								Type:               operatorv1.ComponentAvailable,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.AllObjectsAvailable),
								Message:            "All Objects are available",
								ObservedGeneration: generation,
							},
							{
								Type:               operatorv1.ComponentProgressing,
								Status:             operatorv1.ConditionFalse,
								Reason:             string(operatorv1.NotApplicable),
								Message:            "Not Applicable",
								ObservedGeneration: generation,
							},
							{
								Type:               operatorv1.ComponentDegraded,
								Status:             operatorv1.ConditionFalse,
								Reason:             string(operatorv1.NotApplicable),
								Message:            "Not Applicable",
								ObservedGeneration: generation,
							},
						},
					},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "log-collector",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := GetLogCollector(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(3))
				Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
				Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
				Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
				Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

				Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
				Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionFalse)))
				Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.NotApplicable)))
				Expect(instance.Status.Conditions[1].Message).To(Equal("Not Applicable"))
				Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

				Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
				Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionFalse)))
				Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.NotApplicable)))
				Expect(instance.Status.Conditions[2].Message).To(Equal("Not Applicable"))
				Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
			})
		})
	})

	Context("calico-system reconciliation", func() {
		var readyFlag *utils.ReadyFlag

		BeforeEach(func() {
			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("SetMetaData", mock.Anything).Return()

			readyFlag = &utils.ReadyFlag{}
			readyFlag.MarkAsReady()
			r = ReconcileLogCollector{
				client:          c,
				scheme:          scheme,
				status:          mockStatus,
				licenseAPIReady: readyFlag,
				tierWatchReady:  readyFlag,
				opts: options.ControllerOptions{
					DetectedProvider: operatorv1.ProviderNone,
				},
			}
		})

		It("should wait if calico-system tier is unavailable", func() {
			test.DeleteCalicoSystemTierAndExpectWait(ctx, c, &r, mockStatus)
		})

		It("should wait if tier watch is not ready", func() {
			r.tierWatchReady = &utils.ReadyFlag{}
			test.ExpectWaitForTierWatch(ctx, &r, mockStatus)
		})
	})

	Context("user filters validation", func() {
		It("should warn (not degrade) on unparseable filter content and clear the warning once fixed", func() {
			filtersCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rlogcollector.FluentBitFilterConfigMapName,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string]string{
					// A leftover fluentd-syntax filter: not a fluent-bit YAML list.
					"flow": "<filter flows>\n  @type grep\n</filter>",
					// A valid fluent-bit YAML filter list.
					"dns": "- name: grep\n  exclude: qname noisy.example.com",
				},
			}
			Expect(c.Create(ctx, filtersCM)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			mockStatus.AssertCalled(GinkgoT(), "SetWarning", "fluent-bit-filter-flow", mock.Anything)
			mockStatus.AssertNotCalled(GinkgoT(), "SetWarning", "fluent-bit-filter-dns", mock.Anything)
			mockStatus.AssertCalled(GinkgoT(), "ClearWarning", "fluent-bit-filter-dns")

			// Rendering continued: the valid dns filter is inlined into the
			// config while the invalid flow filter is skipped.
			cm := corev1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: rlogcollector.FluentBitConfConfigMapName, Namespace: render.LogCollectorNamespace},
			}
			Expect(test.GetResource(c, &cm)).To(BeNil())
			Expect(cm.Data["fluent-bit.yaml"]).To(ContainSubstring("noisy.example.com"))
			Expect(cm.Data["fluent-bit.yaml"]).NotTo(ContainSubstring("<filter"))

			// Rewriting the filter as fluent-bit YAML clears the warning.
			filtersCM.Data["flow"] = "- name: grep\n  exclude: action allow"
			Expect(c.Update(ctx, filtersCM)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "ClearWarning", "fluent-bit-filter-flow")
		})
	})

	Context("should test fillDefaults for logCollector", func() {
		It("should set default values for CollectProcessPath, syslog types", func() {
			logCollector := operatorv1.LogCollector{Spec: operatorv1.LogCollectorSpec{AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
				Syslog: &operatorv1.SyslogStoreSpec{},
			}}}
			modifiedFields := fillDefaults(&logCollector)
			expectedFields := []string{"CollectProcessPath", "AdditionalStores.Syslog.LogTypes", "AdditionalStores.Syslog.Encryption"}
			expectedLogTypes := []operatorv1.SyslogLogType{
				operatorv1.SyslogLogAudit,
				operatorv1.SyslogLogDNS,
				operatorv1.SyslogLogFlows,
			}

			Expect(len(modifiedFields)).To(Equal(3))
			Expect(modifiedFields).To(ConsistOf(expectedFields))
			Expect(*logCollector.Spec.CollectProcessPath).To(Equal(operatorv1.CollectProcessPathEnable))
			Expect(logCollector.Spec.AdditionalStores.Syslog.LogTypes).To(Equal(expectedLogTypes))
		})
		It("CollectProcessPath,syslog types should not be changed if set already", func() {
			logCollector := operatorv1.LogCollector{Spec: operatorv1.LogCollectorSpec{AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
				Syslog: &operatorv1.SyslogStoreSpec{},
			}}}

			processPath := operatorv1.CollectProcessPathDisable
			logCollector.Spec.CollectProcessPath = &processPath
			logCollector.Spec.AdditionalStores.Syslog.LogTypes = []operatorv1.SyslogLogType{operatorv1.SyslogLogAudit}
			logCollector.Spec.AdditionalStores.Syslog.Encryption = operatorv1.EncryptionNone
			modifiedFields := fillDefaults(&logCollector)
			Expect(*logCollector.Spec.CollectProcessPath).To(Equal(operatorv1.CollectProcessPathDisable))
			expectedLogTypes := []operatorv1.SyslogLogType{
				operatorv1.SyslogLogAudit,
			}
			Expect(len(modifiedFields)).To(Equal(0))
			Expect(logCollector.Spec.AdditionalStores.Syslog.LogTypes).To(Equal(expectedLogTypes))
		})
	})

	Context("Reconciliation", func() {
		It("create namespace, operator secrets role and pull secrets", func() {
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			// The calico-system namespace is created and owned by the core
			// Installation controller, NOT this reconciler — owning it here would
			// let `kubectl delete logcollector` garbage-collect the whole
			// namespace.
			namespace := corev1.Namespace{
				TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			}
			Expect(errors.IsNotFound(c.Get(ctx, client.ObjectKey{
				Name: render.LogCollectorNamespace,
			}, &namespace))).To(BeTrue())

			// Expect operator rolebinding to be created
			rb := rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      render.TigeraOperatorSecrets,
				Namespace: render.LogCollectorNamespace,
			}, &rb)).NotTo(HaveOccurred())
			Expect(rb.OwnerReferences).To(HaveLen(1))
			ownerRoleBinding := rb.OwnerReferences[0]
			Expect(ownerRoleBinding.Kind).To(Equal("LogCollector"))

			// Expect pull secrets to be created
			pullSecrets := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      "tigera-pull-secret",
				Namespace: render.LogCollectorNamespace,
			}, &pullSecrets)).NotTo(HaveOccurred())
			Expect(pullSecrets.OwnerReferences).To(HaveLen(1))
			pullSecret := pullSecrets.OwnerReferences[0]
			Expect(pullSecret.Kind).To(Equal("LogCollector"))
		})
	})

	Context("License expiry", func() {
		It("should set degraded status and delete fluent-bit DaemonSet when license is expired", func() {
			// First reconcile to create fluent-bit resources.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the DaemonSet exists.
			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-fluent-bit",
					Namespace: render.LogCollectorNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())

			// Replace the valid license with an expired one.
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default", CreationTimestamp: metav1.Now()},
				Status: v3.LicenseKeyStatus{
					Expiry: metav1.Time{Time: time.Now().Add(-24 * time.Hour)},
				},
			})).NotTo(HaveOccurred())

			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError,
				"License is expired - Log forwarding is stopped. Contact Tigera support or email licensing@tigera.io", mock.Anything, mock.Anything).Return()

			// Reconcile again with expired license.
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the DaemonSet has been deleted.
			ds = appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-fluent-bit",
					Namespace: render.LogCollectorNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).NotTo(BeNil())
		})

		It("should requeue when license is in the grace period", func() {
			// First reconcile to create fluent-bit resources.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Replace the valid license with one that expired 1 day ago but has a 90-day grace period.
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default", CreationTimestamp: metav1.Now()},
				Status: v3.LicenseKeyStatus{
					Expiry:      metav1.Time{Time: time.Now().Add(-24 * time.Hour)},
					GracePeriod: "90d",
					Features:    []string{"export-logs"},
				},
			})).NotTo(HaveOccurred())

			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Should requeue to re-reconcile when the grace period expires.
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
			Expect(result.RequeueAfter).To(BeNumerically("~", 89*24*time.Hour, 1*time.Hour))

			// DaemonSet should still exist during the grace period.
			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-fluent-bit",
					Namespace: render.LogCollectorNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
		})
	})
})

var _ = Describe("LogCollector controller watches", func() {
	It("watches the rendered fluent-bit workloads so they are restored if deleted", func() {
		m := &mockController{}
		Expect(add(nil, m)).ShouldNot(HaveOccurred())

		var daemonSets, deployments []string
		for _, obj := range m.watchedObjects {
			key := obj.GetNamespace() + "/" + obj.GetName()
			switch obj.(type) {
			case *appsv1.DaemonSet:
				daemonSets = append(daemonSets, key)
			case *appsv1.Deployment:
				deployments = append(deployments, key)
			}
		}

		Expect(daemonSets).To(ContainElements(
			"calico-system/calico-fluent-bit",
			"calico-system/calico-fluent-bit-windows",
		))
		Expect(deployments).To(ContainElement("calico-system/eks-log-forwarder"))
	})
})

// mockController records the objects add() registers watches for, so tests can
// assert on the watch set without a live manager.
type mockController struct {
	mock.Mock
	watchedObjects []client.Object
}

func (m *mockController) WatchObject(object client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error {
	m.watchedObjects = append(m.watchedObjects, object)
	return nil
}

func (m *mockController) WatchObjectInCache(_ cache.Cache, object client.Object, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error {
	m.watchedObjects = append(m.watchedObjects, object)
	return nil
}

func (m *mockController) Watch(src source.Source) error {
	panic("not implemented")
}

func (m *mockController) Start(ctx context.Context) error {
	return nil
}

func (m *mockController) GetLogger() logr.Logger {
	var logger logr.Logger
	return logger
}

func (m *mockController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	return reconcile.Result{}, nil
}
