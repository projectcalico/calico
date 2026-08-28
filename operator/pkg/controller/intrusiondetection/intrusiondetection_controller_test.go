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

package intrusiondetection

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	entcertificatemanager "github.com/projectcalico/calico/operator/pkg/enterprise/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/render"
	relasticsearch "github.com/projectcalico/calico/operator/pkg/render/common/elasticsearch"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/intrusiondetection/dpi"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage/eck"
	"github.com/projectcalico/calico/operator/test"
)

var _ = Describe("IntrusionDetection controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileIntrusionDetection
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
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(esv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		// Create an object we can use throughout the tests.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDaemonsets", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
		mockStatus.On("ClearWarning", mock.Anything).Return()
		mockStatus.On("SetDegraded", operatorv1.InvalidConfigurationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceReadError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceUpdateError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, mock.AnythingOfType("string"), nil, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceReadError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()

		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		r = ReconcileIntrusionDetection{
			client:          c,
			scheme:          scheme,
			status:          mockStatus,
			licenseAPIReady: &utils.ReadyFlag{},
			dpiAPIReady:     &utils.ReadyFlag{},
			tierWatchReady:  &utils.ReadyFlag{},
			opts: options.ControllerOptions{
				DetectedProvider: operatorv1.ProviderNone,
				Variant:          operatorv1.CalicoEnterprise,
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
						Variant:  operatorv1.CalicoEnterprise,
						Registry: "some.registry.org/",
						ImagePullSecrets: []corev1.LocalObjectReference{{
							Name: "tigera-pull-secret",
						}},
						// The test is provider agnostic.
						KubernetesProvider: operatorv1.ProviderNone,
					},
				},
			})).NotTo(HaveOccurred())

		// The reconcile loop depends on a ton of objects that should be available in your client as
		// prerequisites. Without them, the controller will not even start creating objects. Let's create them now.
		Expect(c.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status:     v3.LicenseKeyStatus{Features: []string{common.ThreatDefenseFeature}},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.LogCollector{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &esv1.Elasticsearch{
			ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace},
			Status: esv1.ElasticsearchStatus{
				Phase: esv1.ElasticsearchReadyPhase,
			},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()}})).NotTo(HaveOccurred())

		certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		kiibanaTLS, err := certificateManager.GetOrCreateKeyPair(c, relasticsearch.PublicCertSecret, common.OperatorNamespace(), []string{relasticsearch.PublicCertSecret})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, kiibanaTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		linseedTLS, err := certificateManager.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, common.OperatorNamespace(), []string{render.TigeraLinseedSecret})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, linseedTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Managed clusters need the public cert for Linseed as well.
		linseedPublicCert, err := certificateManager.GetOrCreateKeyPair(c, render.VoltronLinseedPublicCert, common.OperatorNamespace(), []string{render.VoltronLinseedPublicCert})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, linseedPublicCert.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		Expect(c.Create(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
		Expect(c.Create(ctx, rtest.CreateCertSecret(render.ElasticsearchIntrusionDetectionUserSecret, common.OperatorNamespace(), render.GuardianSecretName)))
		Expect(c.Create(ctx, rtest.CreateCertSecret(render.ElasticsearchPerformanceHotspotsUserSecret, common.OperatorNamespace(), render.GuardianSecretName)))
		Expect(c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      eck.LicenseConfigMapName,
				Namespace: eck.OperatorNamespace,
			},
			Data: map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterpriseTrial)},
		})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &v3.DeepPacketInspection{ObjectMeta: metav1.ObjectMeta{Name: "test-dpi", Namespace: "test-dpi-ns"}})).ShouldNot(HaveOccurred())

		// Apply the intrusiondetection CR to the fake cluster.
		Expect(c.Create(ctx, &operatorv1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())

		// mark that the watches were successful
		r.licenseAPIReady.MarkAsReady()
		r.dpiAPIReady.MarkAsReady()
		r.tierWatchReady.MarkAsReady()
	})

	Context("image reconciliation", func() {
		BeforeEach(func() {
			Expect(c.Create(ctx, &esv1.Elasticsearch{
				ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName},
				Status: esv1.ElasticsearchStatus{
					Phase: esv1.ElasticsearchReadyPhase,
				},
			})).NotTo(HaveOccurred())
		})

		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "intrusion-detection-controller",
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(2))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "controller")
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentIntrusionDetectionController.Image,
					components.ComponentIntrusionDetectionController.Version)))

			training_pt := corev1.PodTemplate{
				TypeMeta: metav1.TypeMeta{
					Kind:       "PodTemplate",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: render.IntrusionDetectionNamespace,
					Name:      render.ADJobPodTemplateBaseName + ".training",
				},
			}
			Expect(test.GetResource(c, &training_pt)).To(HaveOccurred())

			detection_pt := corev1.PodTemplate{
				TypeMeta: metav1.TypeMeta{
					Kind:       "PodTemplate",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: render.IntrusionDetectionNamespace,
					Name:      render.ADJobPodTemplateBaseName + ".detection",
				},
			}
			Expect(test.GetResource(c, &detection_pt)).To(HaveOccurred())

			adAPI := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "anomaly-detection-api",
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &adAPI)).To(HaveOccurred())
		})

		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/deep-packet-inspection", Digest: "sha256:deeppacketinspectionhash"},
						{Image: "tigera/intrusion-detection-controller", Digest: "sha256:intrusiondetectioncontrollerhash"},
						{Image: "tigera/calico", Digest: "sha256:deadbeef0123456789"},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "intrusion-detection-controller",
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(2))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "controller")
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentIntrusionDetectionController.Image,
					"sha256:intrusiondetectioncontrollerhash")))

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dpi.DeepPacketInspectionName,
					Namespace: dpi.DeepPacketInspectionNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			dpiContainer := test.GetContainer(ds.Spec.Template.Spec.Containers, dpi.DeepPacketInspectionName)
			Expect(dpiContainer).ToNot(BeNil())
			Expect(dpiContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentDeepPacketInspection.Image,
					"sha256:deeppacketinspectionhash")))
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
			r = ReconcileIntrusionDetection{
				client:          c,
				scheme:          scheme,
				status:          mockStatus,
				licenseAPIReady: readyFlag,
				dpiAPIReady:     readyFlag,
				tierWatchReady:  readyFlag,
				opts: options.ControllerOptions{
					DetectedProvider: operatorv1.ProviderNone,
					Variant:          operatorv1.CalicoEnterprise,
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

	Context("Feature intrusion detection not active", func() {
		BeforeEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ThreatDefenseFeature}}})).NotTo(HaveOccurred())
			By("Creating a new license that does not contain intrusion detection as a feature")
			Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})

		It("should not create resources", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, mock.Anything).Return()

			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "intrusion-detection-controller",
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).NotTo(BeNil())
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "controller")
			Expect(controller).To(BeNil())
		})

		AfterEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})
	})

	Context("Reconcile tests", func() {
		BeforeEach(func() {
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything).Return()
		})

		It("should Reconcile intrusion detection controller deployment ", func() {
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			namespace := corev1.Namespace{
				TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name: render.IntrusionDetectionNamespace,
			}, &namespace)).NotTo(HaveOccurred())

			tigeraCABundle := corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      "tigera-ca-bundle",
				Namespace: render.IntrusionDetectionNamespace,
			}, &tigeraCABundle)).NotTo(HaveOccurred())

			deployment := appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      render.IntrusionDetectionControllerName,
				Namespace: render.IntrusionDetectionNamespace,
			}, &deployment)).NotTo(HaveOccurred())
			Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("restricted"))
			Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

			// Expect operator rolebinding to be created
			rb := rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      render.TigeraOperatorSecrets,
				Namespace: render.IntrusionDetectionNamespace,
			}, &rb)).NotTo(HaveOccurred())
			Expect(rb.OwnerReferences).To(HaveLen(1))
			ownerRoleBinding := rb.OwnerReferences[0]
			Expect(ownerRoleBinding.Kind).To(Equal("IntrusionDetection"))

			// Expect pull secrets to be created
			pullSecrets := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      "tigera-pull-secret",
				Namespace: render.IntrusionDetectionNamespace,
			}, &pullSecrets)).NotTo(HaveOccurred())
			Expect(pullSecrets.OwnerReferences).To(HaveLen(1))
			pullSecret := pullSecrets.OwnerReferences[0]
			Expect(pullSecret.Kind).To(Equal("IntrusionDetection"))
		})

		It("should Reconcile with default values for intrusion detection resource", func() {
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			ids := operatorv1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
			Expect(test.GetResource(c, &ids)).To(BeNil())
			Expect(ids.Spec.ComponentResources).ShouldNot(BeNil())
			Expect(len(ids.Spec.ComponentResources)).Should(Equal(1))
			Expect(ids.Spec.ComponentResources[0].ComponentName).Should(Equal(operatorv1.ComponentNameDeepPacketInspection))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Requests.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPURequest)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Limits.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPULimit)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Requests.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryRequest)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Limits.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryLimit)))
		})

		It("should not overwrite resource requirements if they are already set", func() {
			By("Deleting the previous IntrusionDetection")
			Expect(c.Delete(ctx, &operatorv1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())

			memoryLimit := "5Gi"
			memoryRequest := "5Gi"
			cpuLimit := "3"
			cpuRequest := "2"

			By("Creating IntrusionDetection resource with custom resource requirements")
			Expect(c.Create(ctx, &operatorv1.IntrusionDetection{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.IntrusionDetectionSpec{
					ComponentResources: []operatorv1.IntrusionDetectionComponentResource{
						{
							ComponentName: operatorv1.ComponentNameDeepPacketInspection,
							ResourceRequirements: &corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse(memoryLimit),
									corev1.ResourceCPU:    resource.MustParse(cpuLimit),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse(memoryRequest),
									corev1.ResourceCPU:    resource.MustParse(cpuRequest),
								},
							},
						},
					},
				},
			})).
				NotTo(HaveOccurred())

			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			ids := operatorv1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
			Expect(test.GetResource(c, &ids)).To(BeNil())
			Expect(ids.Spec.ComponentResources).ShouldNot(BeNil())
			Expect(len(ids.Spec.ComponentResources)).Should(Equal(1))
			Expect(ids.Spec.ComponentResources[0].ComponentName).Should(Equal(operatorv1.ComponentNameDeepPacketInspection))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Requests.Cpu()).Should(Equal(resource.MustParse(cpuRequest)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Limits.Cpu()).Should(Equal(resource.MustParse(cpuLimit)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Requests.Memory()).Should(Equal(resource.MustParse(memoryRequest)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Limits.Memory()).Should(Equal(resource.MustParse(memoryLimit)))
		})
	})

	Context("Reconcile for Condition status", func() {
		generation := int64(2)

		It("should reconcile with creating new status condition with one item", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, "Elasticsearch secrets are not available yet, waiting until they become available - Error: secrets \"tigera-ee-installer-elasticsearch-access\" not found").Return().Maybe()
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection"},
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
				Name:      "intrusion-detection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance := &operatorv1.IntrusionDetection{}
			err = r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, instance)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(1))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
		})

		It("should reconcile with empty tigerastatus conditions ", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, "Elasticsearch secrets are not available yet, waiting until they become available - Error: secrets \"tigera-ee-installer-elasticsearch-access\" not found").Return().Maybe()
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "intrusion-detection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance := &operatorv1.IntrusionDetection{}
			err = r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, instance)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(0))
		})

		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, "Elasticsearch secrets are not available yet, waiting until they become available - Error: secrets \"tigera-ee-installer-elasticsearch-access\" not found").Return().Maybe()
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection"},
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
				Name:      "intrusion-detection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance := &operatorv1.IntrusionDetection{}
			err = r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, instance)
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
			mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, "Elasticsearch secrets are not available yet, waiting until they become available - Error: secrets \"tigera-ee-installer-elasticsearch-access\" not found").Return().Maybe()
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection"},
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
				Name:      "intrusion-detection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance := &operatorv1.IntrusionDetection{}
			err = r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, instance)
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

	Context("External ES mode", func() {
		BeforeEach(func() {
			// Delete the Elasticsearch CR. This is created for ECK only.
			Expect(c.Delete(ctx, &esv1.Elasticsearch{
				ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace},
			})).NotTo(HaveOccurred())

			// Update the reconciler to run in external ES mode for these tests.
			r.opts.ElasticExternal = true
		})

		It("should Reconcile with default values for intrusion detection resource", func() {
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			ids := operatorv1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
			Expect(test.GetResource(c, &ids)).To(BeNil())
			Expect(ids.Spec.ComponentResources).ShouldNot(BeNil())
			Expect(len(ids.Spec.ComponentResources)).Should(Equal(1))
			Expect(ids.Spec.ComponentResources[0].ComponentName).Should(Equal(operatorv1.ComponentNameDeepPacketInspection))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Requests.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPURequest)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Limits.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPULimit)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Requests.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryRequest)))
			Expect(*ids.Spec.ComponentResources[0].ResourceRequirements.Limits.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryLimit)))
		})
	})

	Context("Multi-tenant mode", func() {
		tenantANamespace := "tenantANamespace"

		BeforeEach(func() {
			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Update the reconciler to run in external ES mode for these tests.
			r.opts.ElasticExternal = true
			r.opts.MultiTenant = true

			// Create the Tenant resources for tenant-a
			tenantA := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{ID: "tenant-a"},
			}
			Expect(c.Create(ctx, tenantA)).NotTo(HaveOccurred())

			err := c.Create(ctx, &operatorv1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure", Namespace: tenantANamespace}})
			Expect(err).NotTo(HaveOccurred())

			certificateManagerTenantA, err := entcertificatemanager.Create(c, nil, "", tenantANamespace, tenantA, certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManagerTenantA.KeyPair().Secret(tenantANamespace)))
			tenantABundle, err := entcertificatemanager.CreateTenantBundleWithSystemRootCertificates(certificateManagerTenantA)
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, tenantABundle.ConfigMap(tenantANamespace))).NotTo(HaveOccurred())

			linseedTLSTenantA, err := certificateManagerTenantA.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, tenantANamespace, []string{render.TigeraLinseedSecret})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, linseedTLSTenantA.Secret(tenantANamespace))).NotTo(HaveOccurred())

			Expect(c.Delete(ctx, &v3.DeepPacketInspection{ObjectMeta: metav1.ObjectMeta{Name: "test-dpi", Namespace: "test-dpi-ns"}})).ShouldNot(HaveOccurred())
		})

		It("should Reconcile with default values for DPI", func() {
			clusterRole := rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: dpi.DeepPacketInspectionLinseedRBACName,
				},
			}
			clusterRoleBinding := rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: dpi.DeepPacketInspectionLinseedRBACName,
				},
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantANamespace}})
			Expect(err).ShouldNot(HaveOccurred())

			err = test.GetResource(c, &clusterRole)
			Expect(err).ShouldNot(HaveOccurred())

			err = test.GetResource(c, &clusterRoleBinding)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should reconcile pull secrets and role binding", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantANamespace}})
			Expect(err).ShouldNot(HaveOccurred())

			// Expect operator role binding to be created
			rb := rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      render.TigeraOperatorSecrets,
				Namespace: tenantANamespace,
			}, &rb)).NotTo(HaveOccurred())
			Expect(rb.OwnerReferences).To(HaveLen(1))
			ownerRoleBinding := rb.OwnerReferences[0]
			Expect(ownerRoleBinding.Kind).To(Equal("Tenant"))

			// Expect pull secrets to be created
			pullSecrets := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      "tigera-pull-secret",
				Namespace: tenantANamespace,
			}, &pullSecrets)).NotTo(HaveOccurred())
			Expect(pullSecrets.OwnerReferences).To(HaveLen(1))
			pullSecret := pullSecrets.OwnerReferences[0]
			Expect(pullSecret.Kind).To(Equal("Tenant"))
		})
	})
})
