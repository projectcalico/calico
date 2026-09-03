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

package istio

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
	"github.com/projectcalico/calico/operator/test"
)

var _ = Describe("Istio controller tests", func() {
	var (
		cli                 client.Client
		scheme              *runtime.Scheme
		ctx                 context.Context
		mockStatus          *status.MockStatus
		installation        *operatorv1.Installation
		istioCR             *operatorv1.Istio
		objTrackerWithCalls test.ObjectTrackerWithCalls
		replicas            int32
	)

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admregv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(autoscalingv2.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		// EnvoyFilter is registered via apis.AddToScheme above.

		ctx = context.Background()
		objTrackerWithCalls = test.NewObjectTrackerWithCalls(scheme)
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjectTracker(&objTrackerWithCalls).Build()

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("AddDaemonsets", mock.Anything).Maybe().Return()
		mockStatus.On("AddDeployments", mock.Anything).Maybe().Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Maybe().Return()
		mockStatus.On("AddCronJobs", mock.Anything).Maybe()
		mockStatus.On("IsAvailable").Maybe().Return(true)
		mockStatus.On("OnCRFound").Maybe().Return()
		mockStatus.On("ClearDegraded").Maybe()
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return()
		mockStatus.On("ReadyToMonitor").Maybe()
		mockStatus.On("OnCRNotFound").Maybe().Return()
		mockStatus.On("SetMetaData", mock.Anything).Maybe().Return()

		// Apply prerequisites for the basic reconcile to succeed.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.Calico,
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.Calico,
				Conditions: []metav1.Condition{
					{Type: string(operatorv1.ComponentAvailable), Status: metav1.ConditionTrue},
				},
			},
		}
		installation.Status.Computed = &installation.Spec

		istioCR = &operatorv1.Istio{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}

		replicas = 2
	})

	createResources := func() {
		// Clear any existing resourceVersion to avoid creation conflicts
		Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
	}

	Context("Reconcile tests", func() {
		It("should handle basic Istio reconciliation", func() {
			createResources()

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			// The controller should successfully handle the reconciliation
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the status methods were called appropriately
			mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
			mockStatus.AssertCalled(GinkgoT(), "SetMetaData", mock.Anything)
		})

		It("should handle missing Installation resource", func() {
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())
			// Verify OnCRFound was called since we have an Istio resource
			mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
		})

		It("should handle missing Istio resource", func() {
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())
			// Verify OnCRNotFound was called since we don't have an Istio resource
			mockStatus.AssertCalled(GinkgoT(), "OnCRNotFound")
		})

		Context("Istio configuration tests", func() {
			BeforeEach(func() {
				createResources()
			})

			It("should handle basic Istio spec configuration", func() {
				r := &ReconcileIstio{
					Client:   cli,
					scheme:   scheme,
					provider: operatorv1.ProviderNone,
					status:   mockStatus,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				// The controller should successfully handle the basic configuration
				Expect(err).ShouldNot(HaveOccurred())

				// Verify that we got to the point where we found both CRs
				mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
				mockStatus.AssertCalled(GinkgoT(), "SetMetaData", mock.Anything)
			})

			It("should handle Istiod deployment customization", func() {
				istioCR.Spec.IstiodDeployment = &operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								NodeSelector: map[string]string{
									"kubernetes.io/os": "linux",
								},
							},
						},
					},
				}
				Expect(cli.Update(ctx, istioCR)).NotTo(HaveOccurred())

				r := &ReconcileIstio{
					Client:   cli,
					scheme:   scheme,
					provider: operatorv1.ProviderNone,
					status:   mockStatus,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				// The controller should successfully handle the Istiod deployment customization
				Expect(err).ShouldNot(HaveOccurred())
			})

			It("should handle Istio CNI daemonset customization", func() {
				istioCR.Spec.IstioCNIDaemonset = &operatorv1.IstioCNIDaemonset{
					Spec: &operatorv1.IstioCNIDaemonsetSpec{
						Template: &operatorv1.IstioCNIDaemonsetSpecTemplate{
							Spec: &operatorv1.IstioCNIDaemonsetPodSpec{
								NodeSelector: map[string]string{
									"kubernetes.io/os": "linux",
								},
							},
						},
					},
				}
				Expect(cli.Update(ctx, istioCR)).NotTo(HaveOccurred())

				r := &ReconcileIstio{
					Client:   cli,
					scheme:   scheme,
					provider: operatorv1.ProviderNone,
					status:   mockStatus,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				// The controller should successfully handle the Istio CNI daemonset customization
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Context("Status tests", func() {
		BeforeEach(func() {
			createResources()
		})

		It("should update status when reconciliation is successful", func() {
			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
			mockStatus.AssertCalled(GinkgoT(), "ReadyToMonitor")
		})

		It("should handle reconciliation without errors", func() {
			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			// The reconciliation should be successful
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("Provider-specific tests", func() {
		DescribeTable("should handle different providers correctly",
			func(provider operatorv1.Provider) {
				createResources()

				r := &ReconcileIstio{
					Client:   cli,
					scheme:   scheme,
					provider: provider,
					status:   mockStatus,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				// The controller should handle all providers successfully
				Expect(err).ShouldNot(HaveOccurred())
			},
			Entry("None provider", operatorv1.ProviderNone),
			Entry("GKE provider", operatorv1.ProviderGKE),
			Entry("AKS provider", operatorv1.ProviderAKS),
			Entry("EKS provider", operatorv1.ProviderEKS),
			Entry("OpenShift provider", operatorv1.ProviderOpenShift),
		)
	})

	Context("Finalizer management tests", func() {
		BeforeEach(func() {
			createResources()
		})

		It("should handle deletion and remove finalizer", func() {
			// Create FelixConfiguration for cleanup test
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(cli.Create(ctx, fc)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			// First reconcile to add finalizer
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Get the Istio CR and verify finalizer was added
			updatedIstio := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, updatedIstio)).NotTo(HaveOccurred())
			Expect(updatedIstio.Finalizers).To(ContainElement(istio.IstioFinalizer))

			// Delete the Istio CR - this will set DeletionTimestamp
			Expect(cli.Delete(ctx, updatedIstio)).NotTo(HaveOccurred())

			// Reconcile again to handle deletion - this should remove the finalizer
			_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the object still exists
			Eventually(func() bool {
				finalIstio := &operatorv1.Istio{}
				err = cli.Get(ctx, types.NamespacedName{Name: "default"}, finalIstio)
				return errors.IsNotFound(err)
			}).Should(BeTrue())
		})
	})

	Context("Default value tests", func() {
		It("should set default DSCPMark to 23", func() {
			// Create Istio without DSCPMark
			istioNoDSCP := &operatorv1.Istio{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioNoDSCP)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify DSCPMark was set to 23
			updatedIstio := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, updatedIstio)).NotTo(HaveOccurred())
			Expect(updatedIstio.Spec.DSCPMark).NotTo(BeNil())
			Expect(updatedIstio.Spec.DSCPMark.ToUint8()).To(Equal(uint8(23)))

			// Verify FelixConfiguration was patched
			updatedFC := &v3.FelixConfiguration{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, updatedFC)).NotTo(HaveOccurred())
			Expect(updatedFC.Spec.IstioAmbientMode).NotTo(BeNil())
			Expect(*updatedFC.Spec.IstioAmbientMode).To(Equal(v3.IstioAmbientModeEnabled))
			Expect(updatedFC.Annotations).To(HaveKey(istio.IstioOperatorAnnotationMode))
			Expect(updatedFC.Annotations[istio.IstioOperatorAnnotationMode]).To(Equal("Enabled"))
			Expect(updatedFC.Spec.IstioDSCPMark).NotTo(BeNil())
			Expect(updatedFC.Spec.IstioDSCPMark.ToUint8()).To(Equal(uint8(23)))
			Expect(updatedFC.Annotations).To(HaveKey(istio.IstioOperatorAnnotationDSCP))
			Expect(updatedFC.Annotations[istio.IstioOperatorAnnotationDSCP]).To(Equal("23"))
		})

		It("should preserve existing DSCPMark value", func() {
			// Create Istio with custom DSCPMark
			customDSCP := numorstring.DSCPFromInt(10)
			istioCustomDSCP := &operatorv1.Istio{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: operatorv1.IstioSpec{
					DSCPMark: &customDSCP,
				},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCustomDSCP)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify DSCPMark was preserved
			updatedIstio := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, updatedIstio)).NotTo(HaveOccurred())
			Expect(updatedIstio.Spec.DSCPMark).NotTo(BeNil())
			Expect(updatedIstio.Spec.DSCPMark.ToUint8()).To(Equal(uint8(10)))

			// Verify FelixConfiguration was patched
			updatedFC := &v3.FelixConfiguration{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, updatedFC)).NotTo(HaveOccurred())
			Expect(updatedFC.Spec.IstioAmbientMode).NotTo(BeNil())
			Expect(*updatedFC.Spec.IstioAmbientMode).To(Equal(v3.IstioAmbientModeEnabled))
			Expect(updatedFC.Annotations).To(HaveKey(istio.IstioOperatorAnnotationMode))
			Expect(updatedFC.Annotations[istio.IstioOperatorAnnotationMode]).To(Equal("Enabled"))
			Expect(updatedFC.Spec.IstioDSCPMark).NotTo(BeNil())
			Expect(updatedFC.Spec.IstioDSCPMark.ToUint8()).To(Equal(uint8(10)))
			Expect(updatedFC.Annotations).To(HaveKey(istio.IstioOperatorAnnotationDSCP))
			Expect(updatedFC.Annotations[istio.IstioOperatorAnnotationDSCP]).To(Equal("10"))
		})
	})

	Context("FelixConfiguration patching tests", func() {
		BeforeEach(func() {
			createResources()
		})

		It("should detect user modification of IstioAmbientMode in FelixConfiguration", func() {
			// Create FelixConfiguration with mismatched annotation and spec
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
					Annotations: map[string]string{
						istio.IstioOperatorAnnotationMode: "Enabled",
					},
				},
				Spec: v3.FelixConfigurationSpec{
					IstioAmbientMode: ptr.To(v3.IstioAmbientMode("Disabled")),
				},
			}
			Expect(cli.Create(ctx, fc)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("felixconfig IstioAmbientMode modified by user"))
		})

		It("initializes nil Annotations when writing the DSCP mark (no nil-map panic)", func() {
			// configureIstioAmbientMode only initializes fc.Annotations when it
			// writes the mode annotation and can return without doing so, so
			// configureIstioDSCPMark must guard the nil map itself before
			// writing the DSCP annotation.
			dscp := numorstring.DSCPFromInt(23)
			instance := &operatorv1.Istio{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       operatorv1.IstioSpec{DSCPMark: &dscp},
			}
			// FelixConfiguration with nil Annotations (zero value).
			fc := &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

			r := &ReconcileIstio{}
			changed, err := r.configureIstioDSCPMark(instance, fc, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(changed).To(BeTrue())
			Expect(fc.Annotations).To(HaveKeyWithValue(istio.IstioOperatorAnnotationDSCP, "23"))
			Expect(fc.Spec.IstioDSCPMark).NotTo(BeNil())
			Expect(fc.Spec.IstioDSCPMark.ToUint8()).To(Equal(uint8(23)))
		})

		It("should detect user modification of IstioDSCPMark in FelixConfiguration", func() {
			// Create FelixConfiguration with mismatched annotation and spec
			userModifiedDSCP := numorstring.DSCPFromInt(50)
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
					Annotations: map[string]string{
						istio.IstioOperatorAnnotationDSCP: "23",
					},
				},
				Spec: v3.FelixConfigurationSpec{
					IstioDSCPMark: &userModifiedDSCP,
				},
			}
			Expect(cli.Create(ctx, fc)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("felixconfig IstioDSCPMark modified by user"))
		})

		Context("policySyncPathPrefix coordination", func() {
			// All tests in this block run with Enterprise variant: the L7
			// waypoint feature that makes Istio claim policySyncPathPrefix
			// is Enterprise-only. The parent Context's BeforeEach has
			// already created the Installation as Calico, so we re-read and
			// patch it to Enterprise here.
			BeforeEach(func() {
				inst := &operatorv1.Installation{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, inst)).NotTo(HaveOccurred())
				inst.Spec.Variant = operatorv1.CalicoEnterprise
				inst.Status.Variant = operatorv1.CalicoEnterprise
				Expect(cli.Update(ctx, inst)).NotTo(HaveOccurred())
				inst.Status.Computed = inst.Spec.DeepCopy()
				Expect(cli.Status().Update(ctx, inst)).NotTo(HaveOccurred())
			})

			It("sets policySyncPathPrefix to the operator default when no AL is present", func() {
				fc := &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
				Expect(cli.Create(ctx, fc)).NotTo(HaveOccurred())

				r := &ReconcileIstio{Client: cli, scheme: scheme, provider: operatorv1.ProviderNone, status: mockStatus}
				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				Expect(err).ShouldNot(HaveOccurred())

				patched := &v3.FelixConfiguration{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, patched)).NotTo(HaveOccurred())
				Expect(patched.Spec.PolicySyncPathPrefix).To(Equal("/var/run/nodeagent"))
			})

			It("does not stomp a customer override on policySyncPathPrefix", func() {
				fc := &v3.FelixConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec:       v3.FelixConfigurationSpec{PolicySyncPathPrefix: "/var/run/customer"},
				}
				Expect(cli.Create(ctx, fc)).NotTo(HaveOccurred())

				r := &ReconcileIstio{Client: cli, scheme: scheme, provider: operatorv1.ProviderNone, status: mockStatus}
				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				Expect(err).ShouldNot(HaveOccurred())

				patched := &v3.FelixConfiguration{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, patched)).NotTo(HaveOccurred())
				Expect(patched.Spec.PolicySyncPathPrefix).To(Equal("/var/run/customer"))
			})

			It("leaves policySyncPathPrefix set on Istio deletion when ApplicationLayer is absent", func() {
				fc := &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
				Expect(cli.Create(ctx, fc)).NotTo(HaveOccurred())

				r := &ReconcileIstio{Client: cli, scheme: scheme, provider: operatorv1.ProviderNone, status: mockStatus}
				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				Expect(err).ShouldNot(HaveOccurred())

				updated := &operatorv1.Istio{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, updated)).NotTo(HaveOccurred())
				Expect(cli.Delete(ctx, updated)).NotTo(HaveOccurred())
				_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				Expect(err).ShouldNot(HaveOccurred())

				cleaned := &v3.FelixConfiguration{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, cleaned)).NotTo(HaveOccurred())
				// Never clear a value we may not own: egressgateway and Gateway
				// API share this default and never clear it, so Istio deletion
				// preserves it rather than wiping it out from under them.
				Expect(cleaned.Spec.PolicySyncPathPrefix).To(Equal("/var/run/nodeagent"))
			})
		})

		It("should clear FelixConfiguration on deletion", func() {
			// Create empty FelixConfiguration
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(cli.Create(ctx, fc)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			// First reconcile to add finalizer and set FelixConfiguration values
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify FelixConfiguration was patched with Istio settings
			patchedFC := &v3.FelixConfiguration{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, patchedFC)).NotTo(HaveOccurred())
			Expect(patchedFC.Spec.IstioAmbientMode).NotTo(BeNil())
			Expect(*patchedFC.Spec.IstioAmbientMode).To(Equal(v3.IstioAmbientModeEnabled))
			Expect(patchedFC.Spec.IstioDSCPMark).NotTo(BeNil())
			Expect(patchedFC.Spec.IstioDSCPMark.ToUint8()).To(Equal(uint8(23)))
			Expect(patchedFC.Annotations).To(HaveKey(istio.IstioOperatorAnnotationMode))
			Expect(patchedFC.Annotations[istio.IstioOperatorAnnotationMode]).To(Equal("Enabled"))
			Expect(patchedFC.Annotations).To(HaveKey(istio.IstioOperatorAnnotationDSCP))
			Expect(patchedFC.Annotations[istio.IstioOperatorAnnotationDSCP]).To(Equal("23"))

			// Get the Istio CR and delete it
			updatedIstio := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, updatedIstio)).NotTo(HaveOccurred())

			// Delete the Istio CR - this will set DeletionTimestamp
			Expect(cli.Delete(ctx, updatedIstio)).NotTo(HaveOccurred())

			// Reconcile again to handle deletion and clear FelixConfiguration
			_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify FelixConfiguration was cleared
			clearedFC := &v3.FelixConfiguration{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, clearedFC)).NotTo(HaveOccurred())
			Expect(clearedFC.Spec.IstioAmbientMode).To(BeNil())
			Expect(clearedFC.Spec.IstioDSCPMark).To(BeNil())
			Expect(clearedFC.Annotations).NotTo(HaveKey(istio.IstioOperatorAnnotationMode))
			Expect(clearedFC.Annotations).NotTo(HaveKey(istio.IstioOperatorAnnotationDSCP))
		})
	})

	Context("Error handling tests", func() {
		It("should handle TigeraStatus update in reconciliation", func() {
			createResources()

			// Create TigeraStatus
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{
					Name: IstioName,
				},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:   operatorv1.ComponentAvailable,
							Status: operatorv1.ConditionTrue,
						},
					},
				},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: IstioName}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify Istio status conditions were updated
			updatedIstio := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, updatedIstio)).NotTo(HaveOccurred())
			Expect(updatedIstio.Status.Conditions).NotTo(BeEmpty())
		})
	})

	Context("Pull secrets tests", func() {
		It("should handle pull secrets correctly", func() {
			// Create pull secret
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-pull-secret",
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{"registry.example.com":{"auth":"dGVzdDp0ZXN0"}}}`),
				},
				Type: corev1.SecretTypeDockerConfigJson,
			}
			Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())

			installation.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "tigera-pull-secret"},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify Istiod Deployment references the pull secret
			istiodDeploy := &appsv1.Deployment{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioIstiodDeploymentName, Namespace: istio.IstioNamespace}, istiodDeploy)).NotTo(HaveOccurred())
			Expect(istiodDeploy.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "tigera-pull-secret"}))

			// Verify Istio CNI DaemonSet references the pull secret
			cniDaemonSet := &appsv1.DaemonSet{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioCNIDaemonSetName, Namespace: istio.IstioNamespace}, cniDaemonSet)).NotTo(HaveOccurred())
			Expect(cniDaemonSet.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "tigera-pull-secret"}))

			// Verify Istio Ztunnel DaemonSet references the pull secret
			ztunnelDaemonSet := &appsv1.DaemonSet{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioZTunnelDaemonSetName, Namespace: istio.IstioNamespace}, ztunnelDaemonSet)).NotTo(HaveOccurred())
			Expect(ztunnelDaemonSet.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "tigera-pull-secret"}))
		})
	})

	Context("Resource creation tests", func() {
		BeforeEach(func() {
			createResources()
		})

		It("should create expected Istio resources", func() {
			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify Istiod Deployment was created
			istiodDeploy := &appsv1.Deployment{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioIstiodDeploymentName, Namespace: istio.IstioNamespace}, istiodDeploy)).NotTo(HaveOccurred())

			// Verify Istio CNI DaemonSet was created
			cniDaemonSet := &appsv1.DaemonSet{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioCNIDaemonSetName, Namespace: istio.IstioNamespace}, cniDaemonSet)).NotTo(HaveOccurred())

			// Verify Istio Ztunnel DaemonSet was created
			ztunnelDaemonSet := &appsv1.DaemonSet{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioZTunnelDaemonSetName, Namespace: istio.IstioNamespace}, ztunnelDaemonSet)).NotTo(HaveOccurred())

			// Verify status was marked ready
			mockStatus.AssertCalled(GinkgoT(), "ClearDegraded")
		})

		It("should handle ImageSet application", func() {
			// Create ImageSet with all required Istio images
			imageSet := &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "calico-" + components.CalicoRelease,
				},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "calico/istio-pilot", Digest: "sha256:pilot123"},
						{Image: "calico/istio-install-cni", Digest: "sha256:cni123"},
						{Image: "calico/istio-ztunnel", Digest: "sha256:ztunnel123"},
						{Image: "calico/istio-proxyv2", Digest: "sha256:proxyv2123"},
					},
				},
			}
			Expect(cli.Create(ctx, imageSet)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify Istiod Deployment uses ImageSet digest
			istiodDeploy := &appsv1.Deployment{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioIstiodDeploymentName, Namespace: istio.IstioNamespace}, istiodDeploy)).NotTo(HaveOccurred())
			Expect(istiodDeploy.Spec.Template.Spec.Containers).NotTo(BeEmpty())
			// Verify the pilot container image uses the digest from ImageSet
			Expect(istiodDeploy.Spec.Template.Spec.Containers[0].Image).To(ContainSubstring("@sha256:pilot123"))

			// Verify CNI DaemonSet uses ImageSet digest
			cniDaemonSet := &appsv1.DaemonSet{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioCNIDaemonSetName, Namespace: istio.IstioNamespace}, cniDaemonSet)).NotTo(HaveOccurred())
			Expect(cniDaemonSet.Spec.Template.Spec.Containers).NotTo(BeEmpty())
			// Verify the install-cni container image uses the digest from ImageSet
			Expect(cniDaemonSet.Spec.Template.Spec.Containers[0].Image).To(ContainSubstring("@sha256:cni123"))

			// Verify Ztunnel DaemonSet uses ImageSet digest
			ztunnelDaemonSet := &appsv1.DaemonSet{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioZTunnelDaemonSetName, Namespace: istio.IstioNamespace}, ztunnelDaemonSet)).NotTo(HaveOccurred())
			Expect(ztunnelDaemonSet.Spec.Template.Spec.Containers).NotTo(BeEmpty())
			// Verify the ztunnel container image uses the digest from ImageSet
			Expect(ztunnelDaemonSet.Spec.Template.Spec.Containers[0].Image).To(ContainSubstring("@sha256:ztunnel123"))
		})

	})
})
