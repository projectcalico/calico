// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in policy recommendation with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packetcapture

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	eutils "github.com/projectcalico/calico/operator/pkg/enterprise/utils"
	"github.com/projectcalico/calico/operator/pkg/render"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"github.com/projectcalico/calico/operator/pkg/tls"
	"github.com/projectcalico/calico/operator/test"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("packet capture controller tests", func() {
	var (
		cli                   client.Client
		scheme                *runtime.Scheme
		ctx                   context.Context
		mockStatus            *status.MockStatus
		installation          *operatorv1.Installation
		certificateManagement *operatorv1.CertificateManagement
		packetCaptureSecret   *corev1.Secret
		r                     ReconcilePacketCapture
	)

	ready := &utils.ReadyFlag{}
	ready.MarkAsReady()

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Create a CertificateManagement instance for tests that need it.
		ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		Expect(err).NotTo(HaveOccurred())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		certificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		replicas := int32(2)
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Generation: 2,
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.CalicoEnterprise,
				Registry:             "some.registry.org/",
			},
		}
		installation.Status.Computed = &installation.Spec

		// Apply prerequisites for the basic reconcile to succeed.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		cryptoCA, err := tls.MakeCA("byo-ca")
		Expect(err).NotTo(HaveOccurred())
		packetCaptureSecret, err = secret.CreateTLSSecret(cryptoCA, render.PacketCaptureServerCert, common.OperatorNamespace(), "key.key", "cert.crt", time.Hour, nil, dns.GetServiceDNSNames(render.PacketCaptureServiceName, render.PacketCaptureNamespace, dns.DefaultClusterDomain)...)
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://localhost:9443",
				OIDC: &operatorv1.AuthenticationOIDC{
					IssuerURL: "https://localhost:9443/dex",
				},
			},
		})).ToNot(HaveOccurred())
		dexSecret, err := secret.CreateTLSSecret(cryptoCA, render.DexTLSSecretName, common.OperatorNamespace(), corev1.TLSPrivateKeyKey, corev1.TLSCertKey, time.Hour, nil, dns.GetServiceDNSNames(render.DexTLSSecretName, render.DexNamespace, dns.DefaultClusterDomain)...)
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, dexSecret)).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-oidc-credentials", Namespace: common.OperatorNamespace()},
			Data: map[string][]byte{
				render.ClientIDSecretField:     []byte("a"),
				render.ClientSecretSecretField: []byte("a"),
				render.RootCASecretField:       []byte(dexSecret.Data[corev1.TLSCertKey]),
			},
		})).ToNot(HaveOccurred())

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
		mockStatus.On("ClearWarning", mock.Anything).Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceReadError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceUpdateError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceCreateError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()

		r = ReconcilePacketCapture{
			client:         cli,
			scheme:         scheme,
			status:         mockStatus,
			tierWatchReady: ready,
			opts: options.ControllerOptions{
				DetectedProvider: operatorv1.ProviderNone,
				Variant:          operatorv1.CalicoEnterprise,
			},
		}

		// Apply the packetcapture CR to the fake cluster.
		Expect(cli.Create(ctx, &operatorv1.PacketCaptureAPI{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
	})

	Context("verify reconciliation", func() {
		It("should use builtin images", func() {
			installation.Spec.CertificateManagement = certificateManagement
			Expect(cli.Create(ctx, installation)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			pcDeployment := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PacketCaptureName,
					Namespace: render.PacketCaptureNamespace,
				},
			}
			Expect(test.GetResource(cli, &pcDeployment)).To(BeNil())
			Expect(pcDeployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			pcContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.Containers, render.PacketCaptureContainerName)
			Expect(pcContainer).ToNot(BeNil())
			Expect(pcContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					components.ComponentTigeraCalico.Version)))
			Expect(pcContainer.VolumeMounts).To(ConsistOf([]corev1.VolumeMount{
				{
					Name:      packetCaptureSecret.Name,
					ReadOnly:  true,
					MountPath: fmt.Sprintf("/%s", packetCaptureSecret.Name),
				},
				{
					Name:      "tigera-ca-bundle",
					ReadOnly:  true,
					MountPath: "/etc/pki/tls/certs",
				},
			}))
			csrinitContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.InitContainers, "tigera-packetcapture-server-tls-key-cert-provisioner")
			Expect(csrinitContainer).ToNot(BeNil())
			Expect(csrinitContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					components.ComponentTigeraCalico.Version)))
			pcSecret := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PacketCaptureServerCert,
					Namespace: "tigera-operator",
				},
			}
			Expect(test.GetResource(cli, &pcSecret)).To(HaveOccurred()) // Since certificate management is enabled.
			Expect(pcSecret).NotTo(BeNil())
		})
		It("should use images from imageset", func() {
			installation.Spec.CertificateManagement = certificateManagement
			Expect(cli.Create(ctx, installation)).To(BeNil())

			Expect(cli.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/calico", Digest: "sha256:calicocsrinithash"},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			pcDeployment := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PacketCaptureName,
					Namespace: render.PacketCaptureNamespace,
				},
			}
			Expect(test.GetResource(cli, &pcDeployment)).To(BeNil())
			Expect(pcDeployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			pcContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.Containers, render.PacketCaptureContainerName)
			Expect(pcContainer).ToNot(BeNil())
			Expect(pcContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					"sha256:calicocsrinithash")))
			csrinitContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.InitContainers, "tigera-packetcapture-server-tls-key-cert-provisioner")
			Expect(csrinitContainer).ToNot(BeNil())
			Expect(csrinitContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					"sha256:calicocsrinithash")))
			pcSecret := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PacketCaptureServerCert,
					Namespace: "tigera-operator",
				},
			}
			Expect(test.GetResource(cli, &pcSecret)).To(HaveOccurred()) // Since certificate management is enabled.
			Expect(pcSecret).NotTo(BeNil())
		})

		It("should not add OwnerReference to packetcapture TLS cert secrets", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())
			Expect(cli.Create(ctx, packetCaptureSecret)).ShouldNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			packetCaptureSecret2 := &corev1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: render.PacketCaptureServerCert}, packetCaptureSecret2)).ShouldNot(HaveOccurred())
			Expect(packetCaptureSecret2.GetOwnerReferences()).To(HaveLen(0))
		})

		It("should add OwnerReference packetcapture TLS cert operator managed secrets", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: render.PacketCaptureServerCert}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))
		})

		It("should render calico-system policy when tier and tier watch are ready", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(1))
			Expect(policies.Items[0].Name).To(Equal("calico-system.tigera-packetcapture"))
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
			r = ReconcilePacketCapture{
				client:         cli,
				scheme:         scheme,
				status:         mockStatus,
				tierWatchReady: readyFlag,
				opts: options.ControllerOptions{
					DetectedProvider: operatorv1.ProviderNone,
					Variant:          operatorv1.CalicoEnterprise,
				},
			}
			Expect(cli.Create(ctx, installation)).To(BeNil())
		})

		It("should wait if calico-system tier is unavailable", func() {
			test.DeleteCalicoSystemTierAndExpectWait(ctx, cli, &r, mockStatus)
		})

		It("should wait if tier watch is not ready", func() {
			r.tierWatchReady = &utils.ReadyFlag{}
			test.ExpectWaitForTierWatch(ctx, &r, mockStatus)
		})
	})

	Context("Reconcile for Condition status", func() {
		generation := int64(2)
		BeforeEach(func() {
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
		})
		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "packet-capture"},
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
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "packet-capture",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := eutils.GetPacketCaptureAPI(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(1))

			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
		})
		It("should reconcile with empty tigerastatus conditions ", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "packet-capture"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}

			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "packet-capture",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := eutils.GetPacketCaptureAPI(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(0))
		})
		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "packet-capture"},
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
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "packet-capture",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := eutils.GetPacketCaptureAPI(ctx, r.client)
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
				ObjectMeta: metav1.ObjectMeta{Name: "packet-capture"},
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
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			installation.Status.Conditions = []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionStatus(operatorv1.ConditionFalse),
					Reason:             string(operatorv1.NotApplicable),
					Message:            "Not Applicable",
					LastTransitionTime: metav1.NewTime(time.Now()),
				},
				{
					Type:               "Progressing",
					Status:             metav1.ConditionStatus(operatorv1.ConditionTrue),
					LastTransitionTime: metav1.NewTime(time.Now()),
					Reason:             string(operatorv1.ResourceNotReady),
					Message:            "All resources are not available",
				},
				{
					Type:               "Degraded",
					Status:             metav1.ConditionStatus(operatorv1.ConditionFalse),
					Reason:             string(operatorv1.NotApplicable),
					Message:            "Not Applicable",
					LastTransitionTime: metav1.NewTime(time.Now()),
				},
			}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "packet-capture",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := eutils.GetPacketCaptureAPI(ctx, r.client)
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
		Context("Management cluster reconciliation", func() {
			BeforeEach(func() {
				// Create the ManagementCluster CR needed to configure
				// a management cluster for a multi-cluster setup
				managementCluster := &operatorv1.ManagementCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.ManagementClusterSpec{
						TLS: &operatorv1.TLS{
							SecretName: render.VoltronTunnelSecretName,
						},
					},
				}
				Expect(cli.Create(ctx, managementCluster)).NotTo(HaveOccurred())
			})

			It("Should reconcile and not create packet capture resources for a management cluster in multi tenant mode", func() {
				r := ReconcilePacketCapture{
					client:         cli,
					scheme:         scheme,
					status:         mockStatus,
					tierWatchReady: ready,
					opts: options.ControllerOptions{
						DetectedProvider: operatorv1.ProviderNone,
						Variant:          operatorv1.CalicoEnterprise,
						MultiTenant:      true,
					},
				}

				// Reconcile the API server
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				deployment := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-packetcapture",
						Namespace: "tigera-packetcapture",
					},
				}

				// Ensure a deployment is not created for the packetcapture API
				err = test.GetResource(cli, &deployment)
				Expect(errors.IsNotFound(err)).Should(BeTrue())
			})
			It("Should reconcile and create packet capture resources for a management cluster in single tenant mode", func() {
				r := ReconcilePacketCapture{
					client:         cli,
					scheme:         scheme,
					status:         mockStatus,
					tierWatchReady: ready,
					opts: options.ControllerOptions{
						DetectedProvider: operatorv1.ProviderNone,
						Variant:          operatorv1.CalicoEnterprise,
						MultiTenant:      false,
					},
				}

				// Reconcile the API server
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				deployment := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-packetcapture",
						Namespace: "tigera-packetcapture",
					},
				}

				// Ensure a deployment was created for the packetcapture API
				err = test.GetResource(cli, &deployment)
				Expect(errors.IsNotFound(err)).Should(BeFalse())
			})
		})
	})
})
