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

package installation

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/stretchr/testify/mock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/tls"
	"github.com/projectcalico/calico/operator/test"
)

// createWithComputed publishes the spec as the computed config, the way the core controller
// does, then creates the Installation.
func createWithComputed(ctx context.Context, c client.Client, cr *operator.Installation) error {
	cr.Status.Computed = cr.Spec.DeepCopy()
	return c.Create(ctx, cr)
}

var _ = Describe("windows-controller installation tests", func() {
	var twentySix int32 = 26
	Context("Reconcile tests", func() {
		var c client.Client
		var ctx context.Context
		var cancel context.CancelFunc
		var r ReconcileWindows
		var scheme *runtime.Scheme
		var mockStatus *status.MockStatus

		var cr *operator.Installation

		BeforeEach(func() {
			// The schema contains all objects that should be known to the fake client when the test runs.
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(schedv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

			// Create a client that will have a crud interface of k8s objects.
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
			ctx, cancel = context.WithCancel(context.Background())

			// Create an object we can use throughout the test to do the core reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("AddCertificateSigningRequests", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create dns service which is autodetected by windows-controller
			Expect(c.Create(ctx,
				&corev1.Service{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kube-dns",
						Namespace: "kube-system",
					},
					Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.10"}},
				})).ToNot(HaveOccurred())

			// Create default FelixConfiguration with VXLANVNI set up
			vni := 4096
			Expect(c.Create(ctx,
				&v3.FelixConfiguration{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
					Spec: v3.FelixConfigurationSpec{VXLANVNI: &vni},
				})).ToNot(HaveOccurred())

			// Create default IPAMConfiguration with StrictAffinity
			Expect(c.Create(ctx,
				&v3.IPAMConfiguration{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
					Spec: v3.IPAMConfigurationSpec{StrictAffinity: true},
				})).ToNot(HaveOccurred())

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileWindows{
				ext: coreExtensions.Windows(),
				opts: options.ControllerOptions{
					DetectedProvider: operator.ProviderNone,
					Variant:          operator.Calico,
				},
				config:               nil, // there is no fake for config
				client:               c,
				scheme:               scheme,
				status:               mockStatus,
				ipamConfigWatchReady: &utils.ReadyFlag{},
			}
			r.ipamConfigWatchReady.MarkAsReady()

			ca, err := tls.MakeCA("test")
			Expect(err).NotTo(HaveOccurred())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			// We start off with a 'standard' installation, with nothing special
			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:               operator.Calico,
					Registry:              "some.registry.org/",
					CertificateManagement: &operator.CertificateManagement{CACert: cert},
					WindowsNodes:          &operator.WindowsNodeSpec{},
					ServiceCIDRs:          []string{"10.96.0.0/12"},
					// Add a VXLAN IP pool, which is supported by Calico for Windows
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{
								CIDR:          "192.168.0.0/16",
								Encapsulation: "VXLAN",
								NATOutgoing:   "Enabled",
								NodeSelector:  "all()",
								BlockSize:     &twentySix,
							},
						},
					},
				},
			}
			Expect(updateInstallationWithDefaults(ctx, r.client, cr, r.opts.DetectedProvider, r.opts.Variant)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		})
		AfterEach(func() {
			cancel()
		})
		Context("Windows daemonset tests", func() {
			var degradedMsg []string
			var degradedErr []string
			var dsWin appsv1.DaemonSet

			BeforeEach(func() {
				// Delete the default installation
				_ = c.Delete(ctx, cr)

				// Add a SetDegraded callback to mockStatus to save and verify the messages and errors
				degradedMsg = []string{}
				degradedErr = []string{}
				mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Run(func(args mock.Arguments) {
					degradedMsg = append(degradedMsg, args.Get(1).(string))
					degradedErr = append(degradedErr, args.Get(2).(string))
				})

				dsWin = appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      common.WindowsDaemonSetName,
						Namespace: common.CalicoNamespace,
					},
				}

				cr.Status = operator.InstallationStatus{
					Variant: operator.Calico,
				}
				Expect(updateInstallationWithDefaults(ctx, r.client, cr, r.opts.DetectedProvider, r.opts.Variant)).NotTo(HaveOccurred())

				// Set serviceCIDRs in the installation (required for Calico for Windows)
				cr.Spec.ServiceCIDRs = []string{"10.96.0.0/12"}

				// Create the service endpoint configmap for k8s API (required for Calico for Windows)
				endPointCM := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.K8sSvcEndpointConfigMapName,
						Namespace: common.OperatorNamespace(),
					},
					Data: map[string]string{
						"KUBERNETES_SERVICE_HOST": "1.2.3.4",
						"KUBERNETES_SERVICE_PORT": "6443",
					},
				}
				Expect(c.Create(ctx, endPointCM)).ToNot(HaveOccurred())
			})

			It("should not render the Windows daemonset when it is disabled in the installation resource", func() {
				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))
			})

			It("should not render the Windows daemonset when it is explicitly disabled in the installation resource", func() {
				disabled := operator.WindowsDataplaneDisabled
				cr.Spec.CalicoNetwork.WindowsDataplane = &disabled

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))
			})

			It("should not render the Windows daemonset when the computed config is not published", func() {
				// Create the installation resource with no status
				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns
				cr.Spec.WindowsNodes = nil
				cr.Status = operator.InstallationStatus{}
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(utils.StandardRetry))

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))
			})

			It("should not render the Windows daemonset when the computed config has no WindowsNodes", func() {
				// Create the installation resource with no WindowsNodes
				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns
				cr.Spec.WindowsNodes = nil
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err.Error()).To(Equal("Installation.Status.Computed.WindowsNodes is nil"))

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"Installation.Status.Computed.WindowsNodes is nil"}))
				Expect(degradedErr).To(ConsistOf([]string{"Installation.Status.Computed.WindowsNodes is nil"}))
			})

			It("should not render the Windows daemonset when core_controller hasn't still initialized the defaults", func() {
				// Create the installation resource with no WindowsNodes
				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// this isn't set until default runs
				// and will cause a panic during validation if we don't wait.
				cr.Spec.CNI.IPAM = nil
				cr.Status = operator.InstallationStatus{}
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(utils.StandardRetry))

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))
			})

			It("should render the Windows daemonset when configuration is complete and valid", func() {
				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should be rendered
				Expect(test.GetResource(c, &dsWin)).To(BeNil())
				Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))
			})

			It("should not render the Windows daemonset when the kubernetes-service-endpoint configmap does not exist", func() {
				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				// Delete the configmap
				endPointCM := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.K8sSvcEndpointConfigMapName,
						Namespace: common.OperatorNamespace(),
					},
				}
				Expect(c.Delete(ctx, endPointCM)).ToNot(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(Equal("configmaps \"kubernetes-services-endpoint\" not found"))

				// The calico-node-windows daemonset should be rendered, but in a degraded state
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"Error reading services endpoint configmap"}))
				Expect(degradedErr).To(ConsistOf([]string{"configmaps \"kubernetes-services-endpoint\" not found"}))
			})

			It("should not render the Windows daemonset when the kubernetes-service-endpoint configmap is incomplete", func() {
				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				// Have a configmap with no port
				endPointCM := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.K8sSvcEndpointConfigMapName,
						Namespace: common.OperatorNamespace(),
					},
					Data: map[string]string{
						"KUBERNETES_SERVICE_HOST": "1.2.3.4",
					},
				}
				Expect(c.Update(ctx, endPointCM)).ToNot(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(Equal("services endpoint configmap 'kubernetes-services-endpoint' does not have all required information for Calico Windows daemonset configuration"))

				// The calico-node-windows daemonset should be rendered, but in a degraded state
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"Invalid Installation provided"}))
				Expect(degradedErr).To(ConsistOf([]string{"services endpoint configmap 'kubernetes-services-endpoint' does not have all required information for Calico Windows daemonset configuration"}))
			})

			It("should not render the Windows daemonset when the encapsulation is VXLANCrossSubnet (not supported)", func() {
				// VXLANCrossSubnet is not supported
				cr.Spec.CalicoNetwork.IPPools[0].Encapsulation = "VXLANCrossSubnet"

				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(Equal("IPv4 IPPool encapsulation VXLANCrossSubnet is not supported by Calico for Windows"))

				// The calico-node-windows daemonset should be rendered, but in a degraded state
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"Invalid Installation provided"}))
				Expect(degradedErr).To(ConsistOf([]string{"IPv4 IPPool encapsulation VXLANCrossSubnet is not supported by Calico for Windows"}))
			})

			It("should not render the Windows daemonset when the kube-dns service cannot be found", func() {
				// Create dns service which is autodetected by windows-controller
				Expect(c.Delete(ctx,
					&corev1.Service{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "kube-dns",
							Namespace: "kube-system",
						},
					})).ToNot(HaveOccurred())

				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("services \"kube-dns\" not found"))

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"kube-dns service not found"}))
				Expect(degradedErr).To(ConsistOf([]string{"services \"kube-dns\" not found"}))
			})

			It("should not render the Windows daemonset when FelixConfiguration.Spec.VXLANVNI is nil", func() {
				// Delete existing default FelixConfig and recreate with no VXLANVNI
				Expect(c.Delete(ctx,
					&v3.FelixConfiguration{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
					})).ToNot(HaveOccurred())
				Expect(c.Create(ctx,
					&v3.FelixConfiguration{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Spec: v3.FelixConfigurationSpec{},
					})).ToNot(HaveOccurred())

				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("VXLANVNI not specified in FelixConfigurationSpec"))

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"Error reading VXLANVNI from FelixConfiguration"}))
				Expect(degradedErr).To(ConsistOf([]string{"VXLANVNI not specified in FelixConfigurationSpec"}))
			})

			It("should not render the Windows daemonset when IPAMConfiguration StrictAffinity is not true", func() {
				// Delete existing default IPAMConfiguration and recreate with StrictAffinity false
				Expect(c.Delete(ctx,
					&v3.IPAMConfiguration{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
					})).ToNot(HaveOccurred())
				Expect(c.Create(ctx,
					&v3.IPAMConfiguration{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Spec: v3.IPAMConfigurationSpec{StrictAffinity: false},
					})).ToNot(HaveOccurred())

				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("StrictAffinity is false, it must be set to 'true' in the default IPAMConfiguration when using Calico IPAM on Windows"))

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"Invalid StrictAffinity, it must be set to 'true' when using Calico IPAM on Windows"}))
				Expect(degradedErr).To(ConsistOf([]string{"StrictAffinity is false, it must be set to 'true' in the default IPAMConfiguration when using Calico IPAM on Windows"}))
			})

			It("should not render the Windows daemonset with no ServiceCIDRs", func() {
				cr.Spec.ServiceCIDRs = []string{}

				hns := operator.WindowsDataplaneHNS
				cr.Spec.CalicoNetwork.WindowsDataplane = &hns

				// Create the installation resource
				Expect(createWithComputed(ctx, c, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(Equal("installation spec.ServiceCIDRs must be provided when using Calico CNI on Windows"))

				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
			})
		})
	})
	Context("image reconciliation tests", func() {
		type testConf struct {
			EnableWindows bool
		}
		for _, testConfig := range []testConf{
			{false},
			{true},
		} {
			enableWindows := testConfig.EnableWindows
			Describe(fmt.Sprintf("enableWindows: %v", enableWindows), func() {
				var c client.Client
				var ctx context.Context
				var cancel context.CancelFunc
				var r ReconcileWindows
				var scheme *runtime.Scheme
				var mockStatus *status.MockStatus

				BeforeEach(func() {
					// The schema contains all objects that should be known to the fake client when the test runs.
					scheme = runtime.NewScheme()
					Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
					Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
					Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
					Expect(schedv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
					Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
					Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

					// Create a client that will have a crud interface of k8s objects.
					c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
					ctx, cancel = context.WithCancel(context.Background())

					// Create dns service which is autodetected by windows-controller
					Expect(c.Create(ctx,
						&corev1.Service{
							TypeMeta: metav1.TypeMeta{},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "kube-dns",
								Namespace: "kube-system",
							},
							Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.10"}},
						})).ToNot(HaveOccurred())

					// Create default FelixConfiguration with VXLANVNI set up
					vni := 4096
					Expect(c.Create(ctx,
						&v3.FelixConfiguration{
							TypeMeta: metav1.TypeMeta{},
							ObjectMeta: metav1.ObjectMeta{
								Name: "default",
							},
							Spec: v3.FelixConfigurationSpec{VXLANVNI: &vni},
						})).ToNot(HaveOccurred())

					// Create default IPAMConfiguration with StrictAffinity
					Expect(c.Create(ctx,
						&v3.IPAMConfiguration{
							TypeMeta: metav1.TypeMeta{},
							ObjectMeta: metav1.ObjectMeta{
								Name: "default",
							},
							Spec: v3.IPAMConfigurationSpec{StrictAffinity: true},
						})).ToNot(HaveOccurred())

					if enableWindows {
						// Create the k8s service endpoint configmap (required for windows)
						endPointCM := &corev1.ConfigMap{
							ObjectMeta: metav1.ObjectMeta{
								Name:      render.K8sSvcEndpointConfigMapName,
								Namespace: common.OperatorNamespace(),
							},
							Data: map[string]string{
								"KUBERNETES_SERVICE_HOST": "1.2.3.4",
								"KUBERNETES_SERVICE_PORT": "6443",
							},
						}
						Expect(c.Create(ctx, endPointCM)).ToNot(HaveOccurred())
					}

					// Create an object we can use throughout the test to do the compliance reconcile loops.
					mockStatus = &status.MockStatus{}
					mockStatus.On("AddDaemonsets", mock.Anything).Return()
					mockStatus.On("AddDeployments", mock.Anything).Return()
					mockStatus.On("AddStatefulSets", mock.Anything).Return()
					mockStatus.On("AddCronJobs", mock.Anything)
					mockStatus.On("IsAvailable").Return(true)
					mockStatus.On("OnCRFound").Return()
					mockStatus.On("ClearDegraded")
					mockStatus.On("AddCertificateSigningRequests", mock.Anything)
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
					mockStatus.On("ReadyToMonitor")
					mockStatus.On("SetMetaData", mock.Anything).Return()
					mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

					// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
					r = ReconcileWindows{
						ext: coreExtensions.Windows(),
						opts: options.ControllerOptions{
							DetectedProvider: operator.ProviderNone,
							Variant:          operator.Calico,
						},
						config:               nil, // there is no fake for config
						client:               c,
						scheme:               scheme,
						status:               mockStatus,
						ipamConfigWatchReady: &utils.ReadyFlag{},
					}
					r.ipamConfigWatchReady.MarkAsReady()

					certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
					Expect(err).NotTo(HaveOccurred())
					Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
					Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
					// We start off with a 'standard' installation, with nothing special

					// Create installation CR with defaults and WindowsDataplaneHNS
					winDp := operator.WindowsDataplaneDisabled
					if enableWindows {
						winDp = operator.WindowsDataplaneHNS
					}
					instance := &operator.Installation{
						ObjectMeta: metav1.ObjectMeta{Name: "default"},
						Spec: operator.InstallationSpec{
							Variant:               operator.Calico,
							Registry:              "some.registry.org/",
							CertificateManagement: &operator.CertificateManagement{CACert: certificateManager.KeyPair().GetCertificatePEM()},
							CalicoNetwork: &operator.CalicoNetworkSpec{
								WindowsDataplane: &winDp,
								IPPools: []operator.IPPool{
									{
										CIDR:          "192.168.0.0/16",
										Encapsulation: "VXLAN",
										NATOutgoing:   "Enabled",
										NodeSelector:  "all()",
										BlockSize:     &twentySix,
									},
								},
							},
							WindowsNodes: &operator.WindowsNodeSpec{},
							ServiceCIDRs: []string{"10.96.0.0/12"},
						},
						Status: operator.InstallationStatus{
							Variant: operator.Calico,
						},
					}
					Expect(updateInstallationWithDefaults(ctx, r.client, instance, r.opts.DetectedProvider, r.opts.Variant)).NotTo(HaveOccurred())
					Expect(createWithComputed(ctx, c, instance)).NotTo(HaveOccurred())
				})
				AfterEach(func() {
					cancel()
				})

				It("should use builtin images", func() {

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					if enableWindows {
						dsWin := appsv1.DaemonSet{
							TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      common.WindowsDaemonSetName,
								Namespace: common.CalicoNamespace,
							},
						}
						Expect(test.GetResource(c, &dsWin)).To(BeNil())
						Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
						nodeWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "node")
						Expect(nodeWin).ToNot(BeNil())
						Expect(nodeWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s%s:%s",
								components.CalicoImagePath,
								components.ComponentCalicoNodeWindows.Image,
								components.ComponentCalicoNodeWindows.Version)))
						felixWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "felix")
						Expect(felixWin).ToNot(BeNil())
						Expect(felixWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s%s:%s",
								components.CalicoImagePath,
								components.ComponentCalicoNodeWindows.Image,
								components.ComponentCalicoNodeWindows.Version)))
						confdWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "confd")
						Expect(confdWin).ToNot(BeNil())
						Expect(confdWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s%s:%s",
								components.CalicoImagePath,
								components.ComponentCalicoNodeWindows.Image,
								components.ComponentCalicoNodeWindows.Version)))
						Expect(dsWin.Spec.Template.Spec.InitContainers).To(HaveLen(2))
						cniWin := test.GetContainer(dsWin.Spec.Template.Spec.InitContainers, "install-cni")
						Expect(cniWin).ToNot(BeNil())
						Expect(cniWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s%s:%s",
								components.CalicoImagePath,
								components.ComponentCalicoCNIWindows.Image,
								components.ComponentCalicoCNIWindows.Version)))
					} else {
						dsWin := appsv1.DaemonSet{
							TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      common.WindowsDaemonSetName,
								Namespace: common.CalicoNamespace,
							},
						}
						Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
					}
				})
				It("should use images from imageset", func() {

					imageSet := &operator.ImageSet{
						ObjectMeta: metav1.ObjectMeta{Name: "calico-" + components.CalicoRelease},
						Spec: operator.ImageSetSpec{
							Images: []operator.Image{
								{Image: "calico/calico", Digest: "sha256:calicocombinedhash"},
								{Image: "calico/node", Digest: "sha256:tigeranodehash"},
							},
						},
					}
					if enableWindows {
						imageSet.Spec.Images = append(imageSet.Spec.Images, []operator.Image{
							{Image: "calico/node-windows", Digest: "sha256:tigeranodewindowshash"},
							{Image: "calico/cni-windows", Digest: "sha256:tigeracniwindowshash"},
						}...)
					}
					Expect(c.Create(ctx, imageSet)).ToNot(HaveOccurred())

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					if enableWindows {
						dsWin := appsv1.DaemonSet{
							TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      common.WindowsDaemonSetName,
								Namespace: common.CalicoNamespace,
							},
						}
						Expect(test.GetResource(c, &dsWin)).To(BeNil())
						Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
						nodeWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "node")
						Expect(nodeWin).ToNot(BeNil())
						Expect(nodeWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s%s@%s",
								components.CalicoImagePath,
								components.ComponentCalicoNodeWindows.Image,
								"sha256:tigeranodewindowshash")))
						felixWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "felix")
						Expect(felixWin).ToNot(BeNil())
						Expect(felixWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s%s@%s",
								components.CalicoImagePath,
								components.ComponentCalicoNodeWindows.Image,
								"sha256:tigeranodewindowshash")))
						confdWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "confd")
						Expect(confdWin).ToNot(BeNil())
						Expect(confdWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s%s@%s",
								components.CalicoImagePath,
								components.ComponentCalicoNodeWindows.Image,
								"sha256:tigeranodewindowshash")))
						Expect(dsWin.Spec.Template.Spec.InitContainers).To(HaveLen(2))
						cniWin := test.GetContainer(dsWin.Spec.Template.Spec.InitContainers, "install-cni")
						Expect(cniWin).ToNot(BeNil())
						Expect(cniWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s%s@%s",
								components.CalicoImagePath,
								components.ComponentCalicoCNIWindows.Image,
								"sha256:tigeracniwindowshash")))
					} else {
						dsWin := appsv1.DaemonSet{
							TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      common.WindowsDaemonSetName,
								Namespace: common.CalicoNamespace,
							},
						}
						Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
					}
				})
			})
		}
	})
})
