// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/mock"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	kfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/common/discovery"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/imports/admission"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/rbacmanagement"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"
)

var (
	//go:embed testdata/custom-node-certs.crt
	customNodeCert []byte
	//go:embed testdata/custom-node-certs-urisan.crt
	customNodeCertURISAN []byte
)

var errMismatchedError = fmt.Errorf("installation spec.kubernetesProvider 'DockerEnterprise' does not match auto-detected value 'OpenShift'")

type fakeNamespaceMigration struct{}

func (f *fakeNamespaceMigration) NeedsCoreNamespaceMigration(ctx context.Context) (bool, error) {
	return false, nil
}

func (f *fakeNamespaceMigration) Run(ctx context.Context, log logr.Logger) error {
	return nil
}

func (f *fakeNamespaceMigration) NeedCleanup() bool {
	return false
}

func (f *fakeNamespaceMigration) CleanupMigration(ctx context.Context, log logr.Logger) error {
	return nil
}

var _ = Describe("Testing core-controller installation", func() {
	var c client.Client
	var cs *kfake.Clientset
	var ctx context.Context
	var cancel context.CancelFunc
	var r ReconcileInstallation
	var cr *operator.Installation
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus

	DescribeTable("checking rendering configuration",
		func(detectedProvider, configuredProvider operator.Provider, expectedErr error) {
			configuredInstallation := &operator.Installation{}
			configuredInstallation.Spec.KubernetesProvider = configuredProvider

			err := mergeProvider(configuredInstallation, detectedProvider)
			if expectedErr == nil {
				Expect(err).To(BeNil())
				Expect(configuredInstallation.Spec.KubernetesProvider).To(Equal(detectedProvider))
			} else {
				Expect(err).To(Equal(expectedErr))
			}
		},
		Entry("Same detected/configured provider", operator.ProviderOpenShift, operator.ProviderOpenShift, nil),
		Entry("Different detected/configured provider", operator.ProviderOpenShift, operator.ProviderDockerEE, errMismatchedError),
		Entry("Same detected/configured managed provider", operator.ProviderEKS, operator.ProviderEKS, nil),
	)

	notReady := &utils.ReadyFlag{}
	ready := &utils.ReadyFlag{}
	ready.MarkAsReady()

	Context("mainline tests", func() {
		var nodeIndexInformer cache.SharedIndexInformer

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

			// Create a fake clientset for the autoscaler.
			var replicas int32 = 1
			objs := []runtime.Object{
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
					Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
				},
			}
			cs = kfake.NewClientset(objs...)

			// Create an object we can use throughout the test to do the compliance reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
			mockStatus.On("ClearWarning", mock.Anything).Return()
			mockStatus.On("AddCertificateSigningRequests", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer = cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				ext: testExtensions.Installation(),
				opts: options.ControllerOptions{
					Extensions:       testExtensions,
					DetectedProvider: operator.ProviderNone,
					Variant:          operator.CalicoEnterprise,
				},
				config:              nil, // there is no fake for config
				client:              c,
				scheme:              scheme,
				status:              mockStatus,
				typhaAutoscaler:     newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:  &fakeNamespaceMigration{},
				migrationChecked:    true,
				tierWatchReady:      ready,
				migrationWatchReady: &utils.ReadyFlag{},
				newComponentHandler: utils.NewComponentHandler,
			}

			r.typhaAutoscaler.start(ctx)
			certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())

			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())

			// We start off with a 'standard' installation, with nothing special
			Expect(c.Create(
				ctx,
				&operator.Installation{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec: operator.InstallationSpec{
						Variant:               operator.CalicoEnterprise,
						Registry:              "some.registry.org/",
						CertificateManagement: &operator.CertificateManagement{CACert: prometheusTLS.GetCertificatePEM()},
					},
					Status: operator.InstallationStatus{
						Variant: operator.CalicoEnterprise,
						Computed: &operator.InstallationSpec{
							Registry: "my-reg",
							// The test is provider agnostic.
							KubernetesProvider: operator.ProviderNone,
						},
					},
				})).NotTo(HaveOccurred())

			// In most clusters, the IP pool controller is responsible for creating IP pools. The Installation controller waits for this,
			// so we need to create those pools here.
			pool := v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: v3.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    v3.VXLANModeAlways,
				},
			}
			Expect(c.Create(ctx, &pool)).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		Context("non-cluster host tests", func() {
			nonClusterHostObjectMeta := metav1.ObjectMeta{Name: "tigera-secure"}

			BeforeEach(func() {
				By("Creating a NonClusterHost CR")
				Expect(c.Create(ctx, &operator.NonClusterHost{
					TypeMeta:   metav1.TypeMeta{Kind: "NonClusterHost", APIVersion: "operator.tigera.io/v1"},
					ObjectMeta: nonClusterHostObjectMeta,
				})).NotTo(HaveOccurred())

				r.typhaAutoscalerNonClusterHost = newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus)
				r.typhaAutoscalerNonClusterHost.start(ctx)
			})

			AfterEach(func() {
				r.typhaAutoscalerNonClusterHost = nil
				Expect(c.Delete(ctx, &operator.NonClusterHost{ObjectMeta: nonClusterHostObjectMeta})).NotTo(HaveOccurred())
			})

			It("should create a separate Typha deployment for non-cluster hosts", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).NotTo(HaveOccurred())

				deploy := appsv1.Deployment{}
				err = c.Get(ctx, types.NamespacedName{Name: "calico-typha-noncluster-host", Namespace: common.CalicoNamespace}, &deploy)
				Expect(err).ToNot(HaveOccurred())

				Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
				Expect(deploy.Spec.Template.Spec.Containers[0].Env).To(ContainElements(
					corev1.EnvVar{Name: "TYPHA_CLIENTCN", Value: "typha-client-noncluster-host"},
				))
			})

			It("should use the common name from node-certs-noncluster-host certificate", func() {
				secret := &corev1.Secret{
					TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "node-certs-noncluster-host", Namespace: common.OperatorNamespace()},
					Data: map[string][]byte{
						"tls.crt": customNodeCert,
						"tls.key": []byte("tls.key"),
					},
				}
				Expect(c.Create(ctx, secret)).NotTo(HaveOccurred())

				defer func() {
					Expect(c.Delete(ctx, secret)).NotTo(HaveOccurred())
				}()

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).NotTo(HaveOccurred())

				deploy := appsv1.Deployment{}
				err = c.Get(ctx, types.NamespacedName{Name: "calico-typha-noncluster-host", Namespace: common.CalicoNamespace}, &deploy)
				Expect(err).ToNot(HaveOccurred())

				Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
				Expect(deploy.Spec.Template.Spec.Containers[0].Env).To(ContainElements(
					corev1.EnvVar{Name: "TYPHA_CLIENTCN", Value: "custom-node-certs"},
				))
			})

			It("should use the URI SAN from node-certs-noncluster-host certificate", func() {
				secret := &corev1.Secret{
					TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "node-certs-noncluster-host", Namespace: common.OperatorNamespace()},
					Data: map[string][]byte{
						"tls.crt": customNodeCertURISAN,
						"tls.key": []byte("tls.key"),
					},
				}
				err := c.Create(ctx, secret)
				Expect(err).NotTo(HaveOccurred())

				defer func() {
					Expect(c.Delete(ctx, secret)).NotTo(HaveOccurred())
				}()

				_, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).NotTo(HaveOccurred())

				deploy := appsv1.Deployment{}
				err = c.Get(ctx, types.NamespacedName{Name: "calico-typha-noncluster-host", Namespace: common.CalicoNamespace}, &deploy)
				Expect(err).ToNot(HaveOccurred())

				Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
				Expect(deploy.Spec.Template.Spec.Containers[0].Env).To(ContainElements(
					corev1.EnvVar{Name: "TYPHA_CLIENTURISAN", Value: "spiffe://example.org/calico-node"},
				))
			})
		})

		Context("with Goldmane installed", func() {
			BeforeEach(func() {
				// Create a Goldmane CR.
				By("Creating Goldmane CR")
				goldmane := &operator.Goldmane{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
				Expect(c.Create(ctx, goldmane)).NotTo(HaveOccurred())

				// Edit the Installation, as Goldmane requires Calico.
				cr = &operator.Installation{}
				Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, cr)).NotTo(HaveOccurred())
				cr.Spec.Variant = operator.Calico
				Expect(c.Update(ctx, cr)).NotTo(HaveOccurred())

				// SetDegraded will be called.
				mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
			})

			It("should wait for the Goldmane Service to have an IP", func() {
				// First reconcile should succeed, but not create any resources.
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				ds := appsv1.DaemonSet{}
				err = c.Get(ctx, types.NamespacedName{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}, &ds)
				Expect(err).To(HaveOccurred())

				// Create the Goldmane Service.
				By("Creating Goldmane Service")
				svc := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "goldmane", Namespace: common.CalicoNamespace},
					Spec: corev1.ServiceSpec{
						ClusterIP: "1.2.3.4",
					},
				}
				Expect(c.Create(ctx, svc)).NotTo(HaveOccurred())

				// Next reconcile should create all resources.
				_, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				err = c.Get(ctx, types.NamespacedName{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}, &ds)
				Expect(err).ToNot(HaveOccurred())

				// Host alisas should be set on the DaemonSet Pod.
				Expect(ds.Spec.Template.Spec.HostAliases).To(HaveLen(1))
				Expect(ds.Spec.Template.Spec.HostAliases[0].IP).To(Equal("1.2.3.4"))
			})
		})

		It("degrades with a configuration reason when the extension rejects the configuration", func() {
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

			port := 0
			Expect(c.Create(ctx, &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{PrometheusReporterPort: &port},
			})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).To(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operator.InvalidConfigurationError, "invalid metrics port: felixConfiguration prometheusReporterPort=0 not supported", mock.Anything, mock.Anything)
		})

		Context("image tests", func() {
			It("should use builtin images", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				d := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "calico-kube-controllers",
						Namespace: common.CalicoNamespace,
					},
				}
				Expect(test.GetResource(c, &d)).To(BeNil())
				Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
				controller := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-kube-controllers")
				Expect(controller).ToNot(BeNil())
				Expect(controller.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						components.ComponentTigeraCalico.Version)))

				d = appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      common.TyphaDeploymentName,
						Namespace: common.CalicoNamespace,
					},
				}
				Expect(test.GetResource(c, &d)).To(BeNil())
				Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
				typha := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-typha")
				Expect(typha).ToNot(BeNil())
				Expect(typha.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						components.ComponentTigeraCalico.Version)))
				Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
				csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.TyphaTLSSecretName))
				Expect(csrinit).ToNot(BeNil())
				Expect(csrinit.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						components.ComponentTigeraCalico.Version)))

				ds := appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      common.NodeDaemonSetName,
						Namespace: common.CalicoNamespace,
					},
				}
				Expect(test.GetResource(c, &ds)).To(BeNil())
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				node := test.GetContainer(ds.Spec.Template.Spec.Containers, "calico-node")
				Expect(node).ToNot(BeNil())
				Expect(node.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraNode.Image,
						components.ComponentTigeraNode.Version)))
				Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(6))
				fv := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")
				Expect(fv).ToNot(BeNil())
				Expect(fv.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						components.ComponentTigeraCalico.Version)))
				cni := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				Expect(cni).ToNot(BeNil())
				Expect(cni.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						components.ComponentTigeraCalico.Version)))
				cniPlugins := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "cni-plugins")
				Expect(cniPlugins).ToNot(BeNil())
				Expect(cniPlugins.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCNIPlugins.Image,
						components.ComponentTigeraCNIPlugins.Version)))
				csrinit = test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodeTLSSecretName))
				Expect(csrinit).ToNot(BeNil())
				Expect(csrinit.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						components.ComponentTigeraCalico.Version)))
				csrinit2 := test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodePrometheusTLSServerSecret))
				Expect(csrinit2).ToNot(BeNil())
				Expect(csrinit2.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						components.ComponentTigeraCalico.Version)))
				bpfInit := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "ebpf-bootstrap")
				Expect(bpfInit).ToNot(BeNil())
				Expect(bpfInit.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraNode.Image,
						components.ComponentTigeraNode.Version)))
			})

			It("should use images from imageset", func() {
				imageSet := &operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
					Spec: operator.ImageSetSpec{
						Images: []operator.Image{
							{Image: "tigera/calico", Digest: "sha256:tigeracalicohash"},
							{Image: "tigera/node", Digest: "sha256:tigeranodehash"},
							{Image: "tigera/third-party-cni-plugins", Digest: "sha256:tigeracnipluginshash"},
						},
					},
				}
				Expect(c.Create(ctx, imageSet)).ToNot(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				d := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "calico-kube-controllers",
						Namespace: common.CalicoNamespace,
					},
				}
				Expect(test.GetResource(c, &d)).To(BeNil())
				Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
				controller := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-kube-controllers")
				Expect(controller).ToNot(BeNil())
				Expect(controller.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						"sha256:tigeracalicohash")))

				d = appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      common.TyphaDeploymentName,
						Namespace: common.CalicoNamespace,
					},
				}
				Expect(test.GetResource(c, &d)).To(BeNil())
				Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
				typha := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-typha")
				Expect(typha).ToNot(BeNil())
				Expect(typha.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						"sha256:tigeracalicohash")))
				Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
				csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.TyphaTLSSecretName))
				Expect(csrinit).ToNot(BeNil())
				Expect(csrinit.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						"sha256:tigeracalicohash")))

				ds := appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      common.NodeDaemonSetName,
						Namespace: common.CalicoNamespace,
					},
				}
				Expect(test.GetResource(c, &ds)).To(BeNil())
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				node := test.GetContainer(ds.Spec.Template.Spec.Containers, "calico-node")
				Expect(node).ToNot(BeNil())
				Expect(node.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraNode.Image,
						"sha256:tigeranodehash")))
				Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(6))
				fv := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")
				Expect(fv).ToNot(BeNil())
				Expect(fv.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						"sha256:tigeracalicohash")))
				cni := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
				Expect(cni).ToNot(BeNil())
				Expect(cni.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						"sha256:tigeracalicohash")))
				cniPlugins := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "cni-plugins")
				Expect(cniPlugins).ToNot(BeNil())
				Expect(cniPlugins.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraCNIPlugins.Image,
						"sha256:tigeracnipluginshash")))
				csrinit = test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodeTLSSecretName))
				Expect(csrinit).ToNot(BeNil())
				Expect(csrinit.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						"sha256:tigeracalicohash")))
				csrinit2 := test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodePrometheusTLSServerSecret))
				Expect(csrinit2).ToNot(BeNil())
				Expect(csrinit2.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						"sha256:tigeracalicohash")))

				bpfInit := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "ebpf-bootstrap")
				Expect(bpfInit).ToNot(BeNil())
				Expect(bpfInit.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s@%s",
						components.TigeraImagePath,
						components.ComponentTigeraNode.Image,
						"sha256:tigeranodehash")))
				inst := operator.Installation{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
				}
				Expect(test.GetResource(c, &inst)).To(BeNil())
				Expect(inst.Status.ImageSet).To(Equal("enterprise-" + components.EnterpriseRelease))
			})

			It("should error if correct variant imageset with wrong version", func() {
				mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
				imageSet := &operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{Name: "enterprise-wrong"},
				}
				Expect(c.Create(ctx, imageSet)).ToNot(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).Should(HaveOccurred())
			})
			It("should succeed if other variant imageset exists", func() {
				imageSet := &operator.ImageSet{
					ObjectMeta: metav1.ObjectMeta{Name: "calico-versiondoesntmatter"},
				}
				Expect(c.Create(ctx, imageSet)).ToNot(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				d := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "calico-kube-controllers",
						Namespace: common.CalicoNamespace,
					},
				}
				Expect(test.GetResource(c, &d)).To(BeNil())
				Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
				controller := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-kube-controllers")
				Expect(controller).ToNot(BeNil())
				Expect(controller.Image).To(Equal(
					fmt.Sprintf("some.registry.org/%s%s:%s",
						components.TigeraImagePath,
						components.ComponentTigeraCalico.Image,
						components.ComponentTigeraCalico.Version)))
			})

			It("should update version", func() {
				instance := &operator.Installation{}
				Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, instance)).NotTo(HaveOccurred())

				instance.Status.CalicoVersion = "v3.14"
				Expect(c.Update(ctx, instance)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, instance)).NotTo(HaveOccurred())
				Expect(instance.Status.CalicoVersion).To(Equal(components.EnterpriseRelease))
				Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, instance)).NotTo(HaveOccurred())

				instance.Status.CalicoVersion = "v3.23"
				instance.Spec.Variant = operator.Calico
				Expect(c.Update(ctx, instance)).NotTo(HaveOccurred())

				_, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, instance)).NotTo(HaveOccurred())
				Expect(instance.Status.CalicoVersion).To(Equal(components.CalicoRelease))
			})
		})
	})

	Context("Docker Enterprise defaults", func() {
		It("Sets the default ipv4 autodetection method to skipInterface", func() {
			installation := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderDockerEE,
				},
			}
			currentPools := v3.IPPoolList{}
			currentPools.Items = append(currentPools.Items, v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: v3.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    v3.VXLANModeAlways,
				},
			})
			Expect(MergeAndFillDefaults(installation, nil, &currentPools, operator.Calico)).To(BeNil())
			Expect(installation.Spec.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface).Should(Equal("^br-.*"))
			Expect(installation.Spec.CalicoNetwork.NodeAddressAutodetectionV6).Should(BeNil())
		})
	})

	DescribeTable("test Node Affinity defaults",
		func(expected bool, provider operator.Provider, result []corev1.NodeSelectorTerm) {
			installation := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: provider,
				},
			}
			Expect(MergeAndFillDefaults(installation, nil, nil, operator.Calico)).To(BeNil())
			if expected {
				Expect(installation.Spec.TyphaAffinity).ToNot(BeNil())
				Expect(installation.Spec.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms).Should(Equal(result))
			} else {
				Expect(installation.Spec.TyphaAffinity).To(BeNil())
			}
		},
		Entry("AKS provider sets default",
			true,
			operator.ProviderAKS,
			[]corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{
					{
						Key:      "type",
						Operator: corev1.NodeSelectorOpNotIn,
						Values:   []string{"virtual-node"},
					},
					{
						Key:      "kubernetes.azure.com/cluster",
						Operator: corev1.NodeSelectorOpExists,
					},
				},
			}},
		),
		Entry("Expect no default value for DockerEE provider",
			false,
			operator.ProviderDockerEE,
			[]corev1.NodeSelectorTerm{},
		),
	)

	Context("management cluster exists", func() {
		var expectedDNSNames []string
		var certificateManager certificatemanager.CertificateManager

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

			// Create a fake clientset for the autoscaler.
			var replicas int32 = 1
			objs := []runtime.Object{
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
					Spec: appsv1.DeploymentSpec{
						Replicas: &replicas,
					},
				},
			}
			cs = kfake.NewClientset(objs...)

			// Create an object we can use throughout the test to do the compliance reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
			mockStatus.On("ClearWarning", mock.Anything).Return()
			mockStatus.On("AddCertificateSigningRequests", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				ext: testExtensions.Installation(),
				opts: options.ControllerOptions{
					Extensions:       testExtensions,
					DetectedProvider: operator.ProviderNone,
					Variant:          operator.CalicoEnterprise,
					ClusterDomain:    dns.DefaultClusterDomain,
				},
				config:              nil, // there is no fake for config
				client:              c,
				scheme:              scheme,
				status:              mockStatus,
				typhaAutoscaler:     newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:  &fakeNamespaceMigration{},
				migrationChecked:    true,
				tierWatchReady:      ready,
				migrationWatchReady: &utils.ReadyFlag{},
				newComponentHandler: utils.NewComponentHandler,
			}
			r.typhaAutoscaler.start(ctx)

			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:  operator.CalicoEnterprise,
					Registry: "some.registry.org/",
				},
				Status: operator.InstallationStatus{
					Variant: operator.CalicoEnterprise,
					Computed: &operator.InstallationSpec{
						Registry: "my-reg",
						// The test is provider agnostic.
						KubernetesProvider: operator.ProviderNone,
					},
				},
			}
			// We start off with a 'standard' installation, with nothing special
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			// In most clusters, the IP pool controller is responsible for creating IP pools. The Installation controller waits for this,
			// so we need to create those pools here.
			pool := v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: v3.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    v3.VXLANModeAlways,
				},
			}
			Expect(c.Create(ctx, &pool)).NotTo(HaveOccurred())

			// Configure ourselves as a management cluster.
			Expect(c.Create(ctx, &operator.ManagementCluster{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}})).NotTo(HaveOccurred())

			expectedDNSNames = dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, dns.DefaultClusterDomain)
			expectedDNSNames = append(expectedDNSNames, "localhost")
			var err error
			certificateManager, err = certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		It("should create node and typha TLS cert secrets if not provided and add OwnerReference to those", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			cfgMap := &corev1.ConfigMap{}

			Expect(c.Get(ctx, client.ObjectKey{Name: "tigera-ca-bundle", Namespace: common.CalicoNamespace}, cfgMap)).ShouldNot(HaveOccurred())
			Expect(cfgMap.GetOwnerReferences()).To(HaveLen(1))

			Expect(c.Get(ctx, client.ObjectKey{Name: render.NodeTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

			Expect(c.Get(ctx, client.ObjectKey{Name: render.TyphaTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))
		})

		It("should not add OwnerReference to user supplied node and typha certs", func() {
			testCA := test.MakeTestCA("core-test")
			crtContent := &bytes.Buffer{}
			keyContent := &bytes.Buffer{}
			Expect(testCA.Config.WriteCertConfig(crtContent, keyContent)).NotTo(HaveOccurred())

			// Take CA cert and create ConfigMap
			caConfigMap := &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.TyphaCAConfigMapName,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string]string{
					render.TyphaCABundleName: crtContent.String(),
				},
			}
			Expect(c.Create(ctx, caConfigMap)).NotTo(HaveOccurred())

			nodeSecret, err := secret.CreateTLSSecret(testCA,
				render.NodeTLSSecretName, common.OperatorNamespace(), "key.key",
				"cert.crt", tls.DefaultCertificateDuration, nil, render.FelixCommonName,
			)
			nodeSecret.Data[render.CommonName] = []byte(render.FelixCommonName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, nodeSecret)).NotTo(HaveOccurred())

			typhaSecret, err := secret.CreateTLSSecret(testCA,
				render.TyphaTLSSecretName, common.OperatorNamespace(), "key.key",
				"cert.crt", tls.DefaultCertificateDuration, nil, render.TyphaCommonName,
			)
			typhaSecret.Data[render.CommonName] = []byte(render.TyphaCommonName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, typhaSecret)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(test.GetResource(c, nodeSecret)).To(BeNil())
			Expect(nodeSecret.GetOwnerReferences()).To(HaveLen(0))

			Expect(test.GetResource(c, typhaSecret)).To(BeNil())
			Expect(typhaSecret.GetOwnerReferences()).To(HaveLen(0))
		})
	})

	Context("Reconcile tests", func() {
		createNodeDaemonSet := func() {
			Expect(c.Create(
				ctx,
				&appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
					Spec: appsv1.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: render.CalicoNodeObjectName}},
							},
						},
					},
				})).NotTo(HaveOccurred())
		}

		BeforeEach(func() {
			// The schema contains all objects that should be known to the fake client when the test runs.
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(schedv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(discoveryv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

			// Create a client that will have a crud interface of k8s objects.
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
			ctx, cancel = context.WithCancel(context.Background())

			// Create a fake clientset for the autoscaler.
			var replicas int32 = 1
			objs := []runtime.Object{
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node2",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node3",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
					Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
				},
			}
			cs = kfake.NewClientset(objs...)

			// Create an object we can use throughout the test to do the core reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
			mockStatus.On("ClearWarning", mock.Anything).Return()
			mockStatus.On("AddCertificateSigningRequests", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)

			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				ext: testExtensions.Installation(),
				opts: options.ControllerOptions{
					Extensions:       testExtensions,
					DetectedProvider: operator.ProviderNone,
					Variant:          operator.CalicoEnterprise,
				},
				config:              nil, // there is no fake for config
				client:              c,
				scheme:              scheme,
				status:              mockStatus,
				typhaAutoscaler:     newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:  &fakeNamespaceMigration{},
				migrationChecked:    true,
				tierWatchReady:      ready,
				migrationWatchReady: &utils.ReadyFlag{},
				newComponentHandler: utils.NewComponentHandler,
			}

			r.typhaAutoscaler.start(ctx)
			ca, err := tls.MakeCA("test")
			Expect(err).NotTo(HaveOccurred())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block

			// In most clusters, the IP pool controller is responsible for creating IP pools. The Installation controller waits for this,
			// so we need to create those pools here.
			pool := v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: v3.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    v3.VXLANModeAlways,
				},
			}
			Expect(c.Create(ctx, &pool)).NotTo(HaveOccurred())

			// We start off with a 'standard' installation, with nothing special
			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:               operator.CalicoEnterprise,
					Registry:              "some.registry.org/",
					CertificateManagement: &operator.CertificateManagement{CACert: cert},
					ImagePullSecrets: []corev1.LocalObjectReference{{
						Name: "tigera-pull-secret",
					}},
				},
				Status: operator.InstallationStatus{},
			}
			certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
			pullSecrets := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()}}
			Expect(c.Create(ctx, pullSecrets)).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		Context("with LinuxDataplane=Nftables", func() {
			BeforeEach(func() {
				By("Setting the dataplane to nftables in the Installation")
				nft := operator.LinuxDataplaneNftables
				cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{
					LinuxDataplane: &nft,
				}
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			})

			It("should set NFTablesMode to Enabled on FelixConfiguration", func() {
				By("r.Reconcile()")
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				By("Checking that the FelixConfiguration has NFTablesMode Enabled")
				fc := &v3.FelixConfiguration{}
				err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(fc.Spec.NFTablesMode).ToNot(BeNil())
				Expect(*fc.Spec.NFTablesMode).To(Equal(v3.NFTablesModeAuto))
			})

			It("should set NFTablesMode to Disabled if nftables mode is changed", func() {
				// Reconcile. This should set NFTablesMode to true.
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// Set the dataplane to IPTables.
				err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
				Expect(err).ShouldNot(HaveOccurred())
				ipt := operator.LinuxDataplaneIptables
				cr.Spec.CalicoNetwork.LinuxDataplane = &ipt
				Expect(c.Update(ctx, cr)).NotTo(HaveOccurred())

				// Reconcile again. This should disble NFTablesMode.
				_, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				By("checking that the FelixConfiguration has NFTablesMode Disabled")
				fc := &v3.FelixConfiguration{}
				err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(fc.Spec.NFTablesMode).NotTo(BeNil())
				Expect(*fc.Spec.NFTablesMode).To(Equal(v3.NFTablesMode(v3.NFTablesModeDisabled)))
			})
		})

		Context("with LinuxDataplane=BPF and BPFNetworkBootstrap=Enabled", func() {
			createResource := func(obj client.Object) {
				Expect(c.Create(ctx, obj)).NotTo(HaveOccurred())
			}
			createK8sSvcEpConfigMap := func() {
				createResource(
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: render.K8sSvcEndpointConfigMapName, Namespace: common.OperatorNamespace()},
						Data: map[string]string{
							"KUBERNETES_SERVICE_HOST": "10.96.0.1",
							"KUBERNETES_SERVICE_PORT": "443",
						},
					})
			}
			createK8sService := func() {
				createResource(
					&corev1.Service{
						ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
						Spec: corev1.ServiceSpec{
							IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
							ClusterIP:  "1.2.3.4",
							Ports: []corev1.ServicePort{
								{Name: "https", Port: 443, TargetPort: intstr.FromInt(443)},
							},
						},
					})
			}
			createEndpointSlice := func() {
				createResource(
					&discoveryv1.EndpointSlice{
						ObjectMeta:  metav1.ObjectMeta{Name: "kubernetes-epv4", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}},
						AddressType: discoveryv1.AddressTypeIPv4,
						Endpoints: []discoveryv1.Endpoint{
							{Addresses: []string{"5.6.7.8", "5.6.7.9", "5.6.7.10"}},
						},
						Ports: []discoveryv1.EndpointPort{{Port: ptr.To(int32(6443))}},
					})
			}

			When("the LinuxDataplane is not BPF", func() {
				It("should fail if BPFNetworkBootstrap is enabled", func() {
					By("Setting the dataplane to Iptables and enabling network bootstrap")
					mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

					ipt := operator.LinuxDataplaneIptables
					enabled := operator.BPFNetworkBootstrapEnabled
					cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{
						LinuxDataplane:      &ipt,
						BPFNetworkBootstrap: &enabled,
					}
					Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

					By("Creating the other required resources")
					createK8sService()
					createEndpointSlice()

					By("r.Reconcile()")
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("bpfNetworkBootstrap is enabled but linuxDataplane is not set to BPF"))
				})
			})

			When("the LinuxDataplane is BPF", func() {
				BeforeEach(func() {
					By("Setting the dataplane to BPF and Enabling network bootstrap")
					mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

					bpf := operator.LinuxDataplaneBPF
					enabled := operator.BPFNetworkBootstrapEnabled
					cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{
						LinuxDataplane:      &bpf,
						BPFNetworkBootstrap: &enabled,
					}
					Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
				})
				DescribeTable("should fail if requirements are not met",
					func(funcs []func(), expectedErrorSubstring string) {
						for _, f := range funcs {
							f()
						}
						By("r.Reconcile()")
						_, err := r.Reconcile(ctx, reconcile.Request{})
						Expect(err).Should(HaveOccurred())
						Expect(err.Error()).To(ContainSubstring(expectedErrorSubstring))
					},
					Entry("kubernetes service endpoint is already defined",
						[]func(){createK8sSvcEpConfigMap, createK8sService, createEndpointSlice},
						"kubernetes service endpoint is defined by the kubernetes-service-endpoints ConfigMap",
					),
					Entry("kubernetes service not found",
						[]func(){createEndpointSlice}, "failed to get kubernetes service",
					),
					Entry("kubernetes endpoint slices not found",
						[]func(){createK8sService}, "failed to get kubernetes endpoint slices",
					),
				)

				It("should set NFTablesMode to Enabled on FelixConfiguration", func() {
					createK8sService()
					createEndpointSlice()

					By("r.Reconcile()")
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					By("Checking that the FelixConfiguration has NFTablesMode Enabled")
					fc := &v3.FelixConfiguration{}
					err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(fc.Spec.NFTablesMode).ToNot(BeNil())
					Expect(*fc.Spec.NFTablesMode).To(Equal(v3.NFTablesMode(v3.NFTablesModeEnabled)))
				})

				It("should push env vars to ebpf-bootstrap", func() {
					createK8sService()
					createEndpointSlice()

					By("r.Reconcile()")
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					By("Checking that the Installation has the right config")
					install := &operator.Installation{}
					err = c.Get(ctx, types.NamespacedName{Name: "default"}, install)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(install.Spec.CalicoNetwork).ToNot(BeNil())
					Expect(install.Spec.CalicoNetwork.BPFNetworkBootstrap).ToNot(BeNil())
					Expect(*install.Spec.CalicoNetwork.BPFNetworkBootstrap).To(Equal(operator.BPFNetworkBootstrapEnabled))
					Expect(install.Spec.BPFNetworkBootstrapEnabled()).To(BeTrue())

					By("Checking that the FelixConfiguration has BPF Enabled")
					fc := &v3.FelixConfiguration{}
					err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(fc.Spec.BPFEnabled).ToNot(BeNil())
					Expect(*fc.Spec.BPFEnabled).To(BeTrue())

					By("Checking ebpf-bootstrap init container has correct env vars")
					calicoNode := &appsv1.DaemonSet{}
					err = c.Get(ctx, types.NamespacedName{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}, calicoNode)
					Expect(err).ShouldNot(HaveOccurred())
					initContainer := test.GetContainer(calicoNode.Spec.Template.Spec.InitContainers, "ebpf-bootstrap")
					Expect(initContainer).NotTo(BeNil())
					Expect(initContainer.Name).To(Equal("ebpf-bootstrap"))
					Expect(initContainer.Env).To(ContainElements(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_IPS_PORTS", Value: "1.2.3.4:443"},
						corev1.EnvVar{Name: "KUBERNETES_APISERVER_ENDPOINTS", Value: "5.6.7.8:6443,5.6.7.9:6443,5.6.7.10:6443"},
					))
				})
				It("should support dual-stack clusters - IPv4 and IPv6", func() {
					Expect(c.Create(
						ctx,
						&corev1.Service{
							ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
							Spec: corev1.ServiceSpec{
								IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
								ClusterIPs: []string{"1.2.3.4", "fd00::1"},
								Ports: []corev1.ServicePort{
									{Name: "https", Port: 443, TargetPort: intstr.FromInt(443)},
								},
							},
						})).NotTo(HaveOccurred())
					Expect(c.Create(
						ctx,
						&discoveryv1.EndpointSlice{
							ObjectMeta:  metav1.ObjectMeta{Name: "kubernetes-ep1", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}},
							AddressType: discoveryv1.AddressTypeIPv4,
							Endpoints: []discoveryv1.Endpoint{
								{Addresses: []string{"5.6.7.8", "5.6.7.9", "5.6.7.10"}},
							},
							Ports: []discoveryv1.EndpointPort{{Port: ptr.To(int32(6443))}},
						})).NotTo(HaveOccurred())
					Expect(c.Create(
						ctx,
						&discoveryv1.EndpointSlice{
							ObjectMeta:  metav1.ObjectMeta{Name: "kubernetes-ep2", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}},
							AddressType: discoveryv1.AddressTypeIPv6,
							Endpoints: []discoveryv1.Endpoint{
								{Addresses: []string{"fd00::1", "fd00::2", "fd00::3"}},
							},
							Ports: []discoveryv1.EndpointPort{{Port: ptr.To(int32(6443))}},
						})).NotTo(HaveOccurred())

					By("r.Reconcile()")
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					By("Checking ebpf-bootstrap init container has correct env vars")
					calicoNode := &appsv1.DaemonSet{}
					err = c.Get(ctx, types.NamespacedName{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}, calicoNode)
					Expect(err).ShouldNot(HaveOccurred())
					initContainer := test.GetContainer(calicoNode.Spec.Template.Spec.InitContainers, "ebpf-bootstrap")
					Expect(initContainer).NotTo(BeNil())
					Expect(initContainer.Name).To(Equal("ebpf-bootstrap"))
					Expect(initContainer.Env).To(ContainElements(
						corev1.EnvVar{Name: "KUBERNETES_SERVICE_IPS_PORTS", Value: "1.2.3.4:443,[fd00::1]:443"},
						corev1.EnvVar{Name: "KUBERNETES_APISERVER_ENDPOINTS", Value: "5.6.7.8:6443,5.6.7.9:6443,5.6.7.10:6443,[fd00::1]:6443,[fd00::2]:6443,[fd00::3]:6443"},
					))
				})
			})
		})

		It("should push 'CALICO_CGROUP_PATH' env var to ebpf-bootstrap if specified in FelixConfiguration", func() {
			customPath := "/foo/bar/path"
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.FelixConfigurationSpec{
					CgroupV2Path: customPath,
				},
			}
			Expect(c.Create(ctx, fc)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			By("r.Reconcile()")
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("Checking ebpf-bootstrap init container has correct env var")
			calicoNode := &appsv1.DaemonSet{}
			err = c.Get(ctx, types.NamespacedName{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}, calicoNode)
			Expect(err).ShouldNot(HaveOccurred())
			initContainer := test.GetContainer(calicoNode.Spec.Template.Spec.InitContainers, "ebpf-bootstrap")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Name).To(Equal("ebpf-bootstrap"))
			Expect(initContainer.Env).To(ContainElements(
				corev1.EnvVar{Name: "CALICO_CGROUP_PATH", Value: customPath},
			))
		})

		// The feature is Enterprise only, so the gate is not read on Calico.
		It("should ignore the RBAC management UI feature gate for Calico", func() {
			cr.Spec.Variant = operator.Calico
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rbacmanagement.ConfigMapName,
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{rbacmanagement.ConfigMapKey: "true"},
			})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := &appsv1.Deployment{}
			Expect(c.Get(ctx, client.ObjectKey{
				Name: "calico-kube-controllers", Namespace: common.CalicoNamespace,
			}, d)).ShouldNot(HaveOccurred())
			container := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-kube-controllers")
			Expect(container).NotTo(BeNil())
			Expect(container.Env).NotTo(ContainElement(WithTransform(
				func(env corev1.EnvVar) string { return env.Value },
				ContainSubstring("rbacsync"),
			)))
		})

		It("should Reconcile with default config", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// We should get a felix configuration with the health port defaulted (but nothing else).
			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.HealthPort).NotTo(BeNil())
			Expect(*fc.Spec.HealthPort).To(Equal(9099))

			// This is only set on EKS / GKE.
			Expect(fc.Spec.RouteTableRange).To(BeNil())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("false"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeFalse())
		})

		It("should reconcile namespace, role binding and pull secrets", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			namespace := corev1.Namespace{
				TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name: common.CalicoNamespace,
			}, &namespace)).NotTo(HaveOccurred())
			Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("privileged"))
			Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

			// Expect operator role binding to be created
			rb := rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      render.TigeraOperatorSecrets,
				Namespace: common.CalicoNamespace,
			}, &rb)).NotTo(HaveOccurred())
			Expect(rb.OwnerReferences).To(HaveLen(1))
			ownerRoleBinding := rb.OwnerReferences[0]
			Expect(ownerRoleBinding.Kind).To(Equal("Installation"))

			// Expect pull secrets to be created
			pullSecrets := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      "tigera-pull-secret",
				Namespace: common.CalicoNamespace,
			}, &pullSecrets)).NotTo(HaveOccurred())
			Expect(pullSecrets.OwnerReferences).To(HaveLen(1))
			pullSecret := pullSecrets.OwnerReferences[0]
			Expect(pullSecret.Kind).To(Equal("Installation"))
		})

		It("should not patch FelixConfig and BGPConfig when ClusterRouteMode not set", func() {
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.ProgramClusterRoutes).To(BeNil())

			bgpConfig := &v3.BGPConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
			Expect(err).Should(HaveOccurred())
		})

		It("should correctly patch FelixConfig and BGPConfig with ClusterRouteMode set to BIRD", func() {
			bird := operator.ClusterRoutingModeBIRD
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{ClusterRoutingMode: &bird}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.ProgramClusterRoutes).NotTo(BeNil())
			Expect(*fc.Spec.ProgramClusterRoutes).To(Equal("Disabled"))

			bgpConfig := &v3.BGPConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(bgpConfig.Spec.ProgramClusterRoutes).NotTo(BeNil())
			Expect(*bgpConfig.Spec.ProgramClusterRoutes).To(Equal("Enabled"))
		})

		It("should correctly patch FelixConfig and BGPConfig with ClusterRouteMode set to Felix", func() {
			felix := operator.ClusterRoutingModeFelix
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{ClusterRoutingMode: &felix}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.ProgramClusterRoutes).NotTo(BeNil())
			Expect(*fc.Spec.ProgramClusterRoutes).To(Equal("Enabled"))

			bgpConfig := &v3.BGPConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(bgpConfig.Spec.ProgramClusterRoutes).NotTo(BeNil())
			Expect(*bgpConfig.Spec.ProgramClusterRoutes).To(Equal("Disabled"))
		})

		It("should correctly patch FelixConfig and BGPConfig with ClusterRouteMode set to FelixIPIPOnly", func() {
			felixIPIPOnly := operator.ClusterRoutingModeFelixIPIPOnly
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{ClusterRoutingMode: &felixIPIPOnly}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.ProgramClusterRoutes).NotTo(BeNil())
			Expect(*fc.Spec.ProgramClusterRoutes).To(Equal("EnabledIPIPOnly"))

			bgpConfig := &v3.BGPConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(bgpConfig.Spec.ProgramClusterRoutes).NotTo(BeNil())
			Expect(*bgpConfig.Spec.ProgramClusterRoutes).To(Equal("EnabledNoEncapOnly"))
		})

		It("should create the default BGPConfig and FelixConfig with ClusterRoutingMode set", func() {
			bgpConfig := &v3.BGPConfiguration{}
			err := c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
			Expect(err).Should(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).Should(HaveOccurred())

			felix := operator.ClusterRoutingModeFelix
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{ClusterRoutingMode: &felix}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.ProgramClusterRoutes).NotTo(BeNil())
			Expect(*fc.Spec.ProgramClusterRoutes).To(Equal("Enabled"))

			bgpConfig = &v3.BGPConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(bgpConfig.Spec.ProgramClusterRoutes).NotTo(BeNil())
			Expect(*bgpConfig.Spec.ProgramClusterRoutes).To(Equal("Disabled"))
		})

		It("should set vxlanVNI to 10000 when provider is DockerEE", func() {
			cr.Spec.KubernetesProvider = operator.ProviderDockerEE
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(fc.Spec.VXLANVNI).NotTo(BeNil())
			Expect(*fc.Spec.VXLANVNI).To(Equal(10000))
		})

		It("should set vxlanPort to 8472 and nftables to disabled when provider is DockerEE and BPF is enabled", func() {
			cr.Spec.KubernetesProvider = operator.ProviderDockerEE
			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.VXLANPort).NotTo(BeNil())
			Expect(*fc.Spec.VXLANPort).To(Equal(8472))
			Expect(fc.Spec.NFTablesMode).NotTo(BeNil())
			Expect(*fc.Spec.NFTablesMode).To(Equal(v3.NFTablesMode(v3.NFTablesModeDisabled)))
		})

		It("should set bpfHostConntrackByPass to false when provider is DockerEE and BPF enabled", func() {
			cr.Spec.KubernetesProvider = operator.ProviderDockerEE
			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(fc.Spec.BPFHostConntrackBypass).NotTo(BeNil())
			Expect(*fc.Spec.BPFHostConntrackBypass).To(BeFalse())
		})

		It("should set BPFKubeProxyHealthzPort to 0 when BPF is enabled and operator does not manage kube-proxy", func() {
			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(fc.Spec.BPFKubeProxyHealthzPort).NotTo(BeNil())
			Expect(*fc.Spec.BPFKubeProxyHealthzPort).To(Equal(0))
		})

		It("should not set BPFKubeProxyHealthzPort when BPF is disabled", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(fc.Spec.BPFKubeProxyHealthzPort).To(BeNil())
		})

		It("should not set BPFKubeProxyHealthzPort when BPF is enabled and operator manages kube-proxy", func() {
			network := operator.LinuxDataplaneBPF
			kpManagement := operator.KubeProxyManagementEnabled
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{
				LinuxDataplane:      &network,
				KubeProxyManagement: &kpManagement,
			}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(fc.Spec.BPFKubeProxyHealthzPort).To(BeNil())
		})

		It("should not overwrite an existing user-set BPFKubeProxyHealthzPort", func() {
			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}

			userPort := 12345
			Expect(c.Create(ctx, &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{BPFKubeProxyHealthzPort: &userPort},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(fc.Spec.BPFKubeProxyHealthzPort).NotTo(BeNil())
			Expect(*fc.Spec.BPFKubeProxyHealthzPort).To(Equal(12345))
		})

		It("should set BPFEnabled to ture on FelixConfiguration if BPF is enabled on installation", func() {
			createNodeDaemonSet()

			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("true"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())
		})

		It("should set BPFEnabled to true on FelixConfiguration on a fresh install in BPF Mode", func() {
			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("true"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())
		})

		It("should set BPFEnabled to false on FelixConfiguration if BPF is disabled on installation", func() {
			createNodeDaemonSet()

			// Enable BPF.
			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("true"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())

			// Set dataplane to IPTables.
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			network = operator.LinuxDataplaneIptables
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Update(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc = &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("false"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeFalse())
		})

		It("should set BPFEnabled on FelixConfiguration if FELIX_BPFENABLED Env var is set by old version of operator", func() {
			createNodeDaemonSet()

			ds := &appsv1.DaemonSet{}
			err := c.Get(ctx,
				types.NamespacedName{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
				ds)
			Expect(err).NotTo(HaveOccurred())
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "FELIX_BPFENABLED", Value: "true", ValueFrom: nil},
			}
			Expect(c.Update(ctx, ds)).NotTo(HaveOccurred())

			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("true"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())
		})

		It("generates FelixConfiguration with correct DNS service for Rancher", func() {
			cr.Spec.KubernetesProvider = operator.ProviderRKE2
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// We should get a felix configuration with Rancher's DNS service.
			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.DNSTrustedServers).NotTo(BeNil())
			Expect(*fc.Spec.DNSTrustedServers).To(ConsistOf("k8s-service:kube-system/rke2-coredns-rke2-coredns"))
		})

		It("should Reconcile with AWS CNI config", func() {
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginAmazonVPC}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration is created with RouteTableRange
			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.RouteTableRange).NotTo(BeNil())
			Expect(*fc.Spec.RouteTableRange).To(Equal(v3.RouteTableRange{Min: 65, Max: 99}))
		})

		It("should Reconcile with GKE CNI config", func() {
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginGKE}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration is created with RouteTableRange
			fc := &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.RouteTableRange).NotTo(BeNil())
			Expect(*fc.Spec.RouteTableRange).To(Equal(v3.RouteTableRange{Min: 10, Max: 250}))
		})

		It("should Reconcile with AWS CNI and not change existing FelixConfig", func() {
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.FelixConfigurationSpec{
					RouteTableRange:   &v3.RouteTableRange{Min: 15, Max: 55},
					LogSeverityScreen: "Error",
				},
			}
			err := c.Create(ctx, fc)
			Expect(err).ShouldNot(HaveOccurred())
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginAmazonVPC}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration has not changed
			fc = &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.RouteTableRange).NotTo(BeNil())
			Expect(*fc.Spec.RouteTableRange).To(Equal(v3.RouteTableRange{Min: 15, Max: 55}))
			Expect(fc.Spec.LogSeverityScreen).To(Equal("Error"))
		})

		It("should Reconcile with AWS CNI and update existing FelixConfig", func() {
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.FelixConfigurationSpec{
					LogSeverityScreen: "Error",
				},
			}
			err := c.Create(ctx, fc)
			Expect(err).ShouldNot(HaveOccurred())
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginAmazonVPC}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration is created with RouteTableRange
			fc = &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.RouteTableRange).NotTo(BeNil())
			Expect(*fc.Spec.RouteTableRange).To(Equal(v3.RouteTableRange{Min: 65, Max: 99}))
			Expect(fc.Spec.LogSeverityScreen).To(Equal("Error"))
		})

		It("should Reconcile with FelixConfig natPortRange set", func() {
			fc := &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.FelixConfigurationSpec{
					NATPortRange: &numorstring.Port{MinPort: 15, MaxPort: 55},
				},
			}
			err := c.Create(ctx, fc)
			Expect(err).ShouldNot(HaveOccurred())
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginAmazonVPC}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration has not changed
			fc = &v3.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.NATPortRange).NotTo(BeNil())
			Expect(*fc.Spec.NATPortRange).To(Equal(numorstring.Port{MinPort: 15, MaxPort: 55}))
		})

		It("should Reconcile with GKE and create a resource quota", func() {
			cr.Spec.KubernetesProvider = operator.ProviderGKE
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			rq := corev1.ResourceQuota{
				TypeMeta: metav1.TypeMeta{Kind: "ResourceQuota", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-critical-pods",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &rq)).To(BeNil())
		})

		It("should Reconcile with no active operator ConfigMap", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			cm := corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &cm)).To(BeNil())
			Expect(cm.Data["active-namespace"]).To(Equal("tigera-operator"))
		})

		It("should exit Reconcile when active operator is a different namespace", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{"active-namespace": "other-namespace"},
			})).NotTo(HaveOccurred())

			exited := false
			osExitOverride = func(_ int) { exited = true }
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			Expect(exited).Should(BeTrue())
		})

		It("should not exit Reconcile when active operator is current namespace", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{"active-namespace": "tigera-operator"},
			})).NotTo(HaveOccurred())

			exited := false
			osExitOverride = func(_ int) { exited = false }
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(exited).Should(BeFalse())
			cm := corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &cm)).To(BeNil())
			Expect(cm.Data["active-namespace"]).To(Equal("tigera-operator"))
		})

		It("should not overwrite active-operator CM when it already exists", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{
					"active-namespace": "tigera-operator",
					"extra-dummy":      "dummy-value",
				},
			})).NotTo(HaveOccurred())

			exited := false
			osExitOverride = func(_ int) { exited = false }
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(exited).Should(BeFalse())
			cm := corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &cm)).To(BeNil())
			Expect(cm.Data["active-namespace"]).To(Equal("tigera-operator"))
			Expect(cm.Data).To(HaveKey("extra-dummy"))
		})

		It("should reconcile with creating new installation status condition with one item", func() {
			generation := int64(2)
			ts := &operator.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Spec:       operator.TigeraStatusSpec{},
				Status: operator.TigeraStatusStatus{
					Conditions: []operator.TigeraStatusCondition{
						{
							Type:               operator.ComponentAvailable,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "calico",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Status.Conditions).To(HaveLen(1))

			Expect(cr.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(cr.Status.Conditions[0].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[0].Reason).To(Equal(string(operator.AllObjectsAvailable)))
			Expect(cr.Status.Conditions[0].Message).To(Equal("All Objects are available"))
		})

		It("should reconcile with Empty tigera status condition", func() {
			ts := &operator.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Spec:       operator.TigeraStatusSpec{},
				Status:     operator.TigeraStatusStatus{},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "calico",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Status.Conditions).To(HaveLen(0))
		})

		It("should reconcile with creating new installation status with multiple conditions as true", func() {
			generation := int64(2)
			ts := &operator.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Spec:       operator.TigeraStatusSpec{},
				Status: operator.TigeraStatusStatus{
					Conditions: []operator.TigeraStatusCondition{
						{
							Type:               operator.ComponentAvailable,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operator.ComponentProgressing,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.ResourceNotReady),
							Message:            "Progressing Installation.operator.tigera.io",
							ObservedGeneration: generation,
						},
						{
							Type:               operator.ComponentDegraded,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.ResourceUpdateError),
							Message:            "Error resolving ImageSet for components",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "calico",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Status.Conditions).To(HaveLen(3))

			Expect(cr.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(cr.Status.Conditions[0].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[0].Reason).To(Equal(string(operator.AllObjectsAvailable)))
			Expect(cr.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(cr.Status.Conditions[0].ObservedGeneration).To(Equal(int64(2)))

			Expect(cr.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(cr.Status.Conditions[1].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[1].Reason).To(Equal(string(operator.ResourceNotReady)))
			Expect(cr.Status.Conditions[1].Message).To(Equal("Progressing Installation.operator.tigera.io"))
			Expect(cr.Status.Conditions[1].ObservedGeneration).To(Equal(int64(2)))

			Expect(cr.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(cr.Status.Conditions[2].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[2].Reason).To(Equal(string(operator.ResourceUpdateError)))
			Expect(cr.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
			Expect(cr.Status.Conditions[2].ObservedGeneration).To(Equal(int64(2)))
		})

		It("should reconcile with Existing conditions and toggle Available to true & others to false", func() {
			generation := int64(2)
			ts := &operator.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Spec:       operator.TigeraStatusSpec{},
				Status: operator.TigeraStatusStatus{
					Conditions: []operator.TigeraStatusCondition{
						{
							Type:               operator.ComponentAvailable,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operator.ComponentProgressing,
							Status:             operator.ConditionFalse,
							Reason:             string(operator.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
						{
							Type:               operator.ComponentDegraded,
							Status:             operator.ConditionFalse,
							Reason:             string(operator.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			cr.Status.Conditions = []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionStatus(operator.ConditionFalse),
					Reason:             string(operator.NotApplicable),
					Message:            "Not Applicable",
					LastTransitionTime: metav1.NewTime(time.Now()),
				},
				{
					Type:               "Progressing",
					Status:             metav1.ConditionStatus(operator.ConditionTrue),
					LastTransitionTime: metav1.NewTime(time.Now()),
					Reason:             string(operator.ResourceNotReady),
					Message:            "All resources are not available",
				},
				{
					Type:               "Degraded",
					Status:             metav1.ConditionStatus(operator.ConditionFalse),
					Reason:             string(operator.NotApplicable),
					Message:            "Not Applicable",
					LastTransitionTime: metav1.NewTime(time.Now()),
				},
			}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "calico",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Status.Conditions).To(HaveLen(3))

			Expect(cr.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(cr.Status.Conditions[0].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[0].Reason).To(Equal(string(operator.AllObjectsAvailable)))
			Expect(cr.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(cr.Status.Conditions[0].ObservedGeneration).To(Equal(int64(2)))

			Expect(cr.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(cr.Status.Conditions[1].Status)).To(Equal(string(operator.ConditionFalse)))
			Expect(cr.Status.Conditions[1].Reason).To(Equal(string(operator.NotApplicable)))
			Expect(cr.Status.Conditions[1].Message).To(Equal("Not Applicable"))
			Expect(cr.Status.Conditions[1].ObservedGeneration).To(Equal(int64(2)))

			Expect(cr.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(cr.Status.Conditions[2].Status)).To(Equal(string(operator.ConditionFalse)))
			Expect(cr.Status.Conditions[2].Reason).To(Equal(string(operator.NotApplicable)))
			Expect(cr.Status.Conditions[2].Message).To(Equal("Not Applicable"))
			Expect(cr.Status.Conditions[2].ObservedGeneration).To(Equal(int64(2)))
		})

		It("should render calico-system policy when tier and tier watch are ready", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(2))
			Expect(policies.Items[0].Name).To(Equal("calico-system.default-deny"))
			Expect(policies.Items[1].Name).To(Equal("calico-system.kube-controller-access"))

			defaultDenyPolicy := policies.Items[0]
			Expect(defaultDenyPolicy.Spec.Selector).To(Equal("k8s-app != 'calico-apiserver'"))
		})

		It("should omit calico-system policy and not degrade when tier is not ready", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should omit calico-system policy and not degrade when tier watch is not ready", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			r.tierWatchReady = notReady

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should omit calico-system policy and not degrade when installation is calico", func() {
			cr.Spec.Variant = operator.Calico
			cr.Status.Variant = operator.Calico
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			r.opts.Variant = operator.Calico
			Expect(c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should set default spec.Azure if provider is AKS", func() {
			cr.Spec.KubernetesProvider = operator.ProviderAKS

			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policyMode := operator.PolicyModeDefault
			azure := &operator.Azure{
				PolicyMode: &policyMode,
			}
			instance := &operator.Installation{}

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, instance)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Spec.Azure).NotTo(BeNil())
			Expect(instance.Spec.Azure).To(Equal(azure))
		})

		It("should not set default spec.Azure if provider is not AKS", func() {
			cr.Spec.KubernetesProvider = operator.ProviderEKS

			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			instance := &operator.Installation{}

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, instance)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Spec.Azure).To(BeNil())
		})
	})

	Context("Using EKS networking", func() {
		var certificateManager certificatemanager.CertificateManager

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

			// Create a fake clientset for the autoscaler.
			var replicas int32 = 1
			objs := []runtime.Object{
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
					Spec: appsv1.DeploymentSpec{
						Replicas: &replicas,
					},
				},
			}
			cs = kfake.NewClientset(objs...)

			// Create an object we can use throughout the test to do the compliance reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
			mockStatus.On("ClearWarning", mock.Anything).Return()
			mockStatus.On("AddCertificateSigningRequests", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				ext: testExtensions.Installation(),
				opts: options.ControllerOptions{
					Extensions:       testExtensions,
					DetectedProvider: operator.ProviderNone,
					Variant:          operator.CalicoEnterprise,
					ClusterDomain:    dns.DefaultClusterDomain,
				},
				config:              nil, // there is no fake for config
				client:              c,
				scheme:              scheme,
				status:              mockStatus,
				typhaAutoscaler:     newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:  &fakeNamespaceMigration{},
				migrationChecked:    true,
				tierWatchReady:      ready,
				migrationWatchReady: &utils.ReadyFlag{},
				newComponentHandler: utils.NewComponentHandler,
			}
			r.typhaAutoscaler.start(ctx)

			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:            operator.CalicoEnterprise,
					Registry:           "some.registry.org/",
					KubernetesProvider: operator.ProviderEKS,
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
						IPAM: &operator.IPAMSpec{
							Type: operator.IPAMPluginAmazonVPC,
						},
					},
				},
				Status: operator.InstallationStatus{
					Variant: operator.CalicoEnterprise,
					Computed: &operator.InstallationSpec{
						Registry: "my-reg",
						// The test is provider agnostic.
						KubernetesProvider: operator.ProviderNone,
					},
				},
			}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			// NOTE: We do NOT create an IP pool for this test suite, as it is not needed for the Amazon VPC plugin.

			var err error
			certificateManager, err = certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		It("should reconcile successfully and create resources", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			cfgMap := &corev1.ConfigMap{}

			Expect(c.Get(ctx, client.ObjectKey{Name: "tigera-ca-bundle", Namespace: common.CalicoNamespace}, cfgMap)).ShouldNot(HaveOccurred())
			Expect(cfgMap.GetOwnerReferences()).To(HaveLen(1))

			Expect(c.Get(ctx, client.ObjectKey{Name: render.NodeTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

			Expect(c.Get(ctx, client.ObjectKey{Name: render.TyphaTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))
		})

	})

	Context("with a fake component handler", func() {
		var componentHandler *fakeComponentHandler

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

			// Create a fake clientset for the autoscaler.
			var replicas int32 = 1
			objs := []runtime.Object{
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
					Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
				},
			}
			cs = kfake.NewClientset(objs...)

			// Create an object we can use throughout the test to do the compliance reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
			mockStatus.On("ClearWarning", mock.Anything).Return()
			mockStatus.On("AddCertificateSigningRequests", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			componentHandler = newFakeComponentHandler()
			r = ReconcileInstallation{
				ext: testExtensions.Installation(),
				opts: options.ControllerOptions{
					Extensions:       testExtensions,
					DetectedProvider: operator.ProviderNone,
					Variant:          operator.CalicoEnterprise,
				},
				config:              nil, // there is no fake for config
				client:              c,
				scheme:              scheme,
				status:              mockStatus,
				typhaAutoscaler:     newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:  &fakeNamespaceMigration{},
				migrationChecked:    true,
				tierWatchReady:      ready,
				migrationWatchReady: &utils.ReadyFlag{},
				newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
					return componentHandler
				},
			}

			r.typhaAutoscaler.start(ctx)
			certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())

			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())

			// We start off with a 'standard' installation, with nothing special
			Expect(c.Create(
				ctx,
				&operator.Installation{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec: operator.InstallationSpec{
						Variant:               operator.CalicoEnterprise,
						Registry:              "some.registry.org/",
						CertificateManagement: &operator.CertificateManagement{CACert: prometheusTLS.GetCertificatePEM()},
					},
					Status: operator.InstallationStatus{
						Variant: operator.CalicoEnterprise,
						Computed: &operator.InstallationSpec{
							Registry: "my-reg",
							// The test is provider agnostic.
							KubernetesProvider: operator.ProviderNone,
						},
					},
				})).NotTo(HaveOccurred())

			// In most clusters, the IP pool controller is responsible for creating IP pools. The Installation controller waits for this,
			// so we need to create those pools here.
			pool := v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: v3.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    v3.VXLANModeAlways,
				},
			}
			Expect(c.Create(ctx, &pool)).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		// This test ensures that all resources with the CNIFinalizer applied to them are also returned by
		// render.CNIPluginFinalizedObjects.
		It("should have the correct number of resources with CNIFinalizer", func() {
			// Trigger a reconcile.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Review the resources that were created to count the resources with a CNIFinalizer set.
			numCreated := 0
			for _, o := range componentHandler.objectsToCreate {
				for _, f := range o.GetFinalizers() {
					if f == render.CNIFinalizer {
						numCreated++
						break
					}
				}
			}
			Expect(numCreated).To(Equal(len(render.CNIPluginFinalizedObjects())))
		})
	})
})

func newFakeComponentHandler() *fakeComponentHandler {
	return &fakeComponentHandler{
		objectsToCreate: make([]client.Object, 0),
		objectsToDelete: make([]client.Object, 0),
	}
}

type fakeComponentHandler struct {
	objectsToCreate []client.Object
	objectsToDelete []client.Object
}

func (f *fakeComponentHandler) SetCreateOnly() {
}

func (f *fakeComponentHandler) CreateOrUpdateOrDelete(ctx context.Context, component render.Component, _ status.StatusManager) error {
	c, d := component.Objects()
	f.objectsToCreate = append(f.objectsToCreate, c...)
	f.objectsToDelete = append(f.objectsToDelete, d...)
	return nil
}

var _ = Describe("updateMutatingAdmissionPolicies", func() {
	var (
		ctx              context.Context
		cancel           context.CancelFunc
		r                ReconcileInstallation
		scheme           *runtime.Scheme
		mockStatus       *status.MockStatus
		componentHandler *fakeComponentHandler
		log              logr.Logger
		installation     *operator.Installation
	)

	clientFor := func(initial ...client.Object) client.Client {
		return ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(initial...).Build()
	}

	discoveryFor := func(mapVersion string) *discovery.APIDiscovery {
		m := map[schema.GroupKind]string{}
		if mapVersion != "" {
			m[admission.PolicyGroupKind] = mapVersion
		}
		return discovery.NewStaticAPIDiscovery(m)
	}

	BeforeEach(func() {
		log = logr.Discard()
		ctx, cancel = context.WithCancel(context.Background())

		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(admissionregistrationv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(admissionregistrationv1alpha1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		mockStatus = &status.MockStatus{}
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

		componentHandler = newFakeComponentHandler()
		installation = &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				Variant: operator.Calico,
			},
		}
	})

	AfterEach(func() {
		cancel()
	})

	It("should create v1 MAPs when v1 is served", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(4))

		var mapCount, mapbCount int
		for _, obj := range componentHandler.objectsToCreate {
			switch obj.(type) {
			case *admissionregistrationv1.MutatingAdmissionPolicy:
				mapCount++
				Expect(obj.GetLabels()).To(HaveKeyWithValue(admission.ManagedMAPLabel, admission.ManagedMAPLabelValue))
			case *admissionregistrationv1.MutatingAdmissionPolicyBinding:
				mapbCount++
				Expect(obj.GetLabels()).To(HaveKeyWithValue(admission.ManagedMAPLabel, admission.ManagedMAPLabelValue))
			}
		}
		Expect(mapCount).To(Equal(2))
		Expect(mapbCount).To(Equal(2))
	})

	It("should create v1beta1 MAPs when only v1beta1 is served", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1Beta1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(4))

		var mapCount, mapbCount int
		for _, obj := range componentHandler.objectsToCreate {
			switch obj.(type) {
			case *admissionv1beta1.MutatingAdmissionPolicy:
				mapCount++
			case *admissionv1beta1.MutatingAdmissionPolicyBinding:
				mapbCount++
			}
		}
		Expect(mapCount).To(Equal(2))
		Expect(mapbCount).To(Equal(2))
	})

	It("should create v1alpha1 MAPs when only v1alpha1 is served", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1Alpha1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(4))

		var mapCount, mapbCount int
		for _, obj := range componentHandler.objectsToCreate {
			switch obj.(type) {
			case *admissionregistrationv1alpha1.MutatingAdmissionPolicy:
				mapCount++
			case *admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding:
				mapbCount++
			}
		}
		Expect(mapCount).To(Equal(2))
		Expect(mapbCount).To(Equal(2))
	})

	It("should not create MAPs when no served version exists and should set degraded", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(""),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(BeEmpty())
		mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operator.ResourceNotReady, mock.Anything, mock.Anything, mock.Anything)
	})

	It("should not create MAPs when v3CRDs=false", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    false,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(BeEmpty())
	})

	It("should not create MAPs when manageCRDs=false", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   false,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(BeEmpty())
	})

	It("should delete stale v1 MAPs with managed label", func() {
		staleMAP := &admissionregistrationv1.MutatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "stale-policy",
				Labels: map[string]string{admission.ManagedMAPLabel: admission.ManagedMAPLabelValue},
			},
		}
		staleMAPB := &admissionregistrationv1.MutatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "stale-binding",
				Labels: map[string]string{admission.ManagedMAPLabel: admission.ManagedMAPLabelValue},
			},
		}

		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(staleMAP, staleMAPB),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(4))
		Expect(componentHandler.objectsToDelete).To(HaveLen(2))
		deletedNames := map[string]bool{}
		for _, obj := range componentHandler.objectsToDelete {
			deletedNames[obj.GetName()] = true
		}
		Expect(deletedNames).To(HaveKey("stale-policy"))
		Expect(deletedNames).To(HaveKey("stale-binding"))
	})

	It("should not delete MAPs that are in the desired set", func() {
		var initial []client.Object
		for _, n := range []string{"policytypes.policy.projectcalico.org", "tierlabel.policy.projectcalico.org"} {
			initial = append(initial, &admissionregistrationv1.MutatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:   n,
					Labels: map[string]string{admission.ManagedMAPLabel: admission.ManagedMAPLabelValue},
				},
			})
		}
		for _, n := range []string{"set-policytypes-binding", "set-tier-label-binding"} {
			initial = append(initial, &admissionregistrationv1.MutatingAdmissionPolicyBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:   n,
					Labels: map[string]string{admission.ManagedMAPLabel: admission.ManagedMAPLabelValue},
				},
			})
		}

		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(initial...),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(4))
		Expect(componentHandler.objectsToDelete).To(BeEmpty())
	})

	It("should work with Enterprise variant", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		installation.Spec.Variant = operator.CalicoEnterprise

		Expect(r.updateMutatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(4))
	})
})

var _ = Describe("updateValidatingAdmissionPolicies", func() {
	var (
		ctx              context.Context
		cancel           context.CancelFunc
		r                ReconcileInstallation
		scheme           *runtime.Scheme
		mockStatus       *status.MockStatus
		componentHandler *fakeComponentHandler
		log              logr.Logger
		installation     *operator.Installation
	)

	clientFor := func(initial ...client.Object) client.Client {
		return ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(initial...).Build()
	}

	discoveryFor := func(vapVersion string) *discovery.APIDiscovery {
		m := map[schema.GroupKind]string{}
		if vapVersion != "" {
			m[admission.ValidatingPolicyGroupKind] = vapVersion
		}
		return discovery.NewStaticAPIDiscovery(m)
	}

	BeforeEach(func() {
		log = logr.Discard()
		ctx, cancel = context.WithCancel(context.Background())

		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(admissionregistrationv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(admissionregistrationv1alpha1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		mockStatus = &status.MockStatus{}
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

		componentHandler = newFakeComponentHandler()
		installation = &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				Variant: operator.Calico,
			},
		}
	})

	AfterEach(func() {
		cancel()
	})

	It("should create v1 VAPs when v1 is served", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateValidatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(2))

		var vapCount, vapbCount int
		for _, obj := range componentHandler.objectsToCreate {
			switch obj.(type) {
			case *admissionregistrationv1.ValidatingAdmissionPolicy:
				vapCount++
				Expect(obj.GetLabels()).To(HaveKeyWithValue(admission.ManagedVAPLabel, admission.ManagedVAPLabelValue))
			case *admissionregistrationv1.ValidatingAdmissionPolicyBinding:
				vapbCount++
				Expect(obj.GetLabels()).To(HaveKeyWithValue(admission.ManagedVAPLabel, admission.ManagedVAPLabelValue))
			}
		}
		Expect(vapCount).To(Equal(1))
		Expect(vapbCount).To(Equal(1))
	})

	It("should create v1beta1 VAPs when only v1beta1 is served", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1Beta1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateValidatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(2))

		var vapCount, vapbCount int
		for _, obj := range componentHandler.objectsToCreate {
			switch obj.(type) {
			case *admissionv1beta1.ValidatingAdmissionPolicy:
				vapCount++
			case *admissionv1beta1.ValidatingAdmissionPolicyBinding:
				vapbCount++
			}
		}
		Expect(vapCount).To(Equal(1))
		Expect(vapbCount).To(Equal(1))
	})

	It("should create v1alpha1 VAPs when only v1alpha1 is served", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1Alpha1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateValidatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(2))
	})

	It("should skip without degrading when no served version exists", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(""),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateValidatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(BeEmpty())
		mockStatus.AssertNotCalled(GinkgoT(), "SetDegraded", operator.ResourceNotReady, mock.Anything, mock.Anything, mock.Anything)
	})

	It("should not create VAPs when v3CRDs=false", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    false,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateValidatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(BeEmpty())
	})

	It("should delete stale v1 VAPs with managed label", func() {
		staleVAP := &admissionregistrationv1.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "stale-policy",
				Labels: map[string]string{admission.ManagedVAPLabel: admission.ManagedVAPLabelValue},
			},
		}
		staleVAPB := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "stale-binding",
				Labels: map[string]string{admission.ManagedVAPLabel: admission.ManagedVAPLabelValue},
			},
		}

		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(staleVAP, staleVAPB),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		Expect(r.updateValidatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(2))
		Expect(componentHandler.objectsToDelete).To(HaveLen(2))
		deletedNames := map[string]bool{}
		for _, obj := range componentHandler.objectsToDelete {
			deletedNames[obj.GetName()] = true
		}
		Expect(deletedNames).To(HaveKey("stale-policy"))
		Expect(deletedNames).To(HaveKey("stale-binding"))
	})

	It("should work with Enterprise variant", func() {
		r = ReconcileInstallation{
			ext: testExtensions.Installation(),
			opts: options.ControllerOptions{
				Extensions:   testExtensions,
				ManageCRDs:   true,
				UseV3CRDs:    true,
				APIDiscovery: discoveryFor(admission.VersionV1),
			},
			client: clientFor(),
			scheme: scheme,
			status: mockStatus,
			newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object, ...utils.ComponentHandlerOption) utils.ComponentHandler {
				return componentHandler
			},
		}

		installation.Spec.Variant = operator.CalicoEnterprise

		Expect(r.updateValidatingAdmissionPolicies(ctx, installation, log)).NotTo(HaveOccurred())
		Expect(componentHandler.objectsToCreate).To(HaveLen(2))
	})
})
