// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package kubeproxy

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	// gopkg.in/yaml.v2 didn't parse all the fields but this package did
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render"
)

var _ = Describe("kube-proxy controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r *Reconciler
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var k8sService *corev1.Service
	var K8sEndpointSlice *discoveryv1.EndpointSlice

	kpManagementEnabled := operatorv1.KubeProxyManagementEnabled
	kpManagementDisabled := operatorv1.KubeProxyManagementDisabled

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(discoveryv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a CRUD interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		k8sService = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
				ClusterIP:  "1.2.3.4",
				Ports: []corev1.ServicePort{
					{Name: "https", Port: 443, TargetPort: intstr.FromInt(443)},
				},
			},
		}
		K8sEndpointSlice = &discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Name: "kubernetes-epv4", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"5.6.7.8", "5.6.7.9", "5.6.7.10"}},
			},
			Ports: []discoveryv1.EndpointPort{{Port: ptr.To(int32(6443))}},
		}

		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		r = &Reconciler{
			cli:    c,
			scheme: scheme,
			status: mockStatus,
		}
	})

	createResource := func(obj client.Object) {
		Expect(c.Create(ctx, obj)).NotTo(HaveOccurred())
	}
	createInstallationCR := func(bpfEnabled bool, managed *operatorv1.KubeProxyManagementType) {
		linuxDataplaneBPF := operatorv1.LinuxDataplaneBPF
		if !bpfEnabled {
			linuxDataplaneBPF = operatorv1.LinuxDataplaneIptables
		}
		install := &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					KubeProxyManagement: managed,
					LinuxDataplane:      &linuxDataplaneBPF,
				},
			},
		}
		install.Status.Computed = &install.Spec
		createResource(install)
	}
	createKubeProxyDS := func(addNodeSelector bool) {
		nodeSelector := map[string]string{}
		if addNodeSelector {
			nodeSelector[render.DisableKubeProxyKey] = "true"
		}
		createResource(&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: utils.KubeProxyInstanceKey.Name, Namespace: utils.KubeProxyInstanceKey.Namespace},
			Spec: appsv1.DaemonSetSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: corev1.PodSpec{
						NodeSelector: nodeSelector,
					},
				},
			},
		})
	}
	createFelixConfiguration := func(bpfEnabled bool) {
		createResource(&v3.FelixConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: v3.FelixConfigurationSpec{
				BPFEnabled: ptr.To(bpfEnabled),
			},
		})
	}
	checkKubeProxyState := func(kp *appsv1.DaemonSet, hasNodeSelector bool) {
		if hasNodeSelector {
			Expect(kp.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(kp.Spec.Template.Spec.NodeSelector[render.DisableKubeProxyKey]).To(Equal("true"))
		} else {
			Expect(kp.Spec.Template.Spec.NodeSelector).To(HaveLen(0))
		}
	}

	DescribeTable("manage kube-proxy DaemonSet",
		func(bpfEnabled bool, kpManaged *operatorv1.KubeProxyManagementType) {
			kp := &appsv1.DaemonSet{}
			nodeSelectorIncluded := !bpfEnabled
			By("applying the resources")
			createInstallationCR(bpfEnabled, kpManaged)
			createFelixConfiguration(bpfEnabled)
			createKubeProxyDS(nodeSelectorIncluded)
			createResource(k8sService)
			createResource(K8sEndpointSlice)

			By("reading the KubeProxy DaemonSet initial state")
			err := c.Get(ctx, utils.KubeProxyInstanceKey, kp)
			Expect(err).NotTo(HaveOccurred())
			checkKubeProxyState(kp, nodeSelectorIncluded)

			By("triggering a reconcile")
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("re-reading the KubeProxy DaemonSet")
			err = c.Get(ctx, utils.KubeProxyInstanceKey, kp)
			Expect(err).NotTo(HaveOccurred())

			By("checking if NodeSelector changed")
			// It should change only if KubeProxyManagement is Enabled
			if kpManaged == &kpManagementEnabled {
				nodeSelectorIncluded = !nodeSelectorIncluded
			}
			checkKubeProxyState(kp, nodeSelectorIncluded)
		},
		Entry("disable kube-proxy if BPFEnabled is false and kubeProxyManagement is Enabled",
			true, &kpManagementEnabled,
		),
		Entry("enable kube-proxy if BPFEnabled is false and kubeProxyManagement is Enabled",
			false, &kpManagementEnabled,
		),
		Entry("doesn't change kube-proxy if kubeProxyManagement is Disabled",
			false, &kpManagementDisabled,
		),
		Entry("doesn't change kube-proxy if kubeProxyManagement is unset",
			true, nil,
		),
	)

	Context("kube-proxy managed by external tool", func() {
		kubeProxyDS := func() *appsv1.DaemonSet {
			return &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      utils.KubeProxyInstanceKey.Name,
					Namespace: utils.KubeProxyInstanceKey.Namespace,
				},
			}
		}
		DescribeTable("check whether kube-proxy is not managed",
			func(labels map[string]string, annotations map[string]string, shouldSucceed bool) {
				ds := kubeProxyDS()
				ds.Labels = labels
				ds.Annotations = annotations
				err := validateDaemonSetUnmanaged(ds)
				Expect(err == nil).Should(Equal(shouldSucceed))
			},
			Entry("managed by argocd",
				map[string]string{"app.kubernetes.io/managed-by": "argocd"}, nil, false,
			),
			Entry("addonmanager mode ReconcileOnce",
				map[string]string{"addonmanager.kubernetes.io/mode": "ReconcileOnce"}, nil, false,
			),
			Entry("managed by argocd with tracking-id",
				nil, map[string]string{"argocd.argoproj.io/tracking-id": "fake-git-commit-hash"}, false,
			),
			Entry("kube-proxy not managed",
				map[string]string{"app.kubernetes.io/name": "kube-proxy"}, nil, true,
			),
			Entry("kube-proxy not managed",
				map[string]string{"app.kubernetes.io/name": "kube-proxy"},
				map[string]string{"kube-proxy.config.k8s.io/proxy-mode": "iptables"},
				true,
			),
		)
	})
})
