// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package istio_test

import (
	netattachv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
)

var _ = Describe("Istio data plane upgrade order", func() {
	const oldImage = "registry.example/old:1"

	var (
		cfg     *istio.Configuration
		desired []client.Object
	)

	render := func() []client.Object {
		_, component, err := istio.Istio(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(component.ResolveImages(getCalicoTestImageSet())).To(Succeed())
		objs, _ := component.Objects()
		return objs
	}

	desiredDeployment := func() *appsv1.Deployment {
		d, err := rtest.GetResourceOfType[*appsv1.Deployment](desired, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
		Expect(err).NotTo(HaveOccurred())
		return d.DeepCopy()
	}
	desiredDaemonSet := func(name string) *appsv1.DaemonSet {
		ds, err := rtest.GetResourceOfType[*appsv1.DaemonSet](desired, name, istio.IstioNamespace)
		Expect(err).NotTo(HaveOccurred())
		return ds.DeepCopy()
	}
	withImage := func(spec *corev1.PodSpec, image string) {
		for i := range spec.Containers {
			spec.Containers[i].Image = image
		}
	}
	rolledOut := func(d *appsv1.Deployment) *appsv1.Deployment {
		d.Generation = 3
		d.Spec.Replicas = ptr.To[int32](2)
		d.Status = appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2}
		return d
	}
	oldIstiod := func() *appsv1.Deployment {
		d := rolledOut(desiredDeployment())
		withImage(&d.Spec.Template.Spec, oldImage)
		return d
	}
	oldDaemonSet := func(name string) *appsv1.DaemonSet {
		ds := desiredDaemonSet(name)
		withImage(&ds.Spec.Template.Spec, oldImage)
		return ds
	}
	hasDaemonSet := func(objs []client.Object, name string) bool {
		_, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objs, name, istio.IstioNamespace)
		return err == nil
	}

	BeforeEach(func() {
		testScheme := runtime.NewScheme()
		Expect(scheme.AddToScheme(testScheme)).To(Succeed())
		Expect(operatorv1.AddToScheme(testScheme)).To(Succeed())
		Expect(v3.AddToScheme(testScheme)).To(Succeed())
		Expect(apiextv1.AddToScheme(testScheme)).To(Succeed())
		Expect(netattachv1.AddToScheme(testScheme)).To(Succeed())
		cfg = &istio.Configuration{
			Installation: &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderNone},
			Istio: &operatorv1.Istio{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       operatorv1.IstioSpec{DSCPMark: ptr.To(numorstring.DSCPFromInt(23))},
			},
			IstioNamespace: istio.IstioNamespace,
			Scheme:         testScheme,
			ClusterID:      testClusterID,
		}
		desired = render()
	})

	It("renders the data plane when there is nothing to wait for", func() {
		objs := render()
		Expect(hasDaemonSet(objs, istio.IstioCNIDaemonSetName)).To(BeTrue())
		Expect(hasDaemonSet(objs, istio.IstioZTunnelDaemonSetName)).To(BeTrue())
	})

	It("holds a data plane image change while istiod still runs the old image", func() {
		cfg.Live = &istio.LiveWorkloads{
			Istiod:  oldIstiod(),
			CNI:     oldDaemonSet(istio.IstioCNIDaemonSetName),
			ZTunnel: oldDaemonSet(istio.IstioZTunnelDaemonSetName),
		}
		objs := render()

		Expect(hasDaemonSet(objs, istio.IstioCNIDaemonSetName)).To(BeFalse())
		Expect(hasDaemonSet(objs, istio.IstioZTunnelDaemonSetName)).To(BeFalse())
		istiod, err := rtest.GetResourceOfType[*appsv1.Deployment](objs, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(istiod.Spec.Template.Spec.Containers[0].Image).To(Equal(desiredDeployment().Spec.Template.Spec.Containers[0].Image))
		Expect(objs).To(ContainElement(HaveField("ObjectMeta.Name", "ztunnel")), "only the DaemonSet is held, not its RBAC")
	})

	DescribeTable("holds the data plane until every istiod pod runs the new image",
		func(status appsv1.DeploymentStatus) {
			istiod := rolledOut(desiredDeployment())
			istiod.Status = status
			cfg.Live = &istio.LiveWorkloads{
				Istiod:  istiod,
				ZTunnel: oldDaemonSet(istio.IstioZTunnelDaemonSetName),
			}
			Expect(hasDaemonSet(render(), istio.IstioZTunnelDaemonSetName)).To(BeFalse())
		},
		Entry("the Deployment controller has not seen the new spec",
			appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2}),
		Entry("a new pod is not updated yet",
			appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: 2, UpdatedReplicas: 1, AvailableReplicas: 2}),
		Entry("an old pod is still running",
			appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: 3, UpdatedReplicas: 2, AvailableReplicas: 3}),
		Entry("a new pod is not available yet",
			appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 1}),
	)

	It("rolls the data plane once istiod has rolled out the new image", func() {
		cfg.Live = &istio.LiveWorkloads{
			Istiod:  rolledOut(desiredDeployment()),
			CNI:     oldDaemonSet(istio.IstioCNIDaemonSetName),
			ZTunnel: oldDaemonSet(istio.IstioZTunnelDaemonSetName),
		}
		objs := render()
		Expect(hasDaemonSet(objs, istio.IstioCNIDaemonSetName)).To(BeTrue())
		Expect(hasDaemonSet(objs, istio.IstioZTunnelDaemonSetName)).To(BeTrue())
	})

	It("does not hold a DaemonSet whose image does not change", func() {
		cfg.Live = &istio.LiveWorkloads{
			Istiod:  oldIstiod(),
			CNI:     desiredDaemonSet(istio.IstioCNIDaemonSetName),
			ZTunnel: oldDaemonSet(istio.IstioZTunnelDaemonSetName),
		}
		objs := render()
		Expect(hasDaemonSet(objs, istio.IstioCNIDaemonSetName)).To(BeTrue())
		Expect(hasDaemonSet(objs, istio.IstioZTunnelDaemonSetName)).To(BeFalse())
	})

	It("creates a missing DaemonSet without waiting", func() {
		cfg.Live = &istio.LiveWorkloads{Istiod: oldIstiod()}
		objs := render()
		Expect(hasDaemonSet(objs, istio.IstioCNIDaemonSetName)).To(BeTrue())
		Expect(hasDaemonSet(objs, istio.IstioZTunnelDaemonSetName)).To(BeTrue())
	})
})
