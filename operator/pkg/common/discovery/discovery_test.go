// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package discovery

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("provider discovery", func() {
	BeforeEach(func() {
	})

	It("should not detect a provider if with no info", func() {
		c := fake.NewClientset()
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderNone))
	})

	It("should detect DockerEE if a Master Node has labels prefixed with com.docker.ucp", func() {
		c := fake.NewClientset(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "master1",
				Labels: map[string]string{
					"node-role.kubernetes.io/master":    "",
					"com.docker.ucp.orchestrator.swarm": "true",
				},
			},
		})
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderDockerEE))
	})

	It("should detect openshift based on API resource clusterversion.config.openshift.io existence", func() {
		c := fake.NewClientset()
		c.Resources = []*metav1.APIResourceList{{
			GroupVersion: "config.openshift.io/v1",
			APIResources: []metav1.APIResource{{SingularName: "clusterversion", Name: "clusterversions", Kind: "ClusterVersion"}},
		}}
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderOpenShift))
	})

	It("should detect non-openshift based on API resource clusterversion.config.openshift.io absense, however some other config.openshift.io resources are present", func() {
		c := fake.NewClientset()
		c.Resources = []*metav1.APIResourceList{{
			GroupVersion: "config.openshift.io/v1",
			APIResources: []metav1.APIResource{{SingularName: "dummy", Name: "dummies", Kind: "Dummy"}},
		}}
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderNone))
	})

	It("should detect GKE based on API resource networking.gke.io existence", func() {
		c := fake.NewClientset(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gke-node",
				Labels: map[string]string{
					"cloud.google.com/gke-nodepool": "default-pool",
				},
			},
		})
		c.Resources = []*metav1.APIResourceList{{
			GroupVersion: "networking.gke.io/v1",
		}}
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderGKE))
	})

	It("should not detect GKE based only on API resource networking.gke.io existence", func() {
		c := fake.NewClientset()
		c.Resources = []*metav1.APIResourceList{{
			GroupVersion: "networking.gke.io/v1",
		}}
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderNone))
	})

	It("should detect TKG based on API resource core.tanzu.vmware.com existence", func() {
		c := fake.NewClientset()
		c.Resources = []*metav1.APIResourceList{{
			GroupVersion: "core.tanzu.vmware.com/v1alpha2",
		}}
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderTKG))
	})

	It("should detect EKS based on eks-certificates-controller ConfigMap", func() {
		c := fake.NewClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "eks-certificates-controller",
				Namespace: "kube-system",
			},
		})
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderEKS))
	})
	It("should detect EKS based on aws-auth ConfigMap", func() {
		c := fake.NewClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "aws-auth",
				Namespace: "kube-system",
			},
		})
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderEKS))
	})
	It("should detect EKS based on kube-dns service label", func() {
		c := fake.NewClientset(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-dns",
				Namespace: "kube-system",
				Labels: map[string]string{
					"eks.amazonaws.com/component": "kube-dns",
				},
			},
		})
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderEKS))
	})

	It("should detect RKE2 based on presence of kube-system/rke2 ConfigMap", func() {
		c := fake.NewClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rke2",
				Namespace: "kube-system",
			},
		})
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderRKE2))
	})

	It("should detect RKE2 based on presence of kube-system/rke2-coredns-rke2-coredns Service", func() {
		c := fake.NewClientset(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rke2-coredns-rke2-coredns",
				Namespace: "kube-system",
			},
		})
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderRKE2))
	})

	It("should detect KinD if a Node has ProviderID prefixed with kind://", func() {
		c := fake.NewClientset(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kind-worker",
			},
			Spec: corev1.NodeSpec{
				ProviderID: "kind://docker/kind/kind-worker",
			},
		})
		p, e := AutoDiscoverProvider(context.Background(), c)
		Expect(e).To(BeNil())
		Expect(p).To(Equal(operatorv1.ProviderKind))
	})
})
