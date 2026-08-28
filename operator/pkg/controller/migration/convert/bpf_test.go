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

package convert

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kscheme "k8s.io/client-go/kubernetes/scheme"
)

var (
	cmName = render.K8sSvcEndpointConfigMapName
	cmData = map[string]string{
		"KUBERNETES_SERVICE_HOST": "1.1.1.1",
		"KUBERNETES_SERVICE_PORT": "1234",
	}
	endPointCM = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: "kube-system",
		},
		Data: cmData,
	}
)

func getEndPointCM(c *components, ns string) (map[string]string, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: ns,
	}
	err := c.client.Get(ctx, cmNamespacedName, cm)
	if err != nil {
		return nil, err
	}
	return cm.Data, nil
}

var _ = Describe("convert bpf config", func() {
	var (
		comps  = emptyComponents()
		i      = &operatorv1.Installation{}
		f      = &v3.FelixConfiguration{}
		scheme = kscheme.Scheme
	)

	BeforeEach(func() {
		comps = emptyComponents()
		i = &operatorv1.Installation{}
		f = emptyFelixConfig()
		Expect(apis.AddToScheme(scheme, false)).ToNot(HaveOccurred())
	})

	It("converts bpfenabled felixconfig set to true", func() {
		bpfEnabled := true
		f.Spec.BPFEnabled = &bpfEnabled
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()
		err := handleBPF(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(*i.Spec.CalicoNetwork.LinuxDataplane).To(BeEquivalentTo(operatorv1.LinuxDataplaneBPF))
		Expect(i.Spec.CalicoNetwork.HostPorts).To(BeNil())
		data, err := getEndPointCM(&comps, common.OperatorNamespace())
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(cmData))
	})

	It("converts bpfenabled felixconfig set to false", func() {
		bpfEnabled := false
		f.Spec.BPFEnabled = &bpfEnabled
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()
		err := handleBPF(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
		data, err := getEndPointCM(&comps, "kube-system")
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(cmData))
		data, err = getEndPointCM(&comps, common.OperatorNamespace())
		Expect(err).To(HaveOccurred())
		Expect(data).To(BeNil())
	})

	It("check with no felixconfig", func() {
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM).Build()
		err := handleBPF(&comps, i)
		Expect(err).To(HaveOccurred())
		data, err := getEndPointCM(&comps, "kube-system")
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(cmData))
	})

	It("converts dataplane to BPF given bpfenabled env var set to true", func() {
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()
		comps.node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
			Name:  "FELIX_BPFENABLED",
			Value: "true",
		}}
		err := handleBPF(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(*i.Spec.CalicoNetwork.LinuxDataplane).To(BeEquivalentTo(operatorv1.LinuxDataplaneBPF))
		Expect(i.Spec.CalicoNetwork.HostPorts).To(BeNil())
		data, err := getEndPointCM(&comps, common.OperatorNamespace())
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(cmData))
	})

	It("converts dataplane to empty given bpfenabled env var set to false", func() {
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(endPointCM, f).Build()
		comps.node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
			Name:  "FELIX_BPFENABLED",
			Value: "false",
		}}
		err := handleBPF(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
		data, err := getEndPointCM(&comps, "kube-system")
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(cmData))
		data, err = getEndPointCM(&comps, common.OperatorNamespace())
		Expect(err).To(HaveOccurred())
		Expect(data).To(BeNil())
	})

	It("converts dataplane to empty given bpfenabled env var set not set", func() {
		comps.client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(endPointCM, f).Build()
		comps.node.Spec.Template.Spec.Containers[0].Env = nil
		err := handleBPF(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
		data, err := getEndPointCM(&comps, "kube-system")
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(cmData))
		data, err = getEndPointCM(&comps, common.OperatorNamespace())
		Expect(err).To(HaveOccurred())
		Expect(data).To(BeNil())
	})

	It("returns error when configmap is not present", func() {
		bpfEnabled := true
		f.Spec.BPFEnabled = &bpfEnabled
		comps.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(f).Build()
		err := handleBPF(&comps, i)
		Expect(err).To(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
	})
})
