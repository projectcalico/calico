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

package components

import (
	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/projectcalico/calico/operator/api/v1"
)

var _ = Describe("ApplyOverrides", func() {
	deployment := func(namespace string) *appsv1.Deployment {
		return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: namespace}}
	}
	overrides := &operator.CalicoKubeControllersDeployment{Spec: &operator.CalicoKubeControllersDeploymentSpec{MinReadySeconds: ptr.To[int32](17)}}

	It("applies the overrides to the object in the target's namespace", func() {
		inTarget, other := deployment("target"), deployment("other")

		ApplyOverrides([]client.Object{other, inTarget}, []OverrideTarget{Target[*appsv1.Deployment]("target", "workload", overrides)})

		Expect(inTarget.Spec.MinReadySeconds).To(Equal(int32(17)))
		Expect(other.Spec.MinReadySeconds).To(BeZero())
	})

	It("skips a target whose object isn't rendered in its namespace", func() {
		other := deployment("other")

		ApplyOverrides([]client.Object{other}, []OverrideTarget{Target[*appsv1.Deployment]("target", "workload", overrides)})

		Expect(other.Spec.MinReadySeconds).To(BeZero())
	})
})

var _ = Describe("ApplyEnvoyProxyServiceOverrides", func() {
	It("creates the Kubernetes provider an EnvoyProxy doesn't have yet", func() {
		ep := &envoyapi.EnvoyProxy{}

		ApplyEnvoyProxyServiceOverrides(ep, &operator.GatewayService{Spec: &operator.GatewayServiceSpec{LoadBalancerClass: ptr.To("lb")}})

		Expect(ep.Spec.Provider.Type).To(Equal(envoyapi.EnvoyProxyProviderTypeKubernetes))
		Expect(ep.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerClass).To(HaveValue(Equal("lb")))
	})
})
