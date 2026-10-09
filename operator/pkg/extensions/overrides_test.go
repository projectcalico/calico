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

package extensions_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/extensions/extensionstest"
	"github.com/projectcalico/calico/operator/pkg/render"
	rcomp "github.com/projectcalico/calico/operator/pkg/render/common/components"
)

const workloadName = "workload"

var overriddenResources = corev1.ResourceRequirements{
	Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("777m")},
}

// overridableComponent renders one deployment with a "base" container, and
// declares overrides that set resources on "base" and on "added".
type overridableComponent struct {
	extensionstest.StubComponent
}

func (overridableComponent) ObjectsBeforeOverrides() ([]client.Object, []client.Object) {
	return []client.Object{&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: workloadName},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "base"}},
		}}},
	}}, nil
}

func (overridableComponent) OverrideTargets() []rcomp.OverrideTarget {
	overrides := &operatorv1.CalicoKubeControllersDeployment{
		Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
			Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
				Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
					Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{
						{Name: "base", Resources: overriddenResources.DeepCopy()},
						{Name: "added", Resources: overriddenResources.DeepCopy()},
					},
				},
			},
		},
	}
	return []rcomp.OverrideTarget{rcomp.Target[*appsv1.Deployment](workloadName, overrides)}
}

func (c overridableComponent) Objects() ([]client.Object, []client.Object) {
	return render.ObjectsWithOverrides(c)
}

// stubOnly hides the Overridable methods, so Decorate sees a plain component.
type stubOnly struct {
	extensionstest.StubComponent
}

func addContainer(create, del []client.Object) ([]client.Object, []client.Object) {
	dep := extensions.MustFindObject[*appsv1.Deployment](create, workloadName)
	dep.Spec.Template.Spec.Containers = append(dep.Spec.Template.Spec.Containers, corev1.Container{Name: "added"})
	return create, del
}

func copyWorkload(create, del []client.Object) ([]client.Object, []client.Object) {
	cp := extensions.MustFindObject[*appsv1.Deployment](create, workloadName).DeepCopy()
	cp.Name = "copy"
	return append(create, cp), del
}

func containerResources(objs []client.Object, workload string) map[string]corev1.ResourceRequirements {
	out := map[string]corev1.ResourceRequirements{}
	for _, c := range extensions.MustFindObject[*appsv1.Deployment](objs, workload).Spec.Template.Spec.Containers {
		out[c.Name] = c.Resources
	}
	return out
}

var _ = Describe("Decorate with an Overridable component", func() {
	enterprise := inputsFor(operatorv1.CalicoEnterprise)

	It("applies the overrides to containers the modifier adds", func() {
		c := extensions.Decorate(overridableComponent{}, enterprise, operatorv1.CalicoEnterprise, addContainer)

		create, _ := c.Objects()
		Expect(containerResources(create, workloadName)).To(Equal(map[string]corev1.ResourceRequirements{
			"base":  overriddenResources,
			"added": overriddenResources,
		}))
	})

	It("misses a modifier's container when the overrides go on inside the render", func() {
		base := overridableComponent{}
		objs, _ := base.Objects()
		plain := stubOnly{extensionstest.StubComponent{Create: objs}}
		c := extensions.Decorate(plain, enterprise, operatorv1.CalicoEnterprise, addContainer)

		create, _ := c.Objects()
		Expect(containerResources(create, workloadName)).To(Equal(map[string]corev1.ResourceRequirements{
			"base":  overriddenResources,
			"added": {},
		}))
	})

	It("derives objects from the overridden ones", func() {
		c := extensions.Decorate(overridableComponent{}, enterprise, operatorv1.CalicoEnterprise, addContainer, extensions.WithDerive(copyWorkload))

		create, _ := c.Objects()
		Expect(containerResources(create, "copy")).To(HaveKeyWithValue("added", overriddenResources))
	})

	It("applies the overrides when the Installation asks for another variant", func() {
		c := extensions.Decorate(overridableComponent{}, inputsFor(operatorv1.Calico), operatorv1.CalicoEnterprise, addContainer)

		create, _ := c.Objects()
		Expect(containerResources(create, workloadName)).To(Equal(map[string]corev1.ResourceRequirements{
			"base": overriddenResources,
		}))
	})
})
