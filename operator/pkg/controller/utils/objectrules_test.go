// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
)

// fakeRules claims *v1.ConfigMap, standing in for a kind only a variant knows.
type fakeRules struct {
	podSpec    v1.PodSpec
	containers []v1.Container
	selector   map[string]string
	labelled   bool
}

func (r *fakeRules) owns(obj client.Object) bool {
	_, ok := obj.(*v1.ConfigMap)
	return ok
}

func (r *fakeRules) MergeState(desired client.Object, current runtime.Object) (client.Object, bool) {
	if !r.owns(desired) {
		return nil, false
	}
	return current.(client.Object), true
}

func (r *fakeRules) SkipOwnerReference(obj client.Object) bool { return r.owns(obj) }

func (r *fakeRules) PodSpecs(obj client.Object) []*v1.PodSpec {
	if !r.owns(obj) {
		return nil
	}
	return []*v1.PodSpec{&r.podSpec}
}

func (r *fakeRules) Containers(obj client.Object) []v1.Container {
	if !r.owns(obj) {
		return nil
	}
	return r.containers
}

func (r *fakeRules) SetNodeSelector(obj client.Object, key, value string) bool {
	if !r.owns(obj) {
		return false
	}
	if r.selector == nil {
		r.selector = map[string]string{}
	}
	r.selector[key] = value
	return true
}

func (r *fakeRules) CopyLabelsToPods(obj client.Object) bool {
	if !r.owns(obj) {
		return false
	}
	r.labelled = true
	return true
}

var _ = Describe("variant object rules", func() {
	var (
		rules   *fakeRules
		owned   = &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "owned"}}
		unowned = &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "unowned"}}
	)

	BeforeEach(func() {
		rules = &fakeRules{}
		RegisterVariantObjectRules(rules)
		DeferCleanup(func() { RegisterVariantObjectRules(nil) })
	})

	It("runs the core path when no variant registered", func() {
		RegisterVariantObjectRules(nil)
		desired := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "owned"}, Data: map[string]string{"a": "desired"}}
		current := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "owned"}, Data: map[string]string{"a": "current"}}
		Expect(mergeState(desired, current).(*v1.ConfigMap).Data).To(HaveKeyWithValue("a", "desired"))
	})

	It("lets the variant claim the merge of a kind it owns", func() {
		desired := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "owned"}, Data: map[string]string{"a": "desired"}}
		current := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "owned"}, Data: map[string]string{"a": "current"}}
		Expect(mergeState(desired, current).(*v1.ConfigMap).Data).To(HaveKeyWithValue("a", "current"))
	})

	It("leaves a kind the variant does not claim to the core merge", func() {
		desired := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "unowned", ResourceVersion: ""}}
		current := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "unowned", ResourceVersion: "7"}}
		Expect(mergeState(desired, current).GetResourceVersion()).To(Equal("7"))
	})

	It("modifies the pod specs the variant reports", func() {
		modifyPodSpec(owned, func(s *v1.PodSpec) { s.Hostname = "set" })
		Expect(rules.podSpec.Hostname).To(Equal("set"))
	})

	It("defaults probe fields on the containers the variant reports", func() {
		rules.containers = []v1.Container{{
			Name:           "c",
			ReadinessProbe: &v1.Probe{},
			LivenessProbe:  &v1.Probe{},
		}}
		setProbeTimeouts(owned)
		Expect(rules.containers[0].ReadinessProbe.PeriodSeconds).To(BeNumerically("==", 30))
		Expect(rules.containers[0].LivenessProbe.PeriodSeconds).To(BeNumerically("==", 60))
	})

	It("hands OS scheduling to the variant for a kind it owns", func() {
		ensureOSSchedulingRestrictions(owned, rmeta.OSTypeLinux)
		Expect(rules.selector).To(HaveKeyWithValue("kubernetes.io/os", "linux"))
	})

	It("does not consult the variant when the OS is unrestricted", func() {
		ensureOSSchedulingRestrictions(owned, rmeta.OSTypeAny)
		Expect(rules.selector).To(BeNil())
	})

	It("hands pod labelling to the variant for a kind it owns", func() {
		setStandardSelectorAndLabels(owned, nil, false)
		Expect(rules.labelled).To(BeTrue())
	})

	It("leaves a kind the variant does not own alone", func() {
		ensureOSSchedulingRestrictions(unowned, rmeta.OSTypeLinux)
		Expect(rules.selector).To(BeNil())
		Expect(rules.labelled).To(BeFalse())
	})
})
