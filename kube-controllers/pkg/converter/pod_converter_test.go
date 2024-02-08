// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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

package converter_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
)

var _ = Describe("PodConverter", func() {

	c := converter.NewPodConverter()

	It("should convert a Pod with no labels", func() {
		pod := v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
			},
			Spec: v1.PodSpec{
				NodeName: "nodeA",
			},
		}

		wepDatas, err := c.Convert(&pod)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		Expect(len(wepDatas)).Should(Equal(1))
		wepData := wepDatas[0]

		// Assert workloadID.
		By("returning a WorkloadEndpointData with the correct key information", func() {
			Expect(wepData.PodName).To(Equal("podA"))
			Expect(wepData.Namespace).To(Equal("default"))
		})

		// Assert labels.
		By("returning a WorkloadEndpointData with the Namespace label present", func() {
			l := map[string]string{
				"projectcalico.org/namespace":    "default",
				"projectcalico.org/orchestrator": "k8s",
			}
			Expect(wepData.Labels).To(Equal(l))
		})
	})

	It("should convert a Pod with labels", func() {
		pod := v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Labels: map[string]string{
					"foo":   "bar",
					"roger": "rabbit",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "nodeA",
			},
		}

		wepDatas, err := c.Convert(&pod)

		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		Expect(len(wepDatas)).Should(Equal(1))
		wepData := wepDatas[0]

		// Assert that the returned name / namespace is correct.
		By("returning a WorkloadEndpointData with the correct key information", func() {
			Expect(wepData.PodName).To(Equal("podA"))
			Expect(wepData.Namespace).To(Equal("default"))
		})

		// Assert that GetKey returns the right value.
		key := c.GetKey(wepData)
		By("generating the correct key from the wepData", func() {
			Expect(key).To(Equal("default/podA"))
		})

		// Assert labels are correct.
		var labels = map[string]string{
			"foo":                            "bar",
			"roger":                          "rabbit",
			"projectcalico.org/orchestrator": "k8s",
			"projectcalico.org/namespace":    "default",
		}

		By("returning a WorkloadEndpointData with the pod's labels", func() {
			Expect(wepData.Labels).To(Equal(labels))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown conversion", func() {
		pod := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "default",
					Labels: map[string]string{
						"foo":   "bar",
						"roger": "rabbit",
					},
				},
				Spec: v1.PodSpec{
					NodeName: "nodeA",
				},
			},
		}

		wepDatas, err := c.Convert(pod)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		Expect(len(wepDatas)).Should(Equal(1))
		wepData := wepDatas[0]

		By("returning a WorkloadEndpointData with the correct name and namespace", func() {
			Expect(wepData.PodName).To(Equal("podA"))
			Expect(wepData.Namespace).To(Equal("default"))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown with non-Pod Obj", func() {
		pod := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: "just a string",
		}

		_, err := c.Convert(pod)
		By("generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should handle bad object conversion", func() {
		pod := "just a string"

		_, err := c.Convert(pod)
		By("generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should properly merge weps and WorkloadEndpointData", func() {
		expectedLabels := map[string]string{
			"key": "value",
			"foo": "bar",
		}
		wep := api.NewWorkloadEndpoint()
		wep.Name = "nodename-k8s-testwep-eth0"
		wep.Namespace = "default"
		wep.Spec.Pod = "testwep"
		wepData := converter.WorkloadEndpointData{
			PodName:   "testwep",
			Namespace: "default",
			Labels:    expectedLabels,
		}

		// Merge the wep and the updated data.
		converter.MergeWorkloadEndpointData(wep, wepData)

		By("updating the wep's labels", func() {
			Expect(wep.Labels).To(Equal(expectedLabels))
		})
	})
})
