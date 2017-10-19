// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/kube-controllers/pkg/converter"
	api "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

var _ = Describe("PodConverter", func() {

	c := converter.NewPodConverter()

	Context("Pod with no labels", func() {
		pod := v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
			},
			Spec: v1.PodSpec{
				NodeName: "nodeA",
			},
		}

		wepData, err := c.Convert(&pod)
		It("should not generate a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert workloadID.
		It("should return a WorkloadEndpointData with the correct Key", func() {
			Expect(wepData.(converter.WorkloadEndpointData).Key).To(Equal("default.podA"))
		})

		// Assert labels.
		It("should return a WorkloadEndpointData with the Namespace label present", func() {
			Expect(wepData.(converter.WorkloadEndpointData).Labels).To(Equal(map[string]string{"calico/k8s_ns": "default"}))
		})
	})

	Context("Pod with labels", func() {
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

		wepData, err := c.Convert(&pod)
		It("should not generate a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert that the returned Key is the same as the workload ID.
		It("should return a WorkloadEndpointData with the correct Key", func() {
			Expect(wepData.(converter.WorkloadEndpointData).Key).To(Equal("default.podA"))
		})

		// Assert that GetKey returns the right value.
		It("should support getting a Key with GetKey", func() {
			Expect(c.GetKey(wepData)).To(Equal("default.podA"))
		})

		// Assert labels are correct.
		var labels = map[string]string{
			"foo":           "bar",
			"roger":         "rabbit",
			"calico/k8s_ns": "default",
		}

		It("should return workloadendpoint with correct labels", func() {
			Expect(wepData.(converter.WorkloadEndpointData).Labels).To(Equal(labels))
		})
	})

	Context("should handle cache.DeletedFinalStateUnknown conversion", func() {
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

		wepData, err := c.Convert(pod)
		It("should not generate a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert that the returned Key is the same as the workload ID.
		It("should return a WorkloadEndpointData with the correct Key", func() {
			Expect(wepData.(converter.WorkloadEndpointData).Key).To(Equal("default.podA"))
		})
	})

	Context("should handle cache.DeletedFinalStateUnknown with non-Pod Obj", func() {
		pod := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: "just a string",
		}

		_, err := c.Convert(pod)
		It("should generate a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	Context("should handle bad ojbect conversion", func() {
		pod := "just a string"

		_, err := c.Convert(pod)
		It("should generate a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	Context("MergeWorkloadEndpointData", func() {
		expectedKey := "default.testwep"
		expectedLabels := map[string]string{
			"key": "value",
			"foo": "bar",
		}
		wep := api.NewWorkloadEndpoint()
		wep.Metadata.Workload = expectedKey
		wepData := converter.WorkloadEndpointData{
			Key:    "default.testwep",
			Labels: expectedLabels,
		}

		// Merge the wep and the updated data.
		converter.MergeWorkloadEndpointData(wep, wepData)

		It("should update the wep's labels", func() {
			Expect(wep.Metadata.Labels).To(Equal(expectedLabels))
		})
	})
})
