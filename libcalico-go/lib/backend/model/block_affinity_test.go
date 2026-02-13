// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package model_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v4 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	k8slabels "k8s.io/apimachinery/pkg/labels"

	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("BlockAffinity labels and selectors", func() {
	Context("EnsureBlockAffinityLabels", func() {
		It("should initialize labels and set hostname hash, affinity type, and IPv4 version", func() {
			ba := &v3.BlockAffinity{
				Spec: v3.BlockAffinitySpec{
					Node: "node-a",
					Type: model.IPAMAffinityTypeHost,
					CIDR: "10.0.0.0/24",
				},
			}
			// Ensure labels are initially nil to exercise initialization path.
			Expect(ba.Labels).To(BeNil())

			model.EnsureBlockAffinityLabels(ba)

			Expect(ba.Labels).ToNot(BeNil())
			Expect(ba.Labels[v4.LabelHostnameHash]).ToNot(BeEmpty())
			Expect(ba.Labels[v4.LabelAffinityType]).To(Equal(model.IPAMAffinityTypeHost))
			Expect(ba.Labels[v4.LabelIPVersion]).To(Equal("4"))
		})

		It("should preserve existing custom labels while overwriting Calico-managed ones", func() {
			ba := &v3.BlockAffinity{
				Spec: v3.BlockAffinitySpec{
					Node: "node-b",
					Type: model.IPAMAffinityTypeVirtual,
					CIDR: "2001:db8::/64",
				},
			}
			// Pre-populate with a custom label to ensure it's preserved.
			ba.Labels = map[string]string{"custom": "keep"}

			model.EnsureBlockAffinityLabels(ba)

			Expect(ba.Labels["custom"]).To(Equal("keep"))
			Expect(ba.Labels[v4.LabelHostnameHash]).ToNot(BeEmpty())
			Expect(ba.Labels[v4.LabelAffinityType]).To(Equal(model.IPAMAffinityTypeVirtual))
			Expect(ba.Labels[v4.LabelIPVersion]).To(Equal("6"))
		})

		It("should generate different non-empty hostname hashes for different nodes", func() {
			a := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "node-a", Type: model.IPAMAffinityTypeHost, CIDR: "10.0.0.0/26"}}
			b := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "node-b", Type: model.IPAMAffinityTypeHost, CIDR: "10.0.1.0/26"}}

			model.EnsureBlockAffinityLabels(a)
			model.EnsureBlockAffinityLabels(b)

			ha := a.Labels[v4.LabelHostnameHash]
			hb := b.Labels[v4.LabelHostnameHash]
			Expect(ha).ToNot(BeEmpty())
			Expect(hb).ToNot(BeEmpty())
			Expect(ha).ToNot(Equal(hb))
		})
	})

	Context("CalculateBlockAffinityLabelSelector", func() {
		It("should return nil selector when options are empty", func() {
			sel := model.CalculateBlockAffinityLabelSelector(model.BlockAffinityListOptions{})
			Expect(sel).To(BeNil())
		})

		It("should build selector matching hostname hash only", func() {
			opts := model.BlockAffinityListOptions{Host: "node-a"}
			sel := model.CalculateBlockAffinityLabelSelector(opts)
			Expect(sel).ToNot(BeNil())

			ba := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "node-a", Type: model.IPAMAffinityTypeHost, CIDR: "10.0.0.0/24"}}
			model.EnsureBlockAffinityLabels(ba)
			Expect(sel.Matches(k8slabels.Set(ba.Labels))).To(BeTrue())

			// Different host should not match.
			other := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "node-b", Type: model.IPAMAffinityTypeHost, CIDR: "10.0.0.0/24"}}
			model.EnsureBlockAffinityLabels(other)
			Expect(sel.Matches(k8slabels.Set(other.Labels))).To(BeFalse())
		})

		It("should build selector for affinity type only", func() {
			opts := model.BlockAffinityListOptions{AffinityType: model.IPAMAffinityTypeVirtual}
			sel := model.CalculateBlockAffinityLabelSelector(opts)
			Expect(sel).ToNot(BeNil())

			v := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "n", Type: model.IPAMAffinityTypeVirtual, CIDR: "10.0.0.0/24"}}
			model.EnsureBlockAffinityLabels(v)
			Expect(sel.Matches(k8slabels.Set(v.Labels))).To(BeTrue())

			h := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "n", Type: model.IPAMAffinityTypeHost, CIDR: "10.0.0.0/24"}}
			model.EnsureBlockAffinityLabels(h)
			Expect(sel.Matches(k8slabels.Set(h.Labels))).To(BeFalse())
		})

		It("should build selector for IP version only", func() {
			opts := model.BlockAffinityListOptions{IPVersion: 6}
			sel := model.CalculateBlockAffinityLabelSelector(opts)
			Expect(sel).ToNot(BeNil())

			v6 := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "n", Type: model.IPAMAffinityTypeHost, CIDR: "2001:db8::/64"}}
			model.EnsureBlockAffinityLabels(v6)
			Expect(sel.Matches(k8slabels.Set(v6.Labels))).To(BeTrue())

			v4b := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "n", Type: model.IPAMAffinityTypeHost, CIDR: "10.0.0.0/24"}}
			model.EnsureBlockAffinityLabels(v4b)
			Expect(sel.Matches(k8slabels.Set(v4b.Labels))).To(BeFalse())
		})

		It("should combine host, affinity type, and IP version", func() {
			opts := model.BlockAffinityListOptions{Host: "node-x", AffinityType: model.IPAMAffinityTypeHost, IPVersion: 4}
			sel := model.CalculateBlockAffinityLabelSelector(opts)
			Expect(sel).ToNot(BeNil())

			match := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "node-x", Type: model.IPAMAffinityTypeHost, CIDR: "10.0.0.0/24"}}
			model.EnsureBlockAffinityLabels(match)
			Expect(sel.Matches(k8slabels.Set(match.Labels))).To(BeTrue())

			wrongHost := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "node-y", Type: model.IPAMAffinityTypeHost, CIDR: "10.0.0.0/24"}}
			model.EnsureBlockAffinityLabels(wrongHost)
			Expect(sel.Matches(k8slabels.Set(wrongHost.Labels))).To(BeFalse())

			wrongType := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "node-x", Type: model.IPAMAffinityTypeVirtual, CIDR: "10.0.0.0/24"}}
			model.EnsureBlockAffinityLabels(wrongType)
			Expect(sel.Matches(k8slabels.Set(wrongType.Labels))).To(BeFalse())

			wrongIPVer := &v3.BlockAffinity{Spec: v3.BlockAffinitySpec{Node: "node-x", Type: model.IPAMAffinityTypeHost, CIDR: "2001:db8::/64"}}
			model.EnsureBlockAffinityLabels(wrongIPVer)
			Expect(sel.Matches(k8slabels.Set(wrongIPVer.Labels))).To(BeFalse())
		})
	})
})
