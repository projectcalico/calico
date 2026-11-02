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

package daemon

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/components"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("Options", func() {
	Describe("acceptsVariant", func() {
		It("accepts only Calico when the caller named no variants", func() {
			opts := Options{}
			Expect(opts.acceptsVariant(operatorv1.Calico)).To(BeTrue())
			Expect(opts.acceptsVariant(operatorv1.CalicoEnterprise)).To(BeFalse())
		})

		It("accepts every variant the caller named", func() {
			opts := Options{Variants: []operatorv1.ProductVariant{operatorv1.Calico, operatorv1.CalicoEnterprise}}
			Expect(opts.acceptsVariant(operatorv1.Calico)).To(BeTrue())
			Expect(opts.acceptsVariant(operatorv1.CalicoEnterprise)).To(BeTrue())
		})

		It("rejects a variant missing from a non-empty list", func() {
			opts := Options{Variants: []operatorv1.ProductVariant{operatorv1.CalicoEnterprise}}
			Expect(opts.acceptsVariant(operatorv1.Calico)).To(BeFalse())
		})
	})

	Describe("imageSet", func() {
		It("serves the core set under both of its names", func() {
			opts := Options{}
			for _, name := range []string{"list", "listcalico"} {
				cmpnts, ok := opts.imageSet(name)
				Expect(ok).To(BeTrue(), name)
				Expect(cmpnts).To(Equal(components.CalicoImages), name)
			}
		})

		It("rejects a name nobody registered", func() {
			_, ok := Options{}.imageSet("listenterprise")
			Expect(ok).To(BeFalse())
		})

		It("serves a name the caller registered", func() {
			extra := []components.Component{{Version: "1.2.3"}}
			cmpnts, ok := Options{Images: map[string][]components.Component{"listenterprise": extra}}.imageSet("listenterprise")
			Expect(ok).To(BeTrue())
			Expect(cmpnts).To(Equal(extra))
		})

		It("lets the caller replace the core set", func() {
			extra := []components.Component{{Version: "1.2.3"}}
			cmpnts, ok := Options{Images: map[string][]components.Component{"list": extra}}.imageSet("list")
			Expect(ok).To(BeTrue())
			Expect(cmpnts).To(Equal(extra))
		})
	})

	Describe("Collectors", func() {
		It("registers nothing when the caller supplied no factory", func() {
			Expect(Options{}.Collectors).To(BeNil())
		})

		It("builds the caller's collectors from the client it is given", func() {
			var got client.Client
			collector := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_metric"})
			opts := Options{Collectors: func(c client.Client) []prometheus.Collector {
				got = c
				return []prometheus.Collector{collector}
			}}

			cli := ctrlrfake.DefaultFakeClientBuilder(runtime.NewScheme()).Build()
			Expect(opts.Collectors(cli)).To(ConsistOf(collector))
			Expect(got).To(Equal(cli))
		})
	})

	Describe("afterParse", func() {
		It("reports nothing handled when the caller registered no hook", func() {
			handled, err := Options{}.afterParse()
			Expect(handled).To(BeFalse())
			Expect(err).NotTo(HaveOccurred())
		})

		It("returns what the caller's hook reports", func() {
			handled, err := Options{AfterParse: func() (bool, error) { return true, nil }}.afterParse()
			Expect(handled).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})

		It("surfaces the hook's error", func() {
			hookErr := errors.New("bad flag")
			handled, err := Options{AfterParse: func() (bool, error) { return true, hookErr }}.afterParse()
			Expect(handled).To(BeTrue())
			Expect(err).To(MatchError(hookErr))
		})
	})
})
