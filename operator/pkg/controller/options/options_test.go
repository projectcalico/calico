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

package options_test

import (
	"errors"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ctrl "sigs.k8s.io/controller-runtime"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
)

func TestOptions(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "pkg/controller/options Suite")
}

var _ = Describe("AddControllers", func() {
	It("adds every contributed controller, in order", func() {
		var added []string
		add := func(name string) options.Controller {
			return options.Controller{Name: name, Add: func(ctrl.Manager, options.ControllerOptions) error {
				added = append(added, name)
				return nil
			}}
		}
		opts := options.ControllerOptions{Controllers: []options.Controller{add("First"), add("Second")}}

		Expect(opts.AddControllers(nil)).NotTo(HaveOccurred())
		Expect(added).To(Equal([]string{"First", "Second"}))
	})

	It("passes the options through to the controller", func() {
		var got options.ControllerOptions
		opts := options.ControllerOptions{
			Variant: operatorv1.CalicoEnterprise,
			Controllers: []options.Controller{{Name: "Monitor", Add: func(_ ctrl.Manager, o options.ControllerOptions) error {
				got = o
				return nil
			}}},
		}

		Expect(opts.AddControllers(nil)).NotTo(HaveOccurred())
		Expect(got.Variant).To(Equal(operatorv1.CalicoEnterprise))
	})

	It("names the controller that failed", func() {
		opts := options.ControllerOptions{Controllers: []options.Controller{{
			Name: "Monitor",
			Add:  func(ctrl.Manager, options.ControllerOptions) error { return errors.New("no watch") },
		}}}

		Expect(opts.AddControllers(nil)).To(MatchError(ContainSubstring("controller Monitor: no watch")))
	})

	It("does nothing when the variant contributes none", func() {
		Expect(options.ControllerOptions{}.AddControllers(nil)).NotTo(HaveOccurred())
	})
})
