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
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/extensions"
)

// startupStub is a variant that contributes controllers and nothing else.
type startupStub struct {
	controllers []extensions.Controller
}

func (s startupStub) VerifyAPIsExist(kubernetes.Interface) error {
	return nil
}

func (s startupStub) VerifyClusterState(context.Context, kubernetes.Interface, bool, bool) error {
	return nil
}

func (s startupStub) ProtectedNamespaces() []string {
	return nil
}

func (s startupStub) MultiTenant() bool {
	return false
}

func (s startupStub) Cloud() bool {
	return false
}

func (s startupStub) Controllers() []extensions.Controller {
	return s.controllers
}

func optionsWith(controllers ...extensions.Controller) extensions.ControllerOptions {
	return extensions.ControllerOptions{
		Extensions: extensions.New(extensions.Set{Startup: startupStub{controllers: controllers}}),
	}
}

var _ = Describe("AddControllers", func() {
	It("adds every contributed controller, in order", func() {
		var added []string
		add := func(name string) extensions.Controller {
			return extensions.Controller{Name: name, Add: func(ctrl.Manager, extensions.ControllerOptions) error {
				added = append(added, name)
				return nil
			}}
		}

		Expect(optionsWith(add("First"), add("Second")).AddControllers(nil)).NotTo(HaveOccurred())
		Expect(added).To(Equal([]string{"First", "Second"}))
	})

	It("passes the options through to the controller", func() {
		var got extensions.ControllerOptions
		opts := optionsWith(extensions.Controller{Name: "Monitor", Add: func(_ ctrl.Manager, o extensions.ControllerOptions) error {
			got = o
			return nil
		}})
		opts.Variant = operatorv1.CalicoEnterprise

		Expect(opts.AddControllers(nil)).NotTo(HaveOccurred())
		Expect(got.Variant).To(Equal(operatorv1.CalicoEnterprise))
	})

	It("names the controller that failed", func() {
		opts := optionsWith(extensions.Controller{
			Name: "Monitor",
			Add:  func(ctrl.Manager, extensions.ControllerOptions) error { return errors.New("no watch") },
		})

		Expect(opts.AddControllers(nil)).To(MatchError(ContainSubstring("controller Monitor: no watch")))
	})

	It("does nothing when the variant contributes none", func() {
		Expect(extensions.ControllerOptions{}.AddControllers(nil)).NotTo(HaveOccurred())
	})
})
