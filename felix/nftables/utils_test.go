// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/nftables"
)

var _ = Describe("HostNftablesSupportedFn", func() {
	nftUsable := func(fam knftables.Family, name string, _ ...knftables.Option) (knftables.Interface, error) {
		return NewFake(fam, name), nil
	}
	nftUnusable := func(knftables.Family, string, ...knftables.Option) (knftables.Interface, error) {
		return nil, fmt.Errorf("nft version must be v1.0.1 or later")
	}
	kernel := func(version string) func() (*environment.Version, error) {
		return func() (*environment.Version, error) {
			return environment.MustParseVersion(version), nil
		}
	}
	kernelErr := func() (*environment.Version, error) {
		return nil, fmt.Errorf("cannot read /proc/version")
	}

	It("should report supported with a new enough kernel and a usable nft", func() {
		Expect(nftables.HostNftablesSupportedFn(nftUsable, kernel("5.14.0"))()).To(BeTrue())
	})

	It("should report unsupported on an old kernel (RHEL 8)", func() {
		Expect(nftables.HostNftablesSupportedFn(nftUsable, kernel("4.18.0"))()).To(BeFalse())
	})

	It("should report unsupported just below the minimum kernel", func() {
		Expect(nftables.HostNftablesSupportedFn(nftUsable, kernel("5.12.19"))()).To(BeFalse())
	})

	It("should report unsupported when the nft binary is missing or too old", func() {
		Expect(nftables.HostNftablesSupportedFn(nftUnusable, kernel("6.1.0"))()).To(BeFalse())
	})

	It("should report unsupported when the kernel version cannot be determined", func() {
		Expect(nftables.HostNftablesSupportedFn(nftUsable, kernelErr)()).To(BeFalse())
	})
})
