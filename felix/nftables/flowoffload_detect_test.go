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
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"

	. "github.com/projectcalico/calico/felix/nftables"
)

// flowtableRejectFake wraps a knftables Fake but rejects every transaction, standing in for a
// kernel that lacks the nf_flow_table module.
type flowtableRejectFake struct {
	*knftables.Fake
}

func (f *flowtableRejectFake) Run(ctx context.Context, tx *knftables.Transaction) error {
	return fmt.Errorf("/dev/stdin:1:1-50: Error: Could not process rule: No such file or directory")
}

var _ = Describe("DetectFlowOffloadSupported", func() {
	It("returns true when the kernel accepts a flowtable", func() {
		newDataplane := func(fam knftables.Family, name string, opts ...knftables.Option) (knftables.Interface, error) {
			return knftables.NewFake(fam, name), nil
		}
		Expect(DetectFlowOffloadSupported(newDataplane)).To(BeTrue())
	})

	It("returns false when the kernel rejects the flowtable", func() {
		newDataplane := func(fam knftables.Family, name string, opts ...knftables.Option) (knftables.Interface, error) {
			return &flowtableRejectFake{Fake: knftables.NewFake(fam, name)}, nil
		}
		Expect(DetectFlowOffloadSupported(newDataplane)).To(BeFalse())
	})

	It("returns false when the nftables interface can't be created", func() {
		newDataplane := func(fam knftables.Family, name string, opts ...knftables.Option) (knftables.Interface, error) {
			return nil, fmt.Errorf("nft binary not found")
		}
		Expect(DetectFlowOffloadSupported(newDataplane)).To(BeFalse())
	})
})
