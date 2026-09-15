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
	"regexp"
	"strings"

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

// counterRejectFake wraps a knftables Fake but rejects transactions carrying the counter flag,
// standing in for a kernel older than 5.13.
type counterRejectFake struct {
	*knftables.Fake
}

func (f *counterRejectFake) Run(ctx context.Context, tx *knftables.Transaction) error {
	if strings.Contains(tx.String(), "counter ;") {
		return fmt.Errorf("/dev/stdin:1:1-50: Error: syntax error, unexpected counter")
	}
	return f.Fake.Run(ctx, tx)
}

var flowtableAddRe = regexp.MustCompile(`(?m)^add flowtable \S+ \S+ (\S+)`)

// oldKernelFake stands in for a pre-5.13 kernel whose flowtable update path ignores the counter
// flag that its add path rejects. Cleanup always fails, so probe state survives to the next
// detection.
type oldKernelFake struct {
	*knftables.Fake

	flowtables map[string]bool
}

func (f *oldKernelFake) Run(ctx context.Context, tx *knftables.Transaction) error {
	cmds := tx.String()
	if strings.Contains(cmds, "delete table") {
		return fmt.Errorf("/dev/stdin:1:1-50: Error: Could not process rule: Device or resource busy")
	}

	match := flowtableAddRe.FindStringSubmatch(cmds)
	if match == nil {
		return f.Fake.Run(ctx, tx)
	}

	name := match[1]
	if strings.Contains(cmds, "counter ;") && !f.flowtables[name] {
		return fmt.Errorf("/dev/stdin:1:1-50: Error: syntax error, unexpected counter")
	}
	f.flowtables[name] = true
	return nil
}

var _ = Describe("DetectFlowOffloadSupported", func() {
	It("reports both supported when the kernel accepts a flowtable with counters", func() {
		newDataplane := func(fam knftables.Family, name string, opts ...knftables.Option) (knftables.Interface, error) {
			return knftables.NewFake(fam, name), nil
		}
		supported, counter := DetectFlowOffloadSupported(newDataplane)
		Expect(supported).To(BeTrue())
		Expect(counter).To(BeTrue())
	})

	It("reports offload without counters when the kernel rejects the counter flag", func() {
		newDataplane := func(fam knftables.Family, name string, opts ...knftables.Option) (knftables.Interface, error) {
			return &counterRejectFake{Fake: knftables.NewFake(fam, name)}, nil
		}
		supported, counter := DetectFlowOffloadSupported(newDataplane)
		Expect(supported).To(BeTrue())
		Expect(counter).To(BeFalse())
	})

	It("reports unsupported when the kernel rejects the flowtable", func() {
		newDataplane := func(fam knftables.Family, name string, opts ...knftables.Option) (knftables.Interface, error) {
			return &flowtableRejectFake{Fake: knftables.NewFake(fam, name)}, nil
		}
		supported, counter := DetectFlowOffloadSupported(newDataplane)
		Expect(supported).To(BeFalse())
		Expect(counter).To(BeFalse())
	})

	It("does not read counter support off a probe flowtable left over from a previous detection", func() {
		fake := &oldKernelFake{Fake: knftables.NewFake(knftables.IPv4Family, "probe"), flowtables: map[string]bool{}}
		newDataplane := func(fam knftables.Family, name string, opts ...knftables.Option) (knftables.Interface, error) {
			return fake, nil
		}
		supported, counter := DetectFlowOffloadSupported(newDataplane)
		Expect(supported).To(BeTrue())
		Expect(counter).To(BeFalse())

		supported, counter = DetectFlowOffloadSupported(newDataplane)
		Expect(supported).To(BeTrue())
		Expect(counter).To(BeFalse())
	})

	It("reports unsupported when the nftables interface can't be created", func() {
		newDataplane := func(fam knftables.Family, name string, opts ...knftables.Option) (knftables.Interface, error) {
			return nil, fmt.Errorf("nft binary not found")
		}
		supported, counter := DetectFlowOffloadSupported(newDataplane)
		Expect(supported).To(BeFalse())
		Expect(counter).To(BeFalse())
	})
})
