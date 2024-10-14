// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package routerule_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	. "github.com/projectcalico/calico/felix/routerule"
)

var _ = Describe("RouteRule Rule build cases", func() {
	var nlRule *netlink.Rule
	BeforeEach(func() {
		nlRule = netlink.NewRule()
	})
	It("should has correct rule on new rule", func() {
		Expect(NewRule(4, 100).NetLinkRule().Family).To(Equal(unix.AF_INET))
		Expect(NewRule(6, 100).NetLinkRule().Family).To(Equal(unix.AF_INET6))
		Expect(NewRule(4, 100).NetLinkRule().Priority).To(Equal(100))
	})
	It("should panic if ipVersion is invalid", func() {
		Expect(func() {
			_ = NewRule(0, 100)
		}).To(Panic())
	})
	It("should construct rule based on netlink rule", func() {
		Expect(FromNetlinkRule(nlRule).NetLinkRule()).To(Equal(nlRule))
	})
	It("should construct rule with correct value", func() {
		ip := mustParseCIDR("10.0.1.0/26")
		Expect(NewRule(4, 100).MatchFWMark(0x400).NetLinkRule().Mark).To(Equal(0x400))
		Expect(NewRule(4, 100).MatchFWMark(0x400).NetLinkRule().Mask).To(Equal(0x400))
		Expect(NewRule(4, 100).Not().NetLinkRule().Invert).To(Equal(true))
		Expect(NewRule(4, 100).GoToTable(10).NetLinkRule().Table).To(Equal(10))
		Expect(NewRule(4, 100).MatchSrcAddress(*ip).NetLinkRule().Src.String()).To(Equal("10.0.1.0/26"))
		ipv6 := mustParseCIDR("2002::1234:abcd:ffff:c0a8:101/128")
		Expect(NewRule(6, 100).MatchSrcAddress(*ipv6).NetLinkRule().Src.String()).
			To(Equal("2002::1234:abcd:ffff:c0a8:101/128"))
		Expect(NewRule(4, 100).Not().
			MatchFWMark(0x400).
			MatchSrcAddress(*ip).
			GoToTable(10).NetLinkRule()).
			To(Equal(&netlink.Rule{
				Priority:          100,
				Family:            unix.AF_INET,
				Src:               mustParseCIDR("10.0.1.0/26"),
				Mark:              0x400,
				Mask:              0x400,
				Table:             10,
				Invert:            true,
				Goto:              -1,
				Flow:              -1,
				SuppressIfgroup:   -1,
				SuppressPrefixlen: -1,
			}))
	})
	It("should ignore wrong values", func() {
		ipv6 := mustParseCIDR("2002::1234:abcd:ffff:c0a8:101/64")
		Expect(NewRule(4, 100).MatchSrcAddress(*ipv6).NetLinkRule().Src).To(BeNil())
	})
})

var _ = Describe("RouteRule Rule match cases", func() {
	var r0, r1 *Rule
	BeforeEach(func() {
		r0 = FromNetlinkRule(&netlink.Rule{
			Priority:          100,
			Family:            unix.AF_INET,
			Src:               mustParseCIDR("10.0.1.0/26"),
			Mark:              0x400,
			Mask:              0x400,
			Table:             10,
			Invert:            true,
			Goto:              -1,
			Flow:              -1,
			SuppressIfgroup:   -1,
			SuppressPrefixlen: -1,
		})

		r1 = FromNetlinkRule(&netlink.Rule{
			Priority:          100,
			Family:            unix.AF_INET,
			Src:               mustParseCIDR("10.0.1.0/26"),
			Mark:              0x400,
			Mask:              0x400,
			Table:             20,
			Invert:            true,
			Goto:              0,
			Flow:              0,
			SuppressIfgroup:   0,
			SuppressPrefixlen: 0,
		})

	})
	It("should match on src fwmark table", func() {
		Expect(RulesMatchSrcFWMark(r0, r1)).To(Equal(true))
		Expect(RulesMatchSrcFWMarkTable(r0, r1)).To(Equal(false))

		new := r1.Copy()
		new.NetLinkRule().Invert = false
		Expect(RulesMatchSrcFWMark(r0, new)).To(Equal(false))
		Expect(RulesMatchSrcFWMarkTable(r0, new)).To(Equal(false))

		new = r1.Copy()
		new.NetLinkRule().Table = 10
		Expect(RulesMatchSrcFWMark(r0, new)).To(Equal(true))
		Expect(RulesMatchSrcFWMarkTable(r0, new)).To(Equal(true))

		new = r1.Copy()
		new.NetLinkRule().Src = mustParseCIDR("10.0.2.0/26")
		Expect(RulesMatchSrcFWMark(r0, new)).To(Equal(false))
		Expect(RulesMatchSrcFWMarkTable(r0, new)).To(Equal(false))

		new = r1.Copy()
		new.NetLinkRule().Mark = 0x100
		Expect(RulesMatchSrcFWMark(r0, new)).To(Equal(false))
		Expect(RulesMatchSrcFWMarkTable(r0, new)).To(Equal(false))
	})
})
