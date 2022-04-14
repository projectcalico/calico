// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.
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

package iptables_test

import (
	"github.com/projectcalico/calico/felix/detector"
	. "github.com/projectcalico/calico/felix/iptables"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Actions",
	func(features detector.Features, action Action, expRendering string) {
		Expect(action.ToFragment(&features)).To(Equal(expRendering))
	},
	Entry("GotoAction", detector.Features{}, GotoAction{Target: "cali-abcd"}, "--goto cali-abcd"),
	Entry("JumpAction", detector.Features{}, JumpAction{Target: "cali-abcd"}, "--jump cali-abcd"),
	Entry("ReturnAction", detector.Features{}, ReturnAction{}, "--jump RETURN"),
	Entry("DropAction", detector.Features{}, DropAction{}, "--jump DROP"),
	Entry("AcceptAction", detector.Features{}, AcceptAction{}, "--jump ACCEPT"),
	Entry("LogAction", detector.Features{}, LogAction{Prefix: "prefix"}, `--jump LOG --log-prefix "prefix: " --log-level 5`),
	Entry("DNATAction", detector.Features{}, DNATAction{DestAddr: "10.0.0.1", DestPort: 8081}, "--jump DNAT --to-destination 10.0.0.1:8081"),
	Entry("SNATAction", detector.Features{}, SNATAction{ToAddr: "10.0.0.1"}, "--jump SNAT --to-source 10.0.0.1"),
	Entry("SNATAction fully random", detector.Features{SNATFullyRandom: true}, SNATAction{ToAddr: "10.0.0.1"}, "--jump SNAT --to-source 10.0.0.1 --random-fully"),
	Entry("MasqAction", detector.Features{}, MasqAction{}, "--jump MASQUERADE"),
	Entry("MasqAction", detector.Features{MASQFullyRandom: true}, MasqAction{}, "--jump MASQUERADE --random-fully"),
	Entry("ClearMarkAction", detector.Features{}, ClearMarkAction{Mark: 0x1000}, "--jump MARK --set-mark 0/0x1000"),
	Entry("SetMarkAction", detector.Features{}, SetMarkAction{Mark: 0x1000}, "--jump MARK --set-mark 0x1000/0x1000"),
	Entry("SetMaskedMarkAction", detector.Features{}, SetMaskedMarkAction{
		Mark: 0x1000,
		Mask: 0xf000,
	}, "--jump MARK --set-mark 0x1000/0xf000"),
	Entry("SaveConnMarkAction", detector.Features{}, SaveConnMarkAction{SaveMask: 0x100}, "--jump CONNMARK --save-mark --mark 0x100"),
	Entry("RestoreConnMarkAction", detector.Features{}, RestoreConnMarkAction{RestoreMask: 0x100}, "--jump CONNMARK --restore-mark --mark 0x100"),
	Entry("SaveConnMarkAction", detector.Features{}, SaveConnMarkAction{}, "--jump CONNMARK --save-mark --mark 0xffffffff"),
	Entry("RestoreConnMarkAction", detector.Features{}, RestoreConnMarkAction{}, "--jump CONNMARK --restore-mark --mark 0xffffffff"),
)
