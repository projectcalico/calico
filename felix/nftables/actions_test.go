// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package nftables_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	. "github.com/projectcalico/calico/felix/nftables"
)

var _ = DescribeTable("Actions",
	func(features environment.Features, action generictables.Action, expRendering string) {
		Expect(action.ToFragment(&features)).To(Equal(expRendering))
	},
	Entry("GotoAction", environment.Features{}, GotoAction{Target: "cali-abcd"}, "goto cali-abcd"),
	Entry("JumpAction", environment.Features{}, JumpAction{Target: "cali-abcd"}, "jump cali-abcd"),
	Entry("ReturnAction", environment.Features{}, ReturnAction{}, "return"),
	Entry("DropAction", environment.Features{}, DropAction{}, "drop"),
	Entry("AcceptAction", environment.Features{}, AcceptAction{}, "accept"),
	Entry("LogAction", environment.Features{}, LogAction{Prefix: "prefix"}, "log prefix prefix level info"),
	Entry("DNATAction", environment.Features{}, DNATAction{DestAddr: "10.0.0.1", DestPort: 8081}, "dnat to 10.0.0.1:8081"),
	Entry("SNATAction", environment.Features{}, SNATAction{ToAddr: "10.0.0.1"}, "snat to 10.0.0.1"),
	Entry("SNATAction fully random", environment.Features{SNATFullyRandom: true}, SNATAction{ToAddr: "10.0.0.1"}, "snat to 10.0.0.1 fully-random"),
	Entry("MasqAction", environment.Features{}, MasqAction{}, "masquerade"),
	Entry("MasqAction", environment.Features{MASQFullyRandom: true}, MasqAction{}, "masquerade fully-random"),
	Entry("ClearMarkAction", environment.Features{}, ClearMarkAction{Mark: 0x1000}, "meta mark set mark & 0xffffefff"),
	Entry("SetMarkAction", environment.Features{}, SetMarkAction{Mark: 0x1000}, "meta mark set mark or 0x1000"),
	Entry("SetMaskedMarkAction", environment.Features{}, SetMaskedMarkAction{Mark: 0x1000, Mask: 0xf000}, "meta mark set mark & 0xffff0fff ^ 0x1000"),
	Entry("SaveConnMarkAction", environment.Features{}, SaveConnMarkAction{SaveMask: 0x100}, "ct mark set mark & 0x100"),
	Entry("RestoreConnMarkAction", environment.Features{}, RestoreConnMarkAction{RestoreMask: 0x100}, "meta mark set ct mark & 0x100"),
	Entry("SaveConnMarkAction", environment.Features{}, SaveConnMarkAction{}, "ct mark set mark"),
	Entry("RestoreConnMarkAction", environment.Features{}, RestoreConnMarkAction{}, "meta mark set ct mark"),
	Entry("SetConnMarkAction", environment.Features{}, SetConnMarkAction{Mark: 0x1000, Mask: 0xf000}, "ct mark set ct mark & 0xffff0fff ^ 0x1000"),
	Entry("LimitPacketRateAction", environment.Features{}, LimitPacketRateAction{Rate: 1000}, "limit rate over 1000/second drop"),
	Entry("LimitNumConnectionsAction", environment.Features{}, LimitNumConnectionsAction{Num: 10, RejectWith: generictables.RejectWithTCPReset}, "ct count over 10 reject with tcp reset"),
)
