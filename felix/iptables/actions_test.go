// Copyright (c) 2016-2022 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	. "github.com/projectcalico/calico/felix/iptables"
)

var _ = DescribeTable("Actions",
	func(features environment.Features, action generictables.Action, expRendering string) {
		Expect(action.ToFragment(&features)).To(Equal(expRendering))
	},
	Entry("GotoAction", environment.Features{}, GotoAction{Target: "cali-abcd"}, "--goto cali-abcd"),
	Entry("JumpAction", environment.Features{}, JumpAction{Target: "cali-abcd"}, "--jump cali-abcd"),
	Entry("ReturnAction", environment.Features{}, ReturnAction{}, "--jump RETURN"),
	Entry("DropAction", environment.Features{}, DropAction{}, "--jump DROP"),
	Entry("AcceptAction", environment.Features{}, AcceptAction{}, "--jump ACCEPT"),
	Entry("LogAction", environment.Features{}, LogAction{Prefix: "prefix"}, `--jump LOG --log-prefix "prefix: " --log-level 5`),
	Entry("DNATAction", environment.Features{}, DNATAction{DestAddr: "10.0.0.1", DestPort: 8081}, "--jump DNAT --to-destination 10.0.0.1:8081"),
	Entry("SNATAction", environment.Features{}, SNATAction{ToAddr: "10.0.0.1"}, "--jump SNAT --to-source 10.0.0.1"),
	Entry("SNATAction fully random", environment.Features{SNATFullyRandom: true}, SNATAction{ToAddr: "10.0.0.1"}, "--jump SNAT --to-source 10.0.0.1 --random-fully"),
	Entry("MasqAction", environment.Features{}, MasqAction{}, "--jump MASQUERADE"),
	Entry("MasqAction", environment.Features{MASQFullyRandom: true}, MasqAction{}, "--jump MASQUERADE --random-fully"),
	Entry("ClearMarkAction", environment.Features{}, ClearMarkAction{Mark: 0x1000}, "--jump MARK --set-mark 0/0x1000"),
	Entry("SetMarkAction", environment.Features{}, SetMarkAction{Mark: 0x1000}, "--jump MARK --set-mark 0x1000/0x1000"),
	Entry("SetMaskedMarkAction", environment.Features{}, SetMaskedMarkAction{
		Mark: 0x1000,
		Mask: 0xf000,
	}, "--jump MARK --set-mark 0x1000/0xf000"),
	Entry("SaveConnMarkAction", environment.Features{}, SaveConnMarkAction{SaveMask: 0x100}, "--jump CONNMARK --save-mark --mask 0x100"),
	Entry("RestoreConnMarkAction", environment.Features{}, RestoreConnMarkAction{RestoreMask: 0x100}, "--jump CONNMARK --restore-mark --mask 0x100"),
	Entry("SaveConnMarkAction", environment.Features{}, SaveConnMarkAction{}, "--jump CONNMARK --save-mark --mask 0xffffffff"),
	Entry("RestoreConnMarkAction", environment.Features{}, RestoreConnMarkAction{}, "--jump CONNMARK --restore-mark --mask 0xffffffff"),
	Entry("LimitPacketRateAction", environment.Features{}, LimitPacketRateAction{Rate: 1000, Mark: 0x200}, "-m limit --limit 1000/sec --jump MARK --set-mark 0x200/0x200"),
	Entry("LimitNumConnectionsAction", environment.Features{}, LimitNumConnectionsAction{Num: 10, RejectWith: generictables.RejectWithTCPReset}, "-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 10 --connlimit-mask 0 -j REJECT --reject-with tcp-reset"),
)
