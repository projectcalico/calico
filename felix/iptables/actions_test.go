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
	. "github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/versionparse"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Actions",
	func(features versionparse.Features, action Action, expRendering string) {
		Expect(action.ToFragment(&features)).To(Equal(expRendering))
	},
	Entry("GotoAction", versionparse.Features{}, GotoAction{Target: "cali-abcd"}, "--goto cali-abcd"),
	Entry("JumpAction", versionparse.Features{}, JumpAction{Target: "cali-abcd"}, "--jump cali-abcd"),
	Entry("ReturnAction", versionparse.Features{}, ReturnAction{}, "--jump RETURN"),
	Entry("DropAction", versionparse.Features{}, DropAction{}, "--jump DROP"),
	Entry("AcceptAction", versionparse.Features{}, AcceptAction{}, "--jump ACCEPT"),
	Entry("LogAction", versionparse.Features{}, LogAction{Prefix: "prefix"}, `--jump LOG --log-prefix "prefix: " --log-level 5`),
	Entry("DNATAction", versionparse.Features{}, DNATAction{DestAddr: "10.0.0.1", DestPort: 8081}, "--jump DNAT --to-destination 10.0.0.1:8081"),
	Entry("SNATAction", versionparse.Features{}, SNATAction{ToAddr: "10.0.0.1"}, "--jump SNAT --to-source 10.0.0.1"),
	Entry("SNATAction fully random", versionparse.Features{SNATFullyRandom: true}, SNATAction{ToAddr: "10.0.0.1"}, "--jump SNAT --to-source 10.0.0.1 --random-fully"),
	Entry("MasqAction", versionparse.Features{}, MasqAction{}, "--jump MASQUERADE"),
	Entry("MasqAction", versionparse.Features{MASQFullyRandom: true}, MasqAction{}, "--jump MASQUERADE --random-fully"),
	Entry("ClearMarkAction", versionparse.Features{}, ClearMarkAction{Mark: 0x1000}, "--jump MARK --set-mark 0/0x1000"),
	Entry("SetMarkAction", versionparse.Features{}, SetMarkAction{Mark: 0x1000}, "--jump MARK --set-mark 0x1000/0x1000"),
	Entry("SetMaskedMarkAction", versionparse.Features{}, SetMaskedMarkAction{
		Mark: 0x1000,
		Mask: 0xf000,
	}, "--jump MARK --set-mark 0x1000/0xf000"),
	Entry("SaveConnMarkAction", versionparse.Features{}, SaveConnMarkAction{SaveMask: 0x100}, "--jump CONNMARK --save-mark --mark 0x100"),
	Entry("RestoreConnMarkAction", versionparse.Features{}, RestoreConnMarkAction{RestoreMask: 0x100}, "--jump CONNMARK --restore-mark --mark 0x100"),
	Entry("SaveConnMarkAction", versionparse.Features{}, SaveConnMarkAction{}, "--jump CONNMARK --save-mark --mark 0xffffffff"),
	Entry("RestoreConnMarkAction", versionparse.Features{}, RestoreConnMarkAction{}, "--jump CONNMARK --restore-mark --mark 0xffffffff"),
)
