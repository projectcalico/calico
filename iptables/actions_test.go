// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	. "github.com/projectcalico/felix/iptables"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Actions",
	func(action Action, expRendering string) {
		Expect(action.ToFragment()).To(Equal(expRendering))
	},
	Entry("GotoAction", GotoAction{Target: "cali-abcd"}, "--goto cali-abcd"),
	Entry("JumpAction", JumpAction{Target: "cali-abcd"}, "--jump cali-abcd"),
	Entry("ReturnAction", ReturnAction{}, "--jump RETURN"),
	Entry("DropAction", DropAction{}, "--jump DROP"),
	Entry("AcceptAction", AcceptAction{}, "--jump ACCEPT"),
	Entry("LogAction", LogAction{Prefix: "prefix"}, `--jump LOG --log-prefix "prefix: " --log-level 5`),
	Entry("DNATAction", DNATAction{DestAddr: "10.0.0.1", DestPort: 8081}, "--jump DNAT --to-destination 10.0.0.1:8081"),
	Entry("MasqAction", MasqAction{}, "--jump MASQUERADE"),
	Entry("ClearMarkAction", ClearMarkAction{Mark: 0x1000}, "--jump MARK --set-mark 0/0x1000"),
	Entry("SetMarkAction", SetMarkAction{Mark: 0x1000}, "--jump MARK --set-mark 0x1000/0x1000"),
	Entry("SetMaskedMarkAction", SetMaskedMarkAction{
		Mark: 0x1000,
		Mask: 0xf000,
	}, "--jump MARK --set-mark 0x1000/0xf000"),
)
