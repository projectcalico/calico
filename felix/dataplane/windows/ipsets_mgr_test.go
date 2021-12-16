// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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

package windataplane

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/dataplane/windows/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func TestIPSetsManager(t *testing.T) {
	RegisterTestingT(t)

	ipSetsConfigV4 := ipsets.NewIPVersionConfig(
		ipsets.IPFamilyV4,
	)

	ipSetsV4 := ipsets.NewIPSets(ipSetsConfigV4)

	ipsetsMgr := newIPSetsManager(ipSetsV4)
	//update ipset
	ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
		Id:      "id1",
		Members: []string{"10.0.0.1", "10.0.0.2"},
	})

	Expect(ipSetsV4.GetIPSetMembers("id1")).To(HaveLen(2))
	Expect((set.FromArray(ipSetsV4.GetIPSetMembers("id1")))).To(Equal(set.From("10.0.0.1", "10.0.0.2")))

	//update ipset with delta by removing and adding at the same time
	ipsetsMgr.OnUpdate(&proto.IPSetDeltaUpdate{
		Id:             "id1",
		AddedMembers:   []string{"10.0.0.3", "10.0.0.4"},
		RemovedMembers: []string{"10.0.0.1"},
	})

	Expect(ipSetsV4.GetIPSetMembers("id1")).To(HaveLen(3))
	Expect((set.FromArray(ipSetsV4.GetIPSetMembers("id1")))).To(Equal(set.From("10.0.0.2", "10.0.0.3", "10.0.0.4")))

	//remove ipsets
	ipsetsMgr.OnUpdate(&proto.IPSetRemove{
		Id: "id1",
	})

	Expect(ipSetsV4.GetIPSetMembers("id1")).To(BeNil())

	//update ipsets again here
	ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
		Id:      "id1",
		Members: []string{"10.0.0.2", "10.0.0.3"},
	})

	Expect(ipSetsV4.GetIPSetMembers("id1")).To(HaveLen(2))
	Expect((set.FromArray(ipSetsV4.GetIPSetMembers("id1")))).To(Equal(set.From("10.0.0.2", "10.0.0.3")))

}
