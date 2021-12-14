// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package policysync

import (
	"github.com/projectcalico/calico/felix/proto"
)

type policyInfo struct {
	p    *proto.Policy
	refs map[string]bool
}

func newPolicyInfo(p *proto.Policy) *policyInfo {
	i := &policyInfo{p: p}
	i.computeRefs()
	return i
}

func (pi *policyInfo) referencesIPSet(id string) bool {
	return pi.refs[id]
}

func (pi *policyInfo) computeRefs() {
	pi.refs = make(map[string]bool)
	addIPSetsRuleList(pi.p, pi.refs)
}
