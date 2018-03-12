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
	"fmt"

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type ipSetInfo struct {
	ipsets.IPSetMetadata
	members set.Set
}

func newIPSet(update *proto.IPSetUpdate) *ipSetInfo {
	s := &ipSetInfo{}

	switch update.GetType() {
	case proto.IPSetUpdate_IP:
		s.Type = ipsets.IPSetTypeHashIP
	case proto.IPSetUpdate_IP_AND_PORT:
		s.Type = ipsets.IPSetTypeHashIPPort
	case proto.IPSetUpdate_NET:
		s.Type = ipsets.IPSetTypeHashNet
	}

	s.SetID = update.GetId()

	// Note: We ignore MaxSize.

	s.replaceMembers(update)
	return s
}

func (s *ipSetInfo) replaceMembers(update *proto.IPSetUpdate) {
	s.members = set.New()
	for _, ms := range update.GetMembers() {
		s.members.Add(s.Type.CanonicaliseMember(ms))
	}
}

func (s *ipSetInfo) deltaUpdate(update *proto.IPSetDeltaUpdate) {
	for _, ms := range update.GetAddedMembers() {
		s.members.Add(s.Type.CanonicaliseMember(ms))
	}
	for _, ms := range update.GetRemovedMembers() {
		s.members.Discard(s.Type.CanonicaliseMember(ms))
	}
}

func (s *ipSetInfo) getIPSetUpdate() *proto.IPSetUpdate {
	u := &proto.IPSetUpdate{Id: s.SetID}
	s.members.Iter(func(item interface{}) error {
		m := item.(fmt.Stringer)
		u.Members = append(u.Members, m.String())
		return nil
	})
	return u
}

type ruleList interface {
	GetInboundRules() []*proto.Rule
	GetOutboundRules() []*proto.Rule
}

func addIPSetsRuleList(rl ruleList, s map[string]bool) {
	for _, rule := range rl.GetInboundRules() {
		addIPSetsRule(rule, s)
	}
	for _, rule := range rl.GetOutboundRules() {
		addIPSetsRule(rule, s)
	}
}

func addIPSetsRule(r *proto.Rule, s map[string]bool) {
	addAll(r.SrcIpSetIds, s)
	addAll(r.DstIpSetIds, s)
	addAll(r.SrcNamedPortIpSetIds, s)
	addAll(r.DstNamedPortIpSetIds, s)
	addAll(r.NotSrcIpSetIds, s)
	addAll(r.NotDstIpSetIds, s)
	addAll(r.NotSrcNamedPortIpSetIds, s)
	addAll(r.NotDstNamedPortIpSetIds, s)
}

func addAll(items []string, s map[string]bool) {
	for _, i := range items {
		s[i] = true
	}
}
