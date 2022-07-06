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
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	log "github.com/sirupsen/logrus"
)

type ipSetInfo struct {
	ipsets.IPSetMetadata
	members set.Set[ipsets.IPSetMember]
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
	default:
		log.WithField("IPSetType", update.GetType()).Panic("unknown IPSetType")
	}

	s.SetID = update.GetId()

	// Note: We ignore MaxSize.

	s.replaceMembers(update)
	return s
}

func (s *ipSetInfo) replaceMembers(update *proto.IPSetUpdate) {
	s.members = set.NewBoxed[ipsets.IPSetMember]()
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
	u := &proto.IPSetUpdate{Id: s.SetID, Type: s.getProtoType()}
	s.members.Iter(func(item ipsets.IPSetMember) error {
		u.Members = append(u.Members, item.String())
		return nil
	})
	return u
}

func (s *ipSetInfo) getProtoType() proto.IPSetUpdate_IPSetType {
	switch s.Type {
	case ipsets.IPSetTypeHashIP:
		return proto.IPSetUpdate_IP
	case ipsets.IPSetTypeHashIPPort:
		return proto.IPSetUpdate_IP_AND_PORT
	case ipsets.IPSetTypeHashNet:
		return proto.IPSetUpdate_NET
	default:
		log.WithField("IPSetType", s.Type).Panic("unknown IPSetType")
	}
	// Unhittable.
	return 0
}

type ruleList interface {
	GetInboundRules() []*proto.Rule
	GetOutboundRules() []*proto.Rule
}

func addIPSetsRuleList(rl ruleList, s map[string]bool) {
	for _, rule := range rl.GetInboundRules() {
		AddIPSetsRule(rule, s)
	}
	for _, rule := range rl.GetOutboundRules() {
		AddIPSetsRule(rule, s)
	}
}

func AddIPSetsRule(r *proto.Rule, s map[string]bool) {
	addAll(r.SrcIpSetIds, s)
	addAll(r.DstIpSetIds, s)
	addAll(r.DstIpPortSetIds, s)
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
