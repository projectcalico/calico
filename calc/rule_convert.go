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

package calc

import (
	"crypto/sha256"
	"encoding/base64"

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

const (
	// Compromise: shorter is better for occupancy and readability. Longer is better for
	// collision-resistance.  16 chars gives us 96 bits of entropy, which is fairly collision
	// resistant.
	RuleIDLength = 16
)

func parsedRulesToProtoRules(in []*ParsedRule, ruleIDSeed string) (out []*proto.Rule) {
	out = make([]*proto.Rule, len(in))
	for ii, inRule := range in {
		out[ii] = parsedRuleToProtoRule(inRule)
	}
	fillInRuleIDs(out, ruleIDSeed)
	return
}

func fillInRuleIDs(rules []*proto.Rule, ruleIDSeed string) {
	s := sha256.New224()
	s.Write([]byte(ruleIDSeed))
	hash := s.Sum(nil)
	for ii, rule := range rules {
		// Each hash chains in the previous hash, so that its position in the chain and
		// the rules before it affect its hash.
		s.Reset()
		s.Write(hash)

		// We need a form of the rule that we can hash.  Convert it to the protobuf
		// binary representation, which is deterministic, at least for a given rev of the
		// library.
		// TODO(smc) Can we do better than hashing the protobuf?
		rule.RuleId = ""
		data, err := rule.Marshal()
		if err != nil {
			log.WithError(err).WithField("rule", rule).Panic("Failed to marshal rule")
		}
		s.Write(data)
		hash = s.Sum(hash[0:0])
		// Encode the hash using a compact character set.  We use the URL-safe base64
		// variant because it uses '-' and '_', which are more shell-friendly.
		ruleID := base64.RawURLEncoding.EncodeToString(hash)[:RuleIDLength]
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"rule":     rule,
				"action":   rule.Action,
				"position": ii,
				"seed":     ruleIDSeed,
				"ruleID":   ruleID,
			}).Debug("Calculated rule ID")
		}
		rule.RuleId = ruleID
	}
}

func parsedRuleToProtoRule(in *ParsedRule) *proto.Rule {
	out := &proto.Rule{
		Action: in.Action,

		IpVersion: ipVersionToProtoIPVersion(in.IPVersion, in.Protocol),

		Protocol: protocolToProtoProtocol(in.Protocol),

		SrcNet:      ipNetToProtoString(in.SrcNet),
		SrcPorts:    portsToProtoPorts(in.SrcPorts),
		DstNet:      ipNetToProtoString(in.DstNet),
		DstPorts:    portsToProtoPorts(in.DstPorts),
		SrcIpSetIds: in.SrcIPSetIDs,
		DstIpSetIds: in.DstIPSetIDs,

		NotProtocol:    protocolToProtoProtocol(in.NotProtocol),
		NotSrcNet:      ipNetToProtoString(in.NotSrcNet),
		NotSrcPorts:    portsToProtoPorts(in.NotSrcPorts),
		NotDstNet:      ipNetToProtoString(in.NotDstNet),
		NotDstPorts:    portsToProtoPorts(in.NotDstPorts),
		NotSrcIpSetIds: in.NotSrcIPSetIDs,
		NotDstIpSetIds: in.NotDstIPSetIDs,
	}

	// Fill in the ICMP fields.  We can't follow the pattern and make a
	// convertICMP() function because we can't name the return type of the
	// function (it's private to the protobuf package).
	if in.ICMPType != nil {
		if in.ICMPCode != nil {
			out.Icmp = &proto.Rule_IcmpTypeCode{
				IcmpTypeCode: &proto.IcmpTypeAndCode{
					Type: int32(*in.ICMPType),
					Code: int32(*in.ICMPCode),
				},
			}
		} else {
			out.Icmp = &proto.Rule_IcmpType{
				IcmpType: int32(*in.ICMPType),
			}
		}
	}
	if in.NotICMPType != nil {
		if in.NotICMPCode != nil {
			out.NotIcmp = &proto.Rule_NotIcmpTypeCode{
				NotIcmpTypeCode: &proto.IcmpTypeAndCode{
					Type: int32(*in.NotICMPType),
					Code: int32(*in.NotICMPCode),
				},
			}
		} else {
			out.NotIcmp = &proto.Rule_NotIcmpType{
				NotIcmpType: int32(*in.NotICMPType),
			}
		}
	}

	log.WithFields(log.Fields{
		"in":  in,
		"out": out,
	}).Debug("Converted rule to protobuf format.")
	return out
}

func ipVersionToProtoIPVersion(in *int, p *numorstring.Protocol) proto.IPVersion {
	if in == nil {
		// No explicit version, see if we can work out the version from the protocol.
		if p == nil {
			return proto.IPVersion_ANY
		}
		switch p.String() {
		case "icmp":
			return proto.IPVersion_IPV4
		case "icmpv6":
			return proto.IPVersion_IPV6
		default:
			return proto.IPVersion_ANY
		}
	}
	switch *in {
	case 4:
		return proto.IPVersion_IPV4
	case 6:
		return proto.IPVersion_IPV6
	}
	return proto.IPVersion_ANY
}

func protocolToProtoProtocol(in *numorstring.Protocol) (out *proto.Protocol) {
	if in != nil {
		if in.Type == numorstring.NumOrStringNum {
			out = &proto.Protocol{
				NumberOrName: &proto.Protocol_Number{
					Number: int32(in.NumVal),
				},
			}
		} else {
			out = &proto.Protocol{
				NumberOrName: &proto.Protocol_Name{Name: in.StrVal},
			}
		}
	}
	return
}

func ipNetToProtoString(in *net.IPNet) (out string) {
	if in != nil {
		out = in.String()
	}
	return
}

func portsToProtoPorts(in []numorstring.Port) (out []*proto.PortRange) {
	if len(in) == 0 {
		return
	}
	out = make([]*proto.PortRange, len(in))
	for ii, port := range in {
		out[ii] = portToProtoPort(port)
	}
	return
}

func portToProtoPort(in numorstring.Port) (out *proto.PortRange) {
	out = &proto.PortRange{
		First: int32(in.MinPort),
		Last:  int32(in.MaxPort),
	}
	return
}
