// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

func parsedRulesToProtoRules(in []*ParsedRule) (out []*proto.Rule) {
	out = make([]*proto.Rule, len(in))
	for ii, inRule := range in {
		out[ii] = parsedRuleToProtoRule(inRule)
	}
	return
}

func parsedRuleToProtoRule(in *ParsedRule) *proto.Rule {
	out := &proto.Rule{
		Action: in.Action,

		IpVersion: ipVersionToProtoIPVersion(in.IPVersion),

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

		LogPrefix: in.LogPrefix,
	}

	// Fill in the ICMP fields.  We can't follow the pattern and make a
	// convertICMP() function because we can't name the return type of the
	// function (it's private to the protobuf package).
	if in.ICMPType != nil {
		if in.ICMPCode != nil {
			out.Icmp = &proto.Rule_IcmpTypeCode{
				&proto.IcmpTypeAndCode{
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
				&proto.IcmpTypeAndCode{
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

func ipVersionToProtoIPVersion(in *int) proto.IPVersion {
	if in == nil {
		return proto.IPVersion_ANY
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
				NumberOrName: &proto.Protocol_Number{int32(in.NumVal)},
			}
		} else {
			out = &proto.Protocol{
				NumberOrName: &proto.Protocol_Name{in.StrVal},
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
