// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package conntrack

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// LinuxHoldsTCPFlow reports whether Linux conntrack holds a BPF entry's TCP flow
// before close, by tuple lookup.
func LinuxHoldsTCPFlow(k KeyInterface, v ValueInterface) (bool, error) {
	opener, openerPort, responder, responderPort := k.AddrA(), k.PortA(), k.AddrB(), k.PortB()
	if !v.Data().A2B.Opener {
		opener, openerPort, responder, responderPort = responder, responderPort, opener, openerPort
	}

	// Linux holds the workload's tuple as the original, or as the reply when
	// Linux DNATs to it.
	state, err := linuxTCPState(nl.CTA_TUPLE_ORIG, opener, openerPort, responder, responderPort)
	if errors.Is(err, unix.ENOENT) {
		state, err = linuxTCPState(nl.CTA_TUPLE_REPLY, responder, responderPort, opener, openerPort)
	}
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return tcpStateBeforeClose(state), nil
}

// tcpStateBeforeClose matches the BPF recount, which counts a connection
// until both FINs are seen.
func tcpStateBeforeClose(state uint8) bool {
	switch state {
	case nl.TCP_CONNTRACK_SYN_RECV, nl.TCP_CONNTRACK_ESTABLISHED,
		nl.TCP_CONNTRACK_FIN_WAIT, nl.TCP_CONNTRACK_CLOSE_WAIT:
		return true
	}
	return false
}

// linuxTCPState issues a ctnetlink GET for one tuple and returns its TCP state.
func linuxTCPState(tupleType int, src net.IP, srcPort uint16, dst net.IP, dstPort uint16) (uint8, error) {
	family, srcAttr, dstAttr := uint8(nl.FAMILY_V4), nl.CTA_IP_V4_SRC, nl.CTA_IP_V4_DST
	if src.To4() == nil {
		family, srcAttr, dstAttr = nl.FAMILY_V6, nl.CTA_IP_V6_SRC, nl.CTA_IP_V6_DST
	} else {
		src, dst = src.To4(), dst.To4()
	}

	req := nl.NewNetlinkRequest((int(netlink.ConntrackTable)<<8)|nl.IPCTNL_MSG_CT_GET, unix.NLM_F_ACK)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: family, Version: nl.NFNETLINK_V0})

	tuple := nl.NewRtAttr(unix.NLA_F_NESTED|tupleType, nil)
	ip := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil)
	ip.AddChild(nl.NewRtAttr(srcAttr, src))
	ip.AddChild(nl.NewRtAttr(dstAttr, dst))
	tuple.AddChild(ip)
	proto := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	proto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_NUM, []byte{unix.IPPROTO_TCP}))
	proto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_SRC_PORT, nl.BEUint16Attr(srcPort)))
	proto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_DST_PORT, nl.BEUint16Attr(dstPort)))
	tuple.AddChild(proto)
	req.AddData(tuple)

	msgs, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	if err != nil {
		return 0, err
	}
	if len(msgs) == 0 {
		return 0, unix.ENOENT
	}
	return parseCTTCPState(msgs[0])
}

// parseCTTCPState extracts CTA_PROTOINFO_TCP_STATE from a ctnetlink message.
func parseCTTCPState(msg []byte) (uint8, error) {
	if len(msg) < nl.SizeofNfgenmsg {
		return 0, fmt.Errorf("short ctnetlink message: %d bytes", len(msg))
	}
	protoInfo, err := nestedAttr(msg[nl.SizeofNfgenmsg:], nl.CTA_PROTOINFO)
	if err != nil {
		return 0, err
	}
	tcp, err := nestedAttr(protoInfo, nl.CTA_PROTOINFO_TCP)
	if err != nil {
		return 0, err
	}
	state, err := nestedAttr(tcp, nl.CTA_PROTOINFO_TCP_STATE)
	if err != nil {
		return 0, err
	}
	if len(state) < 1 {
		return 0, errors.New("empty CTA_PROTOINFO_TCP_STATE")
	}
	return state[0], nil
}

func nestedAttr(b []byte, attrType uint16) ([]byte, error) {
	attrs, err := nl.ParseRouteAttr(b)
	if err != nil {
		return nil, err
	}
	for _, a := range attrs {
		if a.Attr.Type&^unix.NLA_F_NESTED == attrType {
			return a.Value, nil
		}
	}
	return nil, fmt.Errorf("ctnetlink attribute %d missing", attrType)
}
