// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package pkt

import (
	"encoding/binary"
	"net"
)

const (
	SizeofIPv4Header = 0x14
	SizeofTCPHeader  = 0x14
	SizeofUDPHeader  = 0x8
	IPv6HeaderLen    = 40
)

type IPv4Header struct {
	Version  uint8
	IHL      uint8
	TOS      uint8
	TotLen   uint16
	Id       uint16
	FragOff  uint16
	Ttl      uint8
	Protocol uint8
	Check    uint16
	Saddr    net.IP
	Daddr    net.IP
}

func ParseIPv4Header(b []byte) IPv4Header {
	endian := binary.BigEndian
	return IPv4Header{
		Version:  b[0] >> 4,
		IHL:      b[0] & 0x0F << 2,
		TOS:      b[1],
		TotLen:   endian.Uint16(b[2:4]),
		Id:       endian.Uint16(b[4:6]),
		FragOff:  endian.Uint16(b[6:8]),
		Ttl:      b[8],
		Protocol: b[9],
		Check:    endian.Uint16(b[10:12]),
		Saddr:    net.IP(b[12:16]),
		Daddr:    net.IP(b[16:20]),
	}
}

// We aren't interested in all the fields here. Just the size of the fields have to be accurate for unpacking.
type TCPHeader struct {
	Source uint16
	Dest   uint16
	Seq    uint32
	AckSeq uint32
	DOff   uint16
	Window uint16
	Check  uint16
	UrgPtr uint16
}

func ParseTCPHeader(b []byte) TCPHeader {
	endian := binary.BigEndian
	return TCPHeader{
		Source: endian.Uint16(b[0:2]),
		Dest:   endian.Uint16(b[2:4]),
		Seq:    endian.Uint32(b[4:8]),
		AckSeq: endian.Uint32(b[8:12]),
		DOff:   endian.Uint16(b[12:14]),
		Window: endian.Uint16(b[14:16]),
		Check:  endian.Uint16(b[16:18]),
		UrgPtr: endian.Uint16(b[18:20]),
	}
}

type UDPHeader struct {
	Source uint16
	Dest   uint16
	Len    uint16
	Check  uint16
}

func ParseUDPHeader(b []byte) UDPHeader {
	endian := binary.BigEndian
	return UDPHeader{
		Source: endian.Uint16(b[0:2]),
		Dest:   endian.Uint16(b[2:4]),
		Len:    endian.Uint16(b[4:6]),
		Check:  endian.Uint16(b[6:8]),
	}
}

type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
}

func ParseICMPHeader(b []byte) ICMPHeader {
	endian := binary.BigEndian
	return ICMPHeader{
		Type:     b[0],
		Code:     b[1],
		Checksum: endian.Uint16(b[2:4]),
		Id:       endian.Uint16(b[4:6]),
	}
}

type IPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	// Payload length in bytes. This is the length of the packet data
	// following the IPv6 packet header.
	Length     uint16
	NextHeader uint8
	HopLimit   uint8
	Saddr      net.IP
	Daddr      net.IP
}

func ParseIPv6Header(b []byte) IPv6Header {
	endian := binary.BigEndian
	return IPv6Header{
		Version:      b[0] >> 4,
		TrafficClass: uint8((endian.Uint16(b[0:2]) >> 4) & 0x00FF),
		FlowLabel:    endian.Uint32(b[0:4]) & 0x000FFFFF,
		Length:       endian.Uint16(b[4:6]),
		NextHeader:   b[6],
		HopLimit:     b[7],
		Saddr:        net.IP(b[8:24]),
		Daddr:        net.IP(b[24:40]),
	}
}
