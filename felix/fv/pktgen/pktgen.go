// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package main

import (
	"math"
	"net"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/docopt/docopt-go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

const usage = `pktgen: generates packets for Felix FV testing.

Usage:
  pktgen <ip_src> <ip_dst> <proto> [--ip-id=<ip_id>] [--port-src=<port_src>] [--port-dst=<port_dst>]`

func main() {
	log.SetLevel(log.InfoLevel)
	args, err := docopt.ParseArgs(usage, nil, "v0.1")
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("Failed to parse usage")
	}

	log.WithField("args", args).Info("Parsed arguments")

	ipsrc := net.ParseIP(args["<ip_src>"].(string))
	if ipsrc == nil {
		log.Fatal("invalid source IP")
	}
	ipdst := net.ParseIP(args["<ip_dst>"].(string))
	if ipdst == nil {
		log.Fatal("invalid destination IP")
	}

	if ipsrc.To4() == nil || ipdst.To4() == nil {
		log.Fatal("cannot handle IPv6")
	}

	ipID := uint16(0)
	if args["--ip-id"] != nil {
		id, err := strconv.ParseUint(args["--ip-id"].(string), 10, 16)
		if err != nil {
			log.WithError(err).Fatal("IP id not a number between 0 and 65535")
		}
		ipID = uint16(id)
	}

	sport := uint16(0)
	if args["--port-src"] != nil {
		p, err := strconv.ParseUint(args["--port-src"].(string), 10, 16)
		if err != nil {
			log.WithError(err).Fatal("source port not a number between 0 and 65535")
		}
		sport = uint16(p)
	}

	dport := uint16(0)
	if args["--port-dst"] != nil {
		p, err := strconv.ParseUint(args["--port-dst"].(string), 10, 16)
		if err != nil {
			log.WithError(err).Fatal("destination port not a number between 0 and 65535")
		}
		dport = uint16(p)
	}

	var proto layers.IPProtocol

	switch args["<proto>"] {
	case "udp":
		proto = layers.IPProtocolUDP
	default:
		log.Fatal("unsupported protocol")
	}

	payload := make([]byte, 64)

	ipv4 := &layers.IPv4{
		Version:  4,
		Id:       ipID,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    ipsrc,
		DstIP:    ipdst,
		Protocol: proto,
		Length:   5 * 4,
	}

	var l4 gopacket.SerializableLayer

	switch proto {
	case layers.IPProtocolUDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(sport),
			DstPort: layers.UDPPort(dport),
			Length:  uint16(8 + len(payload)),
		}

		if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
			log.WithError(err).Fatal("cannot checksum udp")
		}

		l4 = udp
		ipv4.Length += udp.Length
	}

	pkt := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
		ipv4, l4, gopacket.Payload(payload))

	if err != nil {
		log.WithError(err).Fatal("failed to serialized packet")
	}

	s, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)

	if err != nil || s < 0 {
		log.WithError(err).Fatal("failed to create raw socket")
	}

	err = unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		log.WithError(err).Fatal("failed to set IP_HDRINCL")
	}

	addr := &unix.SockaddrInet4{
		Port: int(dport),
	}
	copy(addr.Addr[:], ipdst.To4()[:4])

	if err := unix.Sendto(s, pkt.Bytes(), 0, addr); err != nil {
		log.WithError(err).Fatal("failed to send packet")
	}
}
