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

	"github.com/docopt/docopt-go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const usage = `pktgen: generates packets for Felix FV testing.

Usage:
  pktgen <ip_src> <ip_dst> <proto> [--ip-id=<ip_id>] [--port-src=<port_src>] [--port-dst=<port_dst>]
         [--tcp-syn] [--tcp-ack] [--tcp-fin] [--tcp-rst] [--tcp-ack-no=<ack_no>] [--tcp-seq-no=<seq_no>]
`

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

	family := 4
	if ipsrc.To4() == nil || ipdst.To4() == nil {
		family = 6
	}

	ipID := uint16(0)
	if args["--ip-id"] != nil {
		id, err := strconv.Atoi(args["--ip-id"].(string))
		if err != nil {
			log.WithError(err).Fatal("IP id not a number")
		}
		if id > math.MaxUint16 || id < 0 {
			log.Fatal("IP id should be between 0 and 65535")
		}
		ipID = uint16(id)
	}

	sport := uint16(0)
	if args["--port-src"] != nil {
		p, err := strconv.Atoi(args["--port-src"].(string))
		if err != nil {
			log.WithError(err).Fatal("source port not a number")
		}
		if p > math.MaxUint16 || p < 0 {
			log.Fatal("source port should be between 0 and 65535")
		}
		sport = uint16(p)
	}

	dport := uint16(0)
	if args["--port-dst"] != nil {
		p, err := strconv.Atoi(args["--port-dst"].(string))
		if err != nil {
			log.WithError(err).Fatal("destination port not a number")
		}
		if p > math.MaxUint16 || p < 0 {
			log.Fatal("destination port should be between 0 and 65535")
		}
		dport = uint16(p)
	}

	var proto layers.IPProtocol

	switch args["<proto>"] {
	case "udp":
		proto = layers.IPProtocolUDP
	case "tcp":
		proto = layers.IPProtocolTCP
	default:
		log.Fatal("unsupported protocol")
	}

	payload := make([]byte, 64)

	var iphdr gopacket.SerializableLayer
	if family == 4 {
		iphdr = &layers.IPv4{
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
	} else {
		iphdr = &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			SrcIP:      ipsrc,
			DstIP:      ipdst,
			NextHeader: layers.IPProtocolUDP,
		}

	}

	var l4 gopacket.SerializableLayer

	switch proto {
	case layers.IPProtocolUDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(sport),
			DstPort: layers.UDPPort(dport),
			Length:  uint16(8 + len(payload)),
		}

		if err := udp.SetNetworkLayerForChecksum(iphdr.(gopacket.NetworkLayer)); err != nil {
			log.WithError(err).Fatal("cannot checksum udp")
		}

		l4 = udp
		if family == 4 {
			iphdr.(*layers.IPv4).Length += udp.Length
		} else {
			iphdr.(*layers.IPv6).Length += udp.Length
		}
	case layers.IPProtocolTCP:
		ack := uint32(0)
		if args["--tcp-ack-no"] != nil {
			a, err := strconv.Atoi(args["--tcp-ack-no"].(string))
			if err != nil {
				log.WithError(err).Fatal("tcp ack no not a number")
			}
			if a > math.MaxUint32 || a < 0 {
				log.Fatal("Ack no must be an unsigned 32-bit integer")
			}
			ack = uint32(a)
		}
		seq := uint32(0)
		if args["--tcp-seq-no"] != nil {
			s, err := strconv.Atoi(args["--tcp-seq-no"].(string))
			if err != nil {
				log.WithError(err).Fatal("tcp seq no not a number")
			}
			if s > math.MaxUint32 || s < 0 {
				log.Fatal("Seq no must be an unsigned 32-bit integer")
			}
			seq = uint32(s)
		}
		tcp := &layers.TCP{
			SrcPort:    layers.TCPPort(sport),
			DstPort:    layers.TCPPort(dport),
			Ack:        ack,
			Seq:        seq,
			DataOffset: 5,
		}

		if args["--tcp-syn"] != nil {
			tcp.SYN = args["--tcp-syn"].(bool)
		}
		if args["--tcp-ack"] != nil {
			tcp.ACK = args["--tcp-ack"].(bool)
		}
		if args["--tcp-fin"] != nil {
			tcp.FIN = args["--tcp-fin"].(bool)
		}
		if args["--tcp-rst"] != nil {
			tcp.RST = args["--tcp-rst"].(bool)
		}

		if err := tcp.SetNetworkLayerForChecksum(iphdr.(gopacket.NetworkLayer)); err != nil {
			log.WithError(err).Fatal("cannot checksum tcp")
		}

		l4 = tcp
		if family == 4 {
			iphdr.(*layers.IPv4).Length += uint16(int(tcp.DataOffset*4) + len(payload))
		} else {
			iphdr.(*layers.IPv6).Length += uint16(int(tcp.DataOffset*4) + len(payload))
		}
	}

	pkt := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
		iphdr, l4, gopacket.Payload(payload))

	if err != nil {
		log.WithError(err).Fatal("failed to serialized packet")
	}

	var (
		s    int
		addr unix.Sockaddr
	)

	if family == 4 {
		s, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)

		if err != nil || s < 0 {
			log.WithError(err).Fatal("failed to create raw socket")
		}

		err = unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		if err != nil {
			log.WithError(err).Fatal("failed to set IP_HDRINCL")
		}

		addr = &unix.SockaddrInet4{
			Port: int(dport),
		}
		copy(addr.(*unix.SockaddrInet4).Addr[:], ipdst.To4()[:4])
	} else {
		s, err = unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)

		if err != nil || s < 0 {
			log.WithError(err).Fatal("failed to create raw socket")
		}
		err = unix.SetsockoptInt(s, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
		if err != nil {
			log.WithError(err).Fatal("failed to set IP_HDRINCL")
		}
		addr = &unix.SockaddrInet6{}
		copy(addr.(*unix.SockaddrInet6).Addr[:], ipdst.To16()[:16])
	}

	if err := unix.Sendto(s, pkt.Bytes(), 0, addr); err != nil {
		log.WithError(err).Fatal("failed to send packet")
	}
}
