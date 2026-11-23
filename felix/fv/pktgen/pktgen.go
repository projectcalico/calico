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
	"encoding/binary"
	"math"
	"net"
	"strconv"

	"github.com/docopt/docopt-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const usage = `pktgen: generates packets for Felix FV testing.

Usage:
  pktgen <ip_src> <ip_dst> <proto> [--ip-id=<ip_id>] [--port-src=<port_src>] [--port-dst=<port_dst>]
         [--tcp-syn] [--tcp-ack] [--tcp-fin] [--tcp-rst] [--tcp-ack-no=<ack_no>] [--tcp-seq-no=<seq_no>]
		 [--ip-dnf=[y|n]] [--payload-size=<size>] [--udp-sock]
		 [--icmp-type=<type>] [--icmp-code=<code>] [--icmp-id=<id>]

<proto> is one of tcp, udp, icmp, icmp6, sctp (sent as an INIT chunk) or udplite.
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

	payloadSize := 64
	if args["--payload-size"] != nil {
		p, err := strconv.Atoi(args["--payload-size"].(string))
		if err != nil {
			log.WithError(err).Fatal("destination port not a number")
		}
		payloadSize = p
	}

	ipDNF := true
	if args["--ip-dnf"] != nil {
		ipDNF = false
		if args["--ip-dnf"].(string) == "y" {
			ipDNF = true
		} else if args["--ip-dnf"].(string) != "n" {
			log.Fatal("wrong value for --ip-dnf. It can be only 'y' or 'n'")
		}
	}

	useUDPSock := false
	if _, ok := args["--udp-sock"]; ok {
		useUDPSock = args["--udp-sock"].(bool)
	}

	var proto layers.IPProtocol

	switch args["<proto>"] {
	case "udp":
		proto = layers.IPProtocolUDP
	case "tcp":
		proto = layers.IPProtocolTCP
	case "icmp":
		proto = layers.IPProtocolICMPv4
	case "icmp6":
		proto = layers.IPProtocolICMPv6
	case "sctp":
		proto = layers.IPProtocolSCTP
	case "udplite":
		proto = layers.IPProtocolUDPLite
	default:
		log.Fatal("unsupported protocol")
	}

	icmpType := uint8(intArg(args, "--icmp-type", 0, math.MaxUint8))
	icmpCode := uint8(intArg(args, "--icmp-code", 0, math.MaxUint8))
	icmpID := uint16(intArg(args, "--icmp-id", 1, math.MaxUint16))

	payload := make([]byte, payloadSize)
	if proto == layers.IPProtocolSCTP {
		// An INIT chunk is the whole packet: anything after it would be read as another chunk.
		payload = nil
	}

	var iphdr gopacket.SerializableLayer
	if family == 4 {
		ip4 := &layers.IPv4{
			Version:  4,
			Id:       ipID,
			IHL:      5,
			TTL:      64,
			SrcIP:    ipsrc,
			DstIP:    ipdst,
			Protocol: proto,
			Length:   5 * 4,
		}
		if ipDNF {
			ip4.Flags = layers.IPv4DontFragment
		}
		iphdr = ip4
	} else {
		iphdr = &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			SrcIP:      ipsrc,
			DstIP:      ipdst,
			NextHeader: proto,
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

	addLength := func(n int) {
		if family == 4 {
			iphdr.(*layers.IPv4).Length += uint16(n)
		} else {
			iphdr.(*layers.IPv6).Length += uint16(n)
		}
	}
	l4Layers := []gopacket.SerializableLayer{l4}

	switch proto {
	case layers.IPProtocolICMPv4:
		l4Layers = []gopacket.SerializableLayer{&layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
			Id:       icmpID,
			Seq:      1,
		}}
		addLength(8 + len(payload))
	case layers.IPProtocolICMPv6:
		icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(icmpType, icmpCode)}
		if err := icmp.SetNetworkLayerForChecksum(iphdr.(gopacket.NetworkLayer)); err != nil {
			log.WithError(err).Fatal("cannot checksum icmp6")
		}
		// The identifier and sequence number follow the header for echo requests; conntrack reads
		// the identifier from there for every type it tracks.
		l4Layers = []gopacket.SerializableLayer{icmp, &layers.ICMPv6Echo{Identifier: icmpID, SeqNumber: 1}}
		addLength(8 + len(payload))
	case layers.IPProtocolSCTP:
		l4Layers = []gopacket.SerializableLayer{
			&layers.SCTP{SrcPort: layers.SCTPPort(sport), DstPort: layers.SCTPPort(dport)},
			&layers.SCTPInit{
				SCTPChunk:                      layers.SCTPChunk{Type: layers.SCTPChunkTypeInit},
				InitiateTag:                    1,
				AdvertisedReceiverWindowCredit: 65535,
				OutboundStreams:                1,
				InboundStreams:                 1,
				InitialTSN:                     1,
			},
		}
		addLength(12 + 20)
	case layers.IPProtocolUDPLite:
		// gopacket can't serialise UDP-Lite, so the datagram goes in as payload, with its checksum
		// worked out here over the whole datagram (a checksum coverage of 0).
		datagram := udpLiteDatagram(ipsrc, ipdst, sport, dport, payload)
		l4Layers = nil
		payload = datagram
		addLength(len(datagram))
	}

	pkt := gopacket.NewSerializeBuffer()
	toSerialize := append([]gopacket.SerializableLayer{iphdr}, l4Layers...)
	toSerialize = append(toSerialize, gopacket.Payload(payload))
	err = gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true}, toSerialize...)

	if err != nil {
		log.WithError(err).Fatal("failed to serialized packet")
	}

	var (
		s    int
		addr unix.Sockaddr
	)

	if useUDPSock {
		s, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)

		if err != nil || s < 0 {
			log.WithError(err).Fatal("failed to create UDP socket")
		}

		if sport != 0 {
			laddr := &unix.SockaddrInet4{
				Port: int(sport), // Your specific source port
				Addr: [4]byte{0, 0, 0, 0},
			}
			if err := unix.Bind(s, laddr); err != nil {
				log.WithError(err).Fatal("failed to bind to source port")
			}
		}

		if !ipDNF {
			err = unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_PMTUDISC, unix.IP_PMTUDISC_DONT)
			if err != nil {
				log.WithError(err).Fatal("failed to set IP_PMTUDISC_DONT")
			}
		}

		addr = &unix.SockaddrInet4{
			Port: int(dport),
		}
		copy(addr.(*unix.SockaddrInet4).Addr[:], ipdst.To4()[:4])

		if err := unix.Sendto(s, payload, 0, addr); err != nil {
			log.WithError(err).Fatal("failed to send packet")
		}

		return
	}

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

func intArg(args map[string]interface{}, name string, def, max int) int {
	if args[name] == nil {
		return def
	}
	v, err := strconv.Atoi(args[name].(string))
	if err != nil {
		log.WithError(err).Fatalf("%s not a number", name)
	}
	if v < 0 || v > max {
		log.Fatalf("%s should be between 0 and %d", name, max)
	}
	return v
}

// udpLiteDatagram returns a UDP-Lite header and payload, with the checksum covering all of it.
//
// The pseudo-header carries UDP's protocol number, not UDP-Lite's: conntrack checks a UDP-Lite
// checksum that way, and drops a packet whose checksum it rejects as invalid, before policy.
func udpLiteDatagram(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	d := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(d[0:2], sport)
	binary.BigEndian.PutUint16(d[2:4], dport)
	// Bytes 4:6 are the checksum coverage, 0 for the whole datagram.
	copy(d[8:], payload)

	var pseudo []byte
	if v4 := src.To4(); v4 != nil && dst.To4() != nil {
		pseudo = append(pseudo, v4...)
		pseudo = append(pseudo, dst.To4()...)
		pseudo = append(pseudo, 0, byte(layers.IPProtocolUDP))
		pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(d)))
	} else {
		pseudo = append(pseudo, src.To16()...)
		pseudo = append(pseudo, dst.To16()...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(d)))
		pseudo = append(pseudo, 0, 0, 0, byte(layers.IPProtocolUDP))
	}
	var sum uint32
	for _, b := range [][]byte{pseudo, d} {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(d[6:8], csum)
	return d
}
