// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package ut_test

import (
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
)

func TestIP4Defrag(t *testing.T) {
	RegisterTestingT(t)

	cleanUpMaps()

	bpfIfaceName = "DEFR"
	defer func() { bpfIfaceName = "" }()

	data := make([]byte, 2000)

	for i := 0; i < 1000; i++ {
		data[i*2] = byte(uint16(i) >> 8)
		data[i*2+1] = byte(uint16(i) & 0xff)
	}

	ip := *ipv4Default
	ip.Id = 0x1234
	ip.Length = 20 + 8 + 2000
	ip.Flags = 0
	udp := *udpDefault
	udp.Length = 8 + 2000

	// compute ull packet
	payload := gopacket.Payload(data)
	_ = udp.SetNetworkLayerForChecksum(&ip)

	pktFull := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pktFull, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, &udp, payload)
	Expect(err).NotTo(HaveOccurred())

	dataLen := 1600
	dataOffset := 0

	ip.Flags = layers.IPv4MoreFragments
	ip.FragOffset = 0
	ip.Length = 20 + 8 + 1596

	payload = gopacket.Payload(data[dataOffset : dataOffset+dataLen])
	_ = udp.SetNetworkLayerForChecksum(&ip)

	pkt0 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt0, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, &udp, payload)
	Expect(err).NotTo(HaveOccurred())

	dataOffset = dataLen
	dataLen = 192

	ip.FragOffset = uint16((8 + dataOffset) / 8)
	ip.Length = uint16(20 + dataLen)
	payload = gopacket.Payload(data[dataOffset : dataOffset+dataLen])

	pkt1 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt1, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, payload)
	Expect(err).NotTo(HaveOccurred())

	dataOffset += dataLen
	dataLen = 80

	ip.Flags = layers.IPv4MoreFragments
	ip.FragOffset = uint16((8 + dataOffset) / 8)
	ip.Length = uint16(20 + dataLen)
	payload = gopacket.Payload(data[dataOffset : dataOffset+dataLen])

	pkt2 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt2, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, payload)
	Expect(err).NotTo(HaveOccurred())

	dataOffset += dataLen
	dataLen = 2000 - dataOffset

	ip.Flags = 0
	ip.FragOffset = uint16((8 + dataOffset) / 8)
	ip.Length = uint16(20 + dataLen)
	payload = gopacket.Payload(data[dataOffset : dataOffset+dataLen])

	pkt3 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt3, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, payload)
	Expect(err).NotTo(HaveOccurred())

	pktFullR := gopacket.NewPacket(pktFull.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		bytes := pkt0.Bytes()
		copy(bytes[40:42], pktFull.Bytes()[40:42]) // patch in the udp csum for the entire packet
		res, err := bpfrun(bytes)
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt1.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt3.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt2.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		fmt.Printf("pktFullR = %+v\n", pktFullR)
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		payloadL := pktR.ApplicationLayer()
		data := payloadL.Payload()

		for i := 0; i < 1000; i++ {
			Expect(data[i*2]).To(Equal(byte(uint16(i)>>8)), fmt.Sprintf("wrong at index %d", i*2))
			Expect(data[i*2+1]).To(Equal(byte(uint16(i)&0xff)), fmt.Sprintf("wrong at index %d", i*2+1))
		}

		Expect(pktFull.Bytes()).To(Equal(res.dataOut))
	})
}
