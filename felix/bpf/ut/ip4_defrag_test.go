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

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	mapsbpf "github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/routes"
)

func TestIP4Defrag(t *testing.T) {
	RegisterTestingT(t)

	cleanUpMaps()

	bpfIfaceName = "DEFR"
	defer func() { bpfIfaceName = "" }()

	data := make([]byte, 2000)

	for i := range 1000 {
		data[i*2] = byte(uint16(i) >> 8)
		data[i*2+1] = byte(uint16(i) & 0xff)
	}

	ip := *ipv4Default
	ip.Id = 0x1234
	ip.Length = 20 + 8 + 2000
	ip.Flags = 0
	udp := *udpDefault
	udp.Length = 8 + 2000

	// compute full packet
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

	/* First fragment in-order */

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		bytes := pkt0.Bytes()
		copy(bytes[40:42], pktFull.Bytes()[40:42]) // patch in the udp csum for the entire packet
		res, err := bpfrun(bytes)
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt1.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt3.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt2.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	/* First fragment out-of-order */

	cleanupMap(ipfragsFwdMap)

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

		for i := range 1000 {
			Expect(data[i*2]).To(Equal(byte(uint16(i)>>8)), fmt.Sprintf("wrong at index %d", i*2))
			Expect(data[i*2+1]).To(Equal(byte(uint16(i)&0xff)), fmt.Sprintf("wrong at index %d", i*2+1))
		}

		Expect(pktFull.Bytes()).To(Equal(res.dataOut))
	})

	/* First fragment only - sets timer, it needs to kick in */

	cleanupMap(ipfragsFwdMap)

	ipfragsFwdMapCount := func() int {
		count := 0
		_ = ipfragsFwdMap.Iter(func(key, value []byte) mapsbpf.IteratorAction {
			count++
			return mapsbpf.IterNone
		})
		return count
	}

	Expect(ipfragsFwdMapCount()).To(Equal(0))

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		bytes := pkt0.Bytes()
		copy(bytes[40:42], pktFull.Bytes()[40:42]) // patch in the udp csum for the entire packet
		res, err := bpfrun(bytes)
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	}, withIPFragTimeout(1))

	Expect(ipfragsFwdMapCount()).To(Equal(1))

	Eventually(func() int {
		return ipfragsFwdMapCount()
	}, "2s", "200ms").Should(Equal(0))
}

// TestIP4FragShortTail checks that a non-first fragment whose payload is
// shorter than a UDP header is not dropped as too short. Such a fragment
// carries no L4 header, so the 8-byte L4 minimum does not apply to it.
// See https://github.com/projectcalico/calico/issues/14052
func TestIP4FragShortTail(t *testing.T) {
	RegisterTestingT(t)

	defer resetCTMap(ctMap)
	defer cleanupMap(ipfragsFwdMap)

	bpfIfaceName = "FRST"
	defer func() { bpfIfaceName = "" }()

	firstData := make([]byte, 40)
	for i := range firstData {
		firstData[i] = byte(i)
	}

	ipHdr := *ipv4Default
	ipHdr.Id = 0x4321
	ipHdr.Flags = layers.IPv4MoreFragments
	ipHdr.FragOffset = 0
	ipHdr.Length = uint16(20 + 8 + len(firstData))
	udp := *udpDefault
	// The length of the whole datagram, 1 byte ends up in the last fragment.
	udp.Length = uint16(8 + len(firstData) + 1)
	_ = udp.SetNetworkLayerForChecksum(&ipHdr)

	pktFirst := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pktFirst, gopacket.SerializeOptions{ComputeChecksums: true},
		ethDefault, &ipHdr, &udp, gopacket.Payload(firstData))
	Expect(err).NotTo(HaveOccurred())

	ipHdr.Flags = 0
	ipHdr.FragOffset = uint16((8 + len(firstData)) / 8)
	ipHdr.Length = 20 + 1

	// Serialize the tail without the Ethernet layer as it would pad the frame
	// to the Ethernet minimum and the padding would hide the short payload.
	ipTail := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(ipTail, gopacket.SerializeOptions{ComputeChecksums: true},
		&ipHdr, gopacket.Payload([]byte{0xab}))
	Expect(err).NotTo(HaveOccurred())

	pktTail := append([]byte{}, ethDefault.DstMAC...)
	pktTail = append(pktTail, ethDefault.SrcMAC...)
	pktTail = append(pktTail, 0x08, 0x00)
	pktTail = append(pktTail, ipTail.Bytes()...)
	Expect(pktTail).To(HaveLen(14 + 20 + 1))

	t.Run("from workload", func(t *testing.T) {
		RegisterTestingT(t)

		resetCTMap(ctMap)
		cleanupMap(ipfragsFwdMap)

		rtKey := routes.NewKey(srcV4CIDR).AsBytes()
		rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
		defer resetRTMap(rtMap)
		err := rtMap.Update(rtKey, rtVal)
		Expect(err).NotTo(HaveOccurred())

		var firstRetval int

		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktFirst.Bytes())
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RetvalStr()).NotTo(Equal("TC_ACT_SHOT"))
			firstRetval = res.Retval
		})

		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktTail)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(firstRetval))
		})
	})

	t.Run("from host", func(t *testing.T) {
		RegisterTestingT(t)

		resetCTMap(ctMap)
		cleanupMap(ipfragsFwdMap)

		skbMark = 0
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktFirst.Bytes())
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		})

		skbMark = 0
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktTail)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		})
	})
}
