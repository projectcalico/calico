// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
)

func TestIPv4Opts(t *testing.T) {
	RegisterTestingT(t)

	ipHdr := *ipv4Default
	ipHdr.Options = []layers.IPv4Option{{
		OptionType:   123,
		OptionLength: 6,
		OptionData:   []byte{0xde, 0xad, 0xbe, 0xef},
	}}
	ipHdr.IHL += 2

	_, ipv4, l4, payload, pktBytes, err := testPacket(nil, &ipHdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	runBpfUnitTest(t, "ipv4_opts_test.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(HaveLen(len(pktBytes) + 50))

		checkVxlanEncap(pktR, true, ipv4, udp, payload)
	})
}

func BenchmarkPktAccess(b *testing.B) {
	RegisterTestingT(b)

	ipHdr := *ipv4Default

	_, _, _, _, pktBytes, err := testPacket(nil, &ipHdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	source := "ipv4_opts_test.c"
	objFname := "../../bpf-gpl/ut/" + strings.TrimSuffix(source, path.Ext(source)) + ".o"

	tempDir, err := os.MkdirTemp("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)
	obj, err := objUTLoad(objFname, bpfFsDir, "IPv4", testOpts{}, true, false)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = obj.UnpinPrograms(bpfFsDir) }()
	defer obj.Close()

	ctxIn := make([]byte, 18*4)

	b.ResetTimer()
	res, err := bpftoolProgRunN(bpfFsDir+"/classifier_calico_unittest", pktBytes, ctxIn, b.N)
	b.StopTimer()
	Expect(err).NotTo(HaveOccurred())
	Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	fmt.Printf("%7d iterations avg %d\n", b.N, res.Duration)
}
