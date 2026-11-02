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

package k8s

import (
	"context"
	"errors"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// stubHandleIPAM is an ipam.Interface that serves a fixed IPsByHandle answer and records
// what ReleaseIPs is asked to release. Other methods panic through the nil embedded interface.
type stubHandleIPAM struct {
	ipam.Interface
	ips        []cnet.IP
	ipsErr     error
	releaseErr error
	released   []ipam.ReleaseOptions
}

func (s *stubHandleIPAM) IPsByHandle(_ context.Context, _ string) ([]cnet.IP, error) {
	return s.ips, s.ipsErr
}

func (s *stubHandleIPAM) ReleaseIPs(_ context.Context, opts ...ipam.ReleaseOptions) ([]cnet.IP, []ipam.ReleaseOptions, error) {
	s.released = append(s.released, opts...)
	return nil, nil, s.releaseErr
}

func stubIPs(addrs ...string) []cnet.IP {
	var ips []cnet.IP
	for _, a := range addrs {
		ips = append(ips, cnet.IP{IP: net.ParseIP(a)})
	}
	return ips
}

var _ = Describe("releaseUnlisted", func() {
	const handle = "k8s-pod-network.sandbox-y"
	logger := logrus.WithField("test", "releaseUnlisted")

	It("releases only the unlisted address and reports it kept one", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.5", "10.0.0.6")}
		kept, err := releaseUnlisted(context.Background(), stub, handle, set.From("10.0.0.5"), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(BeTrue())
		Expect(stub.released).To(Equal([]ipam.ReleaseOptions{{Address: "10.0.0.6", Handle: handle}}))
	})

	It("releases every address when none is listed and reports none kept", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.6", "fd00::6")}
		kept, err := releaseUnlisted(context.Background(), stub, handle, set.New[string](), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(BeFalse())
		Expect(stub.released).To(ConsistOf(
			ipam.ReleaseOptions{Address: "10.0.0.6", Handle: handle},
			ipam.ReleaseOptions{Address: "fd00::6", Handle: handle},
		))
	})

	It("releases nothing when every address on the handle is listed", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.5")}
		kept, err := releaseUnlisted(context.Background(), stub, handle, set.From("10.0.0.5"), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(BeTrue())
		Expect(stub.released).To(BeEmpty())
	})

	It("treats a missing handle as nothing to release", func() {
		stub := &stubHandleIPAM{ipsErr: cerrors.ErrorResourceDoesNotExist{}}
		kept, err := releaseUnlisted(context.Background(), stub, handle, set.From("10.0.0.5"), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(BeFalse())
		Expect(stub.released).To(BeEmpty())
	})

	It("returns any other IPsByHandle error without releasing", func() {
		boom := errors.New("datastore down")
		stub := &stubHandleIPAM{ipsErr: boom}
		_, err := releaseUnlisted(context.Background(), stub, handle, set.New[string](), logger)
		Expect(err).To(MatchError(boom))
		Expect(stub.released).To(BeEmpty())
	})

	It("returns a ReleaseIPs error", func() {
		boom := errors.New("release failed")
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.6"), releaseErr: boom}
		_, err := releaseUnlisted(context.Background(), stub, handle, set.New[string](), logger)
		Expect(err).To(MatchError(boom))
	})
})

var _ = DescribeTable("listedAddresses",
	func(wep *internalapi.WorkloadEndpoint, want []string) {
		got := listedAddresses(wep)
		Expect(got.Len()).To(Equal(len(want)))
		for _, ip := range want {
			Expect(got.Contains(ip)).To(BeTrue(), "missing %s", ip)
		}
	},
	Entry("a nil endpoint lists nothing", nil, nil),
	Entry("an endpoint with no networks lists nothing", &internalapi.WorkloadEndpoint{}, nil),
	Entry("dual-stack networks give both bare IPs", wepWithNetworks("10.0.0.5/32", "fd00::5/128"), []string{"10.0.0.5", "fd00::5"}),
	Entry("an unparseable entry is skipped", wepWithNetworks("10.0.0.5/32", "garbage"), []string{"10.0.0.5"}),
)

var _ = DescribeTable("keepsListedAddresses",
	func(ipamType, pod, ipAddrsNoIpam string, want bool) {
		conf := types.NetConf{}
		conf.IPAM.Type = ipamType
		Expect(keepsListedAddresses(conf, utils.WEPIdentifiers{Pod: pod}, ipAddrsNoIpam)).To(Equal(want))
	},
	Entry("calico-ipam, ordinary pod", "calico-ipam", "web-0", "", true),
	Entry("another IPAM type", "host-local", "web-0", "", false),
	Entry("a virt-launcher pod", "calico-ipam", "virt-launcher-vm1-abcde", "", false),
	Entry("ipAddrsNoIpam is set", "calico-ipam", "web-0", `["10.0.0.1"]`, false),
)

func wepWithNetworks(nets ...string) *internalapi.WorkloadEndpoint {
	wep := internalapi.NewWorkloadEndpoint()
	wep.Spec.IPNetworks = nets
	return wep
}
