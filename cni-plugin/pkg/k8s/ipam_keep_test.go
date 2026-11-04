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
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/gofrs/flock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// stubHandleIPAM is an ipam.Interface that serves a fixed IPsByHandle answer and records
// what ReleaseIPs is asked to release. Other methods panic through the nil embedded interface.
// Each call also records its context's error and, when lockPath is set, whether that lock
// was free.
type stubHandleIPAM struct {
	ipam.Interface
	ips        []cnet.IP
	ipsErr     error
	releaseErr error
	released   []ipam.ReleaseOptions
	lockPath   string
	ctxErrs    []error
	lockFree   []bool
}

func (s *stubHandleIPAM) IPsByHandle(ctx context.Context, _ string) ([]cnet.IP, error) {
	s.observe(ctx)
	return s.ips, s.ipsErr
}

func (s *stubHandleIPAM) ReleaseIPs(ctx context.Context, opts ...ipam.ReleaseOptions) ([]cnet.IP, []ipam.ReleaseOptions, error) {
	s.observe(ctx)
	s.released = append(s.released, opts...)
	return nil, nil, s.releaseErr
}

func (s *stubHandleIPAM) observe(ctx context.Context) {
	s.ctxErrs = append(s.ctxErrs, ctx.Err())
	if s.lockPath != "" {
		s.lockFree = append(s.lockFree, lockIsFree(s.lockPath))
	}
}

// lockIsFree reports whether another holder could take the flock at path.
func lockIsFree(path string) bool {
	lock := flock.New(path)
	locked, err := lock.TryLock()
	Expect(err).NotTo(HaveOccurred())
	if locked {
		Expect(lock.Unlock()).To(Succeed())
	}
	return locked
}

func stubIPs(addrs ...string) []cnet.IP {
	var ips []cnet.IP
	for _, a := range addrs {
		ips = append(ips, cnet.IP{IP: net.ParseIP(a)})
	}
	return ips
}

var (
	errStubLookup  = errors.New("datastore down")
	errStubRelease = errors.New("release failed")
	errStubIPAMDel = errors.New("IPAM DEL failed")
)

// releaseCase is one releaseSandboxAddresses scenario: the sandbox's IPAM type and pod, the
// addresses to keep, how the handle lookup, ReleaseIPs and the IPAM plugin answer, and the
// expected IPAM DEL, direct releases and error.
type releaseCase struct {
	ipamType     string
	pod          string
	keep         []string
	handleIPs    []string
	ipsErr       error
	releaseErr   error
	delErr       error
	wantIPAMDel  bool
	wantReleased []string
	wantErr      error
}

var _ = Describe("releaseSandboxAddresses", func() {
	const network, sandbox = "k8s-pod-network", "sandbox-y"
	handle := ipam.PodHandleID(network, sandbox)
	logger := logrus.WithField("test", "releaseSandboxAddresses")

	var fake *fakeIPAMExec
	var lockPath string
	BeforeEach(func() {
		fake = &fakeIPAMExec{}
		utils.IPAMExec = fake
		DeferCleanup(func() { utils.IPAMExec = nil })
		GinkgoT().Setenv("CNI_COMMAND", "ADD")
		lockPath = filepath.Join(GinkgoT().TempDir(), "ipam.lock")
	})

	release := func(ctx context.Context, stub ipam.Interface, ipamType, pod string, keep ...string) error {
		conf := types.NetConf{Name: network, IPAMLockFile: lockPath}
		conf.IPAM.Type = ipamType
		args := &skel.CmdArgs{ContainerID: sandbox, StdinData: fmt.Appendf(nil, `{"ipam":{"type":%q}}`, ipamType)}
		var keepAddresses []net.IP
		for _, k := range keep {
			keepAddresses = append(keepAddresses, net.ParseIP(k))
		}
		return releaseSandboxAddresses(ctx, stub, conf, args, utils.WEPIdentifiers{Pod: pod}, keepAddresses, logger)
	}

	DescribeTable("chooses between the IPAM DEL and releasing only unkept addresses",
		func(c releaseCase) {
			fake.delErr = c.delErr
			stub := &stubHandleIPAM{ips: stubIPs(c.handleIPs...), ipsErr: c.ipsErr, releaseErr: c.releaseErr}

			err := release(context.Background(), stub, c.ipamType, c.pod, c.keep...)

			if c.wantErr != nil {
				Expect(err).To(MatchError(c.wantErr))
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			if c.wantIPAMDel {
				Expect(fake.callsFor("DEL")).To(HaveLen(1))
				Expect(stub.ctxErrs).To(BeEmpty(), "the handle was read directly as well")
			} else {
				Expect(fake.calls).To(BeEmpty())
			}
			var released []string
			for _, opt := range stub.released {
				Expect(opt.Handle).To(Equal(handle))
				released = append(released, opt.Address)
			}
			Expect(released).To(ConsistOf(c.wantReleased))
			Expect(os.Getenv("CNI_COMMAND")).To(Equal("ADD"))
		},
		Entry("nothing to keep runs the IPAM DEL", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", handleIPs: []string{"10.0.0.6"},
			wantIPAMDel: true,
		}),
		Entry("another IPAM type runs the IPAM DEL despite addresses to keep", releaseCase{
			ipamType: "host-local", pod: "web-0", keep: []string{"10.0.0.5"}, handleIPs: []string{"10.0.0.5"},
			wantIPAMDel: true,
		}),
		Entry("a virt-launcher pod runs the IPAM DEL despite addresses to keep", releaseCase{
			ipamType: "calico-ipam", pod: "virt-launcher-vm1-abcde", keep: []string{"10.0.0.5"}, handleIPs: []string{"10.0.0.5"},
			wantIPAMDel: true,
		}),
		Entry("addresses to keep release only the others, without the IPAM DEL", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", keep: []string{"10.0.0.5"}, handleIPs: []string{"10.0.0.5", "10.0.0.6", "fd00::6"},
			wantReleased: []string{"10.0.0.6", "fd00::6"},
		}),
		Entry("an IPv6 address kept in a longer textual form still matches the handle's", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", keep: []string{"fd00:0:0:0:0:0:0:5"}, handleIPs: []string{"fd00::5", "fd00::6"},
			wantReleased: []string{"fd00::6"},
		}),
		Entry("a handle holding only kept addresses releases nothing", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", keep: []string{"10.0.0.5"}, handleIPs: []string{"10.0.0.5"},
		}),
		Entry("a missing handle is nothing to release, without the IPAM DEL", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", keep: []string{"10.0.0.5"}, ipsErr: cerrors.ErrorResourceDoesNotExist{},
		}),
		Entry("another handle lookup error is returned, without the IPAM DEL", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", keep: []string{"10.0.0.5"}, ipsErr: errStubLookup,
			wantErr: errStubLookup,
		}),
		Entry("a ReleaseIPs error is returned", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", keep: []string{"10.0.0.5"}, handleIPs: []string{"10.0.0.6"}, releaseErr: errStubRelease,
			wantReleased: []string{"10.0.0.6"}, wantErr: errStubRelease,
		}),
		Entry("an IPAM DEL error is returned", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", delErr: errStubIPAMDel,
			wantIPAMDel: true, wantErr: errStubIPAMDel,
		}),
	)

	It("still looks up and releases after the caller's context is canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.5", "10.0.0.6")}

		Expect(release(ctx, stub, "calico-ipam", "web-0", "10.0.0.5")).To(Succeed())

		Expect(stub.released).To(Equal([]ipam.ReleaseOptions{{Address: "10.0.0.6", Handle: handle}}))
		Expect(stub.ctxErrs).To(HaveLen(2))
		Expect(stub.ctxErrs).To(HaveEach(BeNil()))
	})

	It("holds the host IPAM lock while it looks up and releases, and frees it after", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.6"), lockPath: lockPath}

		Expect(release(context.Background(), stub, "calico-ipam", "web-0", "10.0.0.5")).To(Succeed())

		Expect(stub.lockFree).To(Equal([]bool{false, false}))
		Expect(lockIsFree(lockPath)).To(BeTrue())
	})
})

var _ = DescribeTable("addressesFromEndpoint",
	func(wep *internalapi.WorkloadEndpoint, want []string) {
		var got []string
		for _, ip := range addressesFromEndpoint(wep, logrus.WithField("test", "addressesFromEndpoint")) {
			got = append(got, ip.String())
		}
		Expect(got).To(Equal(want))
	},
	Entry("a nil endpoint has none", nil, nil),
	Entry("an endpoint with no networks has none", &internalapi.WorkloadEndpoint{}, nil),
	Entry("IPv6 then IPv4 give both bare IPs in that order", wepWithNetworks("fd00::5/128", "10.0.0.5/32"), []string{"fd00::5", "10.0.0.5"}),
	Entry("IPv4 then IPv6 give both bare IPs in that order", wepWithNetworks("10.0.0.5/32", "fd00::5/128"), []string{"10.0.0.5", "fd00::5"}),
	Entry("an unparsable entry is skipped and the rest kept", wepWithNetworks("garbage", "10.0.0.5/32", "10.0.0.6"), []string{"10.0.0.5"}),
)

func wepWithNetworks(nets ...string) *internalapi.WorkloadEndpoint {
	wep := internalapi.NewWorkloadEndpoint()
	wep.Spec.IPNetworks = nets
	return wep
}
