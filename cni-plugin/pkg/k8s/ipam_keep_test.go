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
	"path/filepath"

	"github.com/gofrs/flock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
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
	attrs      map[string]*model.AllocationAttribute
	attrErrs   map[string]error
	lockPath   string
	ctxErrs    []error
	lockFree   []bool
}

func (s *stubHandleIPAM) IPsByHandle(ctx context.Context, _ string) ([]cnet.IP, error) {
	s.observe(ctx)
	return s.ips, s.ipsErr
}

func (s *stubHandleIPAM) GetAssignmentAttributes(ctx context.Context, addr cnet.IP) (*model.AllocationAttribute, error) {
	s.observe(ctx)
	if err, ok := s.attrErrs[addr.String()]; ok {
		return nil, err
	}
	return s.attrs[addr.String()], nil
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

var _ = Describe("releaseUnlisted", func() {
	const handle = "k8s-pod-network.sandbox-y"
	logger := logrus.WithField("test", "releaseUnlisted")

	var lockPath string
	BeforeEach(func() {
		lockPath = filepath.Join(GinkgoT().TempDir(), "ipam.lock")
	})

	It("still looks up and releases after the caller's context is canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.6")}

		_, err := releaseUnlisted(ctx, stub, handle, lockPath, set.New[string](), logger)

		Expect(err).NotTo(HaveOccurred())
		Expect(stub.released).To(Equal([]ipam.ReleaseOptions{{Address: "10.0.0.6", Handle: handle}}))
		Expect(stub.ctxErrs).To(HaveLen(2))
		Expect(stub.ctxErrs).To(HaveEach(BeNil()))
	})

	It("holds the host IPAM lock while it looks up and releases, and frees it after", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.6"), lockPath: lockPath}

		_, err := releaseUnlisted(context.Background(), stub, handle, lockPath, set.New[string](), logger)

		Expect(err).NotTo(HaveOccurred())
		Expect(stub.lockFree).To(Equal([]bool{false, false}))
		Expect(lockIsFree(lockPath)).To(BeTrue())
	})

	It("releases only the unlisted address and reports it kept one", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.5", "10.0.0.6")}
		kept, err := releaseUnlisted(context.Background(), stub, handle, lockPath, set.From("10.0.0.5"), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(BeTrue())
		Expect(stub.released).To(Equal([]ipam.ReleaseOptions{{Address: "10.0.0.6", Handle: handle}}))
	})

	It("releases every address when none is listed and reports none kept", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.6", "fd00::6")}
		kept, err := releaseUnlisted(context.Background(), stub, handle, lockPath, set.New[string](), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(BeFalse())
		Expect(stub.released).To(ConsistOf(ipam.ReleaseOptions{Address: "10.0.0.6", Handle: handle}, ipam.ReleaseOptions{Address: "fd00::6", Handle: handle}))
	})

	It("releases nothing when every address on the handle is listed", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.5")}
		kept, err := releaseUnlisted(context.Background(), stub, handle, lockPath, set.From("10.0.0.5"), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(BeTrue())
		Expect(stub.released).To(BeEmpty())
	})

	It("treats a missing handle as nothing to release", func() {
		stub := &stubHandleIPAM{ipsErr: cerrors.ErrorResourceDoesNotExist{}}
		kept, err := releaseUnlisted(context.Background(), stub, handle, lockPath, set.From("10.0.0.5"), logger)
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(BeFalse())
		Expect(stub.released).To(BeEmpty())
	})

	It("returns any other IPsByHandle error without releasing", func() {
		boom := errors.New("datastore down")
		stub := &stubHandleIPAM{ipsErr: boom}
		_, err := releaseUnlisted(context.Background(), stub, handle, lockPath, set.New[string](), logger)
		Expect(err).To(MatchError(boom))
		Expect(stub.released).To(BeEmpty())
	})

	It("returns a ReleaseIPs error", func() {
		boom := errors.New("release failed")
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.6"), releaseErr: boom}
		_, err := releaseUnlisted(context.Background(), stub, handle, lockPath, set.New[string](), logger)
		Expect(err).To(MatchError(boom))
	})
})

var _ = Describe("releaseListedElsewhere", func() {
	const network = "k8s-pod-network"
	owner := ipam.AttributeOwner{Namespace: "ns", Name: "web-0"}
	logger := logrus.WithField("test", "releaseListedElsewhere")
	sandboxHandle := ipam.PodHandleID(network, "sandbox-x")

	allocation := func(handle, pod string) *model.AllocationAttribute {
		return &model.AllocationAttribute{
			HandleID:         &handle,
			ActiveOwnerAttrs: map[string]string{ipam.AttributeNamespace: "ns", ipam.AttributePod: pod},
		}
	}

	var lockPath string
	BeforeEach(func() {
		lockPath = filepath.Join(GinkgoT().TempDir(), "ipam.lock")
	})

	It("releases only the pod's addresses on a sandbox handle of this network, by that handle", func() {
		stub := &stubHandleIPAM{attrs: map[string]*model.AllocationAttribute{
			"10.0.0.5": allocation(sandboxHandle, "web-0"),
			"10.0.0.6": allocation(sandboxHandle, "other"),
			"10.0.0.7": allocation("victim-workload", "web-0"),
			"10.0.0.8": allocation(ipam.PodHandleID("other-network", "sandbox-x"), "web-0"),
			"10.0.0.9": {},
		}}

		err := releaseListedElsewhere(context.Background(), stub, network, lockPath, owner, set.From("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"), logger)

		Expect(err).NotTo(HaveOccurred())
		Expect(stub.released).To(Equal([]ipam.ReleaseOptions{{Address: "10.0.0.5", Handle: sandboxHandle}}))
	})

	It("treats an address that is already free or cooling down as released", func() {
		stub := &stubHandleIPAM{attrErrs: map[string]error{
			"10.0.0.5": cerrors.ErrorResourceDoesNotExist{},
			"10.0.0.6": cerrors.ErrorIPInCooldown{},
		}}

		err := releaseListedElsewhere(context.Background(), stub, network, lockPath, owner, set.From("10.0.0.5", "10.0.0.6"), logger)

		Expect(err).NotTo(HaveOccurred())
		Expect(stub.released).To(BeEmpty())
	})

	It("returns read and release errors after trying every address", func() {
		readErr, releaseErr := errors.New("datastore down"), errors.New("release failed")
		stub := &stubHandleIPAM{
			attrs:      map[string]*model.AllocationAttribute{"10.0.0.6": allocation(sandboxHandle, "web-0")},
			attrErrs:   map[string]error{"10.0.0.5": readErr},
			releaseErr: releaseErr,
		}

		err := releaseListedElsewhere(context.Background(), stub, network, lockPath, owner, set.From("10.0.0.5", "10.0.0.6"), logger)

		Expect(err).To(MatchError(readErr))
		Expect(err).To(MatchError(releaseErr))
		Expect(stub.released).To(HaveLen(1))
	})

	It("works under the host IPAM lock after the caller's context is canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		stub := &stubHandleIPAM{attrs: map[string]*model.AllocationAttribute{"10.0.0.5": allocation(sandboxHandle, "web-0")}, lockPath: lockPath}

		err := releaseListedElsewhere(ctx, stub, network, lockPath, owner, set.From("10.0.0.5"), logger)

		Expect(err).NotTo(HaveOccurred())
		Expect(stub.released).To(HaveLen(1))
		Expect(stub.ctxErrs).To(HaveEach(BeNil()))
		Expect(stub.lockFree).To(Equal([]bool{false, false}))
	})
})

var _ = DescribeTable("endpointIPs",
	func(wep *internalapi.WorkloadEndpoint, want []string) {
		var got []string
		for _, ip := range endpointIPs(wep, logrus.WithField("test", "endpointIPs")) {
			got = append(got, ip.String())
		}
		Expect(got).To(Equal(want))
	},
	Entry("a nil endpoint records nothing", nil, nil),
	Entry("an endpoint with no networks records nothing", &internalapi.WorkloadEndpoint{}, nil),
	Entry("dual-stack networks give both bare IPs in order", wepWithNetworks("fd00::5/128", "10.0.0.5/32"), []string{"fd00::5", "10.0.0.5"}),
	Entry("an unparsable entry is skipped and the rest kept", wepWithNetworks("garbage", "10.0.0.5/32", "10.0.0.6"), []string{"10.0.0.5"}),
)

var _ = DescribeTable("listedAddresses",
	func(wep *internalapi.WorkloadEndpoint, want []string) {
		got := listedAddresses(wep, logrus.WithField("test", "listedAddresses"))
		Expect(got.Len()).To(Equal(len(want)))
		for _, ip := range want {
			Expect(got.Contains(ip)).To(BeTrue(), "missing %s", ip)
		}
	},
	Entry("a nil endpoint lists nothing", nil, nil),
	Entry("dual-stack networks give both bare IPs", wepWithNetworks("10.0.0.5/32", "fd00::5/128"), []string{"10.0.0.5", "fd00::5"}),
	Entry("an unparsable entry is skipped", wepWithNetworks("10.0.0.5/32", "garbage"), []string{"10.0.0.5"}),
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
