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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// stubCalicoClient is a Calico client that serves a stub IPAM. Other methods panic through the
// nil embedded interface.
type stubCalicoClient struct {
	calicoclient.Interface
	ipam ipam.Interface
}

func (c stubCalicoClient) IPAM() ipam.Interface {
	return c.ipam
}

// stubHandleIPAM is an ipam.Interface that serves a fixed IPsByHandle answer and records what
// ReleaseIPs and ReleaseByHandle are asked to release, and each call's context error. Other
// methods panic through the nil embedded interface.
type stubHandleIPAM struct {
	ipam.Interface
	ips             []cnet.IP
	ipsErr          error
	released        []ipam.ReleaseOptions
	releasedHandles []string
	ctxErrs         []error
}

func (s *stubHandleIPAM) IPsByHandle(ctx context.Context, _ string) ([]cnet.IP, error) {
	s.ctxErrs = append(s.ctxErrs, ctx.Err())
	return s.ips, s.ipsErr
}

func (s *stubHandleIPAM) ReleaseIPs(ctx context.Context, opts ...ipam.ReleaseOptions) ([]cnet.IP, []ipam.ReleaseOptions, error) {
	s.ctxErrs = append(s.ctxErrs, ctx.Err())
	s.released = append(s.released, opts...)
	return nil, nil, nil
}

func (s *stubHandleIPAM) ReleaseByHandle(ctx context.Context, handleID string) error {
	s.ctxErrs = append(s.ctxErrs, ctx.Err())
	s.releasedHandles = append(s.releasedHandles, handleID)
	return nil
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
	errStubIPAMDel = errors.New("IPAM DEL failed")
)

// releaseCase is one releaseUnusedAddresses scenario: the sandbox's IPAM type and pod, the
// pod's endpoint, how the handle lookup and the IPAM plugin answer, and the expected IPAM DEL,
// whole-handle releases, single-address releases and error.
type releaseCase struct {
	ipamType     string
	pod          string
	wep          *internalapi.WorkloadEndpoint
	handleIPs    []string
	ipsErr       error
	delErr       error
	wantIPAMDel  bool
	wantHandles  bool
	wantReleased []string
	wantErr      error
}

var _ = Describe("releaseUnusedAddresses", func() {
	const network, namespace, sandbox, otherSandbox = "k8s-pod-network", "ns", "sandbox-y", "sandbox-x"
	handle := ipam.PodHandleID(network, sandbox)
	logger := logrus.WithField("test", "releaseUnusedAddresses")

	var fake *fakeIPAMExec
	BeforeEach(func() {
		fake = &fakeIPAMExec{}
		utils.IPAMExec = fake
		DeferCleanup(func() { utils.IPAMExec = nil })
		GinkgoT().Setenv("CNI_COMMAND", "ADD")
	})

	sandboxConf := func(ipamType, pod string) (types.NetConf, *skel.CmdArgs) {
		conf := types.NetConf{Name: network, Nodename: "node1", IPAMLockFile: filepath.Join(GinkgoT().TempDir(), "ipam.lock")}
		conf.IPAM.Type = ipamType
		args := &skel.CmdArgs{
			ContainerID: sandbox,
			IfName:      "eth0",
			Args:        "K8S_POD_NAMESPACE=" + namespace + ";K8S_POD_NAME=" + pod,
			StdinData:   fmt.Appendf(nil, `{"ipam":{"type":%q}}`, ipamType),
		}
		return conf, args
	}

	// podContext carries the pod the way the calico plugin passes it to calico-ipam, so a
	// virt-launcher pod's VMI check reads it instead of calling the API server.
	podContext := func(ctx context.Context, pod string) context.Context {
		return utils.WithSandboxLookups(ctx, utils.SandboxLookups{
			Pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: namespace}},
		})
	}

	release := func(ctx context.Context, stub ipam.Interface, ipamType, pod string, wep *internalapi.WorkloadEndpoint) error {
		conf, args := sandboxConf(ipamType, pod)
		return releaseUnusedAddresses(podContext(ctx, pod), stubCalicoClient{ipam: stub}, conf, args, wep, logger)
	}

	DescribeTable("decides what to keep and which release runs",
		func(c releaseCase) {
			fake.delErr = c.delErr
			stub := &stubHandleIPAM{ips: stubIPs(c.handleIPs...), ipsErr: c.ipsErr}

			err := release(context.Background(), stub, c.ipamType, c.pod, c.wep)

			if c.wantErr != nil {
				Expect(err).To(MatchError(c.wantErr))
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			if c.wantIPAMDel {
				Expect(fake.callsFor("DEL")).To(HaveLen(1))
			} else {
				Expect(fake.calls).To(BeEmpty())
			}
			if c.wantHandles {
				Expect(stub.releasedHandles).To(Equal([]string{handle, namespace + "." + c.pod}))
			} else {
				Expect(stub.releasedHandles).To(BeEmpty(), "released a whole handle")
			}
			var released []string
			for _, opt := range stub.released {
				Expect(opt.Handle).To(Equal(handle))
				released = append(released, opt.Address)
			}
			Expect(released).To(ConsistOf(c.wantReleased))
			Expect(os.Getenv("CNI_COMMAND")).To(Equal("ADD"))
		},
		Entry("no endpoint releases the sandbox's handles whole", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", handleIPs: []string{"10.0.0.6"},
			wantHandles: true,
		}),
		Entry("an endpoint naming this sandbox releases its handles whole despite listing an address", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", wep: wepOnSandbox(sandbox, "10.0.0.5/32"), handleIPs: []string{"10.0.0.5"},
			wantHandles: true,
		}),
		Entry("an endpoint naming another sandbox but listing nothing releases its handles whole", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", wep: wepOnSandbox(otherSandbox), handleIPs: []string{"10.0.0.6"},
			wantHandles: true,
		}),
		Entry("an endpoint naming another sandbox releases only unlisted addresses", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", wep: wepOnSandbox(otherSandbox, "10.0.0.5/32"), handleIPs: []string{"10.0.0.5", "10.0.0.6"},
			wantReleased: []string{"10.0.0.6"},
		}),
		Entry("an endpoint naming no sandbox keeps its addresses like one naming another sandbox", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", wep: wepOnSandbox("", "10.0.0.5/32"), handleIPs: []string{"10.0.0.5", "10.0.0.6"},
			wantReleased: []string{"10.0.0.6"},
		}),
		Entry("a virt-launcher pod that is not a VM keeps the endpoint's addresses like any pod", releaseCase{
			ipamType: "calico-ipam", pod: "virt-launcher-vm1-abcde", wep: wepOnSandbox(otherSandbox, "10.0.0.5/32"), handleIPs: []string{"10.0.0.5", "10.0.0.6"},
			wantReleased: []string{"10.0.0.6"},
		}),
		Entry("a calico-ipam release error is returned", releaseCase{
			ipamType: "calico-ipam", pod: "web-0", wep: wepOnSandbox(otherSandbox, "10.0.0.5/32"), ipsErr: errStubLookup,
			wantErr: errStubLookup,
		}),
		Entry("another IPAM type runs its plugin's DEL despite an address to keep", releaseCase{
			ipamType: "host-local", pod: "web-0", wep: wepOnSandbox(otherSandbox, "10.0.0.5/32"), handleIPs: []string{"10.0.0.5"},
			wantIPAMDel: true,
		}),
		Entry("another IPAM type's DEL error is returned", releaseCase{
			ipamType: "host-local", pod: "web-0", delErr: errStubIPAMDel,
			wantIPAMDel: true, wantErr: errStubIPAMDel,
		}),
	)

	It("still looks up and releases after the caller's context is canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.5", "10.0.0.6")}

		Expect(release(ctx, stub, "calico-ipam", "web-0", wepOnSandbox(otherSandbox, "10.0.0.5/32"))).To(Succeed())

		Expect(stub.released).To(Equal([]ipam.ReleaseOptions{{Address: "10.0.0.6", Handle: handle}}))
		Expect(stub.ctxErrs).To(HaveLen(2))
		Expect(stub.ctxErrs).To(HaveEach(BeNil()))
	})

	It("judges a failed ADD by the endpoint as the ADD found it, not as the ADD rewrote it", func() {
		stub := &stubHandleIPAM{ips: stubIPs("10.0.0.5", "10.0.0.6")}
		conf, args := sandboxConf("calico-ipam", "web-0")
		endpoint := wepOnSandbox(otherSandbox, "10.0.0.5/32")
		cleanup := failedAddCleanup(context.Background(), stubCalicoClient{ipam: stub}, conf, args, endpoint, logger)

		// The ADD rewrites the endpoint like this before a later step can fail.
		endpoint.Spec.ContainerID = sandbox
		endpoint.Spec.IPNetworks = []string{"10.0.0.6/32"}
		cleanup()

		Expect(stub.releasedHandles).To(BeEmpty(), "a whole-handle release frees the pod's address")
		Expect(stub.released).To(Equal([]ipam.ReleaseOptions{{Address: "10.0.0.6", Handle: handle}}))
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

// wepOnSandbox returns an endpoint that names containerID as its sandbox and lists nets.
func wepOnSandbox(containerID string, nets ...string) *internalapi.WorkloadEndpoint {
	wep := wepWithNetworks(nets...)
	wep.Spec.ContainerID = containerID
	return wep
}
