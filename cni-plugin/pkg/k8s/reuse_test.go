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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
)

const (
	singleStackStdin = `{"cniVersion":"1.0.0","name":"calico-uts","type":"calico","ipam":{"type":"calico-ipam"}}`
	dualStackStdin   = `{"cniVersion":"1.0.0","name":"calico-uts","type":"calico","ipam":{"type":"calico-ipam","assign_ipv6":"true"}}`
)

// freshAddExpectation says what fresh (no IP=) ADD a reuse test expects.
type freshAddExpectation int

const (
	expectNoFreshAdd freshAddExpectation = iota
	expectFreshAddWithOriginalStdin
	expectFreshAddForIPv6Only
	expectFreshAddForIPv4Only
)

// reuseCase is one row of the reuse policy table.
type reuseCase struct {
	endpointIPs []string
	dualStack   bool
	addErrs     map[string]error
	wantErr     bool
	wantErrCode uint
	wantIPs     []string
	wantFresh   freshAddExpectation
}

var _ = Describe("assignPodIPs", func() {
	var fake *fakeIPAMExec

	BeforeEach(func() {
		fake = &fakeIPAMExec{fresh: []string{"10.0.0.99", "fd00::99"}}
		utils.IPAMExec = fake
		DeferCleanup(func() { utils.IPAMExec = nil })
		GinkgoT().Setenv("CNI_ARGS", "IgnoreUnknown=1;K8S_POD_NAME=web-0")
	})

	run := func(endpointIPs []string, stdin string) ([]string, error) {
		conf := types.NetConf{}
		conf.IPAM.Type = "calico-ipam"
		args := &skel.CmdArgs{
			ContainerID: "sandbox-y",
			Args:        "IgnoreUnknown=1;K8S_POD_NAME=web-0",
			StdinData:   []byte(stdin),
		}
		ep := internalapi.NewWorkloadEndpoint()
		for _, ip := range endpointIPs {
			bits := "/32"
			if ip[0] == 'f' {
				bits = "/128"
			}
			ep.Spec.IPNetworks = append(ep.Spec.IPNetworks, ip+bits)
		}
		result, err := assignPodIPs(context.Background(), conf, args, utils.WEPIdentifiers{Pod: "web-0"}, ep, logrus.WithField("test", "reuse"))
		if err != nil {
			return nil, err
		}
		var resultIPs []string
		for _, ip := range result.IPs {
			resultIPs = append(resultIPs, ip.Address.IP.String())
		}
		return resultIPs, nil
	}

	DescribeTable("reuse policy",
		func(e reuseCase) {
			fake.addErrs = e.addErrs
			stdin := singleStackStdin
			if e.dualStack {
				stdin = dualStackStdin
			}

			ips, err := run(e.endpointIPs, stdin)

			if e.wantErr {
				Expect(err).To(HaveOccurred())
				Expect(isAddressNotHeld(err)).To(BeFalse(), "only a lost address may be reported as not held")
				if e.wantErrCode != 0 {
					var cniErr *cnitypes.Error
					Expect(errors.As(err, &cniErr)).To(BeTrue(), "expected a CNI error, got: %v", err)
					Expect(cniErr.Code).To(Equal(e.wantErrCode))
				}
			} else {
				Expect(err).NotTo(HaveOccurred())
				Expect(ips).To(Equal(e.wantIPs))
			}
			Expect(fake.callsFor("DEL")).To(BeEmpty(), "reuse must never release")

			fresh := fake.freshAdds()
			switch e.wantFresh {
			case expectNoFreshAdd:
				Expect(fresh).To(BeEmpty())
			case expectFreshAddWithOriginalStdin:
				Expect(fresh).To(HaveLen(1))
				Expect(string(fresh[0].Stdin)).To(Equal(stdin))
			case expectFreshAddForIPv6Only:
				Expect(fresh).To(HaveLen(1))
				var conf fakeIPAMConf
				Expect(json.Unmarshal(fresh[0].Stdin, &conf)).To(Succeed())
				Expect(conf.IPAM.AssignIPv4).To(Equal("false"))
				Expect(conf.IPAM.AssignIPv6).To(Equal("true"))
			}
		},
		Entry("transient error on the second family fails the ADD", reuseCase{
			endpointIPs: []string{"10.0.0.5", "fd00::5"},
			dualStack:   true,
			addErrs:     map[string]error{"fd00::5": errors.New("etcdserver: request timed out")},
			wantErr:     true,
		}),
		Entry("transient error on a single-stack endpoint fails the ADD", reuseCase{
			endpointIPs: []string{"10.0.0.5"},
			addErrs:     map[string]error{"10.0.0.5": errors.New("etcdserver: request timed out")},
			wantErr:     true,
		}),
		Entry("lost IPv6 keeps IPv4 and assigns IPv6 only", reuseCase{
			endpointIPs: []string{"10.0.0.5", "fd00::5"},
			dualStack:   true,
			addErrs:     map[string]error{"fd00::5": cnitypes.NewError(types.ErrCodeAddressNotHeld, "not held", "")},
			wantIPs:     []string{"10.0.0.5", "fd00::99"},
			wantFresh:   expectFreshAddForIPv6Only,
		}),
		Entry("lost IPv4 keeps IPv6, assigns IPv4 only and lists IPv4 first", reuseCase{
			endpointIPs: []string{"10.0.0.5", "fd00::5"},
			dualStack:   true,
			addErrs:     map[string]error{"10.0.0.5": cnitypes.NewError(types.ErrCodeAddressNotHeld, "not held", "")},
			wantIPs:     []string{"10.0.0.99", "fd00::5"},
			wantFresh:   expectFreshAddForIPv4Only,
		}),
		Entry("lost IPv6 under a single-stack config is not requested", reuseCase{
			endpointIPs: []string{"10.0.0.5", "fd00::5"},
			addErrs:     map[string]error{"fd00::5": cnitypes.NewError(types.ErrCodeAddressNotHeld, "not held", "")},
			wantIPs:     []string{"10.0.0.5"},
			wantFresh:   expectNoFreshAdd,
		}),
		Entry("every family lost runs a normal fresh ADD", reuseCase{
			endpointIPs: []string{"10.0.0.5", "fd00::5"},
			dualStack:   true,
			addErrs: map[string]error{
				"10.0.0.5": cnitypes.NewError(types.ErrCodeAddressNotHeld, "not held", ""),
				"fd00::5":  cnitypes.NewError(types.ErrCodeAddressNotHeld, "not held", ""),
			},
			wantIPs:   []string{"10.0.0.99", "fd00::99"},
			wantFresh: expectFreshAddWithOriginalStdin,
		}),
		Entry("a superseded sandbox fails without a fresh ADD", reuseCase{
			endpointIPs: []string{"10.0.0.5"},
			addErrs:     map[string]error{"10.0.0.5": cnitypes.NewError(types.ErrCodeSandboxSuperseded, "superseded", "")},
			wantErr:     true,
			wantErrCode: types.ErrCodeSandboxSuperseded,
		}),
		Entry("an IPv4-only endpoint under a dual-stack config keeps IPv4 only", reuseCase{
			endpointIPs: []string{"10.0.0.5"},
			dualStack:   true,
			wantIPs:     []string{"10.0.0.5"},
		}),
		Entry("a lost IPv4-only endpoint under a dual-stack config uses the full config", reuseCase{
			endpointIPs: []string{"10.0.0.5"},
			dualStack:   true,
			addErrs:     map[string]error{"10.0.0.5": cnitypes.NewError(types.ErrCodeAddressNotHeld, "not held", "")},
			wantIPs:     []string{"10.0.0.99", "fd00::99"},
			wantFresh:   expectFreshAddWithOriginalStdin,
		}),
	)

	It("returns both reused addresses when a failed ADD is retried after the error clears", func() {
		fake.addErrs = map[string]error{"fd00::5": errors.New("etcdserver: request timed out")}
		_, err := run([]string{"10.0.0.5", "fd00::5"}, dualStackStdin)
		Expect(err).To(HaveOccurred())

		fake.addErrs = nil
		ips, err := run([]string{"10.0.0.5", "fd00::5"}, dualStackStdin)
		Expect(err).NotTo(HaveOccurred())
		Expect(ips).To(Equal([]string{"10.0.0.5", "fd00::5"}))
		Expect(fake.freshAdds()).To(BeEmpty())
		Expect(fake.callsFor("DEL")).To(BeEmpty())
	})
})

var _ = Describe("isAddressNotHeld", func() {
	DescribeTable("classifies errors",
		func(err error, want bool) {
			Expect(isAddressNotHeld(err)).To(Equal(want))
		},
		Entry("the not-held code", cnitypes.NewError(types.ErrCodeAddressNotHeld, "x", ""), true),
		Entry("the not-held code wrapped", fmt.Errorf("wrapped: %w", cnitypes.NewError(types.ErrCodeAddressNotHeld, "x", "")), true),
		Entry("the superseded code", cnitypes.NewError(types.ErrCodeSandboxSuperseded, "x", ""), false),
		Entry("a plain error", errors.New("boom"), false),
		Entry("nil", nil, false),
	)
})

var _ = Describe("withAssignFamilies", func() {
	It("sets both flags as strings and preserves unknown fields", func() {
		out, err := withAssignFamilies([]byte(`{"name":"n","ipam":{"type":"calico-ipam","extra":[1,2]}}`), false, true)
		Expect(err).NotTo(HaveOccurred())
		var top map[string]any
		Expect(json.Unmarshal(out, &top)).To(Succeed())
		Expect(top).To(HaveKeyWithValue("name", "n"))
		ipam, ok := top["ipam"].(map[string]any)
		Expect(ok).To(BeTrue())
		Expect(ipam).To(HaveKeyWithValue("assign_ipv4", "false"))
		Expect(ipam).To(HaveKeyWithValue("assign_ipv6", "true"))
		Expect(ipam).To(HaveKeyWithValue("type", "calico-ipam"))
		Expect(ipam).To(HaveKey("extra"))
	})

	It("rejects stdin without an ipam object", func() {
		_, err := withAssignFamilies([]byte(`{"name":"n"}`), true, false)
		Expect(err).To(HaveOccurred())
	})
})
