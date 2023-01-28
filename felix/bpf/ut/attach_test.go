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

package ut

import (
	"regexp"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	linux "github.com/projectcalico/calico/felix/dataplane/linux"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

func TestAttach(t *testing.T) {
	RegisterTestingT(t)

	bpfmaps, err := bpfmap.CreateBPFMaps()
	Expect(err).NotTo(HaveOccurred())

	bpfEpMgr, err := linux.NewTestEpMgr(
		&linux.Config{
			Hostname:              "uthost",
			BPFLogLevel:           "info",
			BPFDataIfacePattern:   regexp.MustCompile("^eth12345"),
			VXLANMTU:              1000,
			VXLANPort:             1234,
			BPFNodePortDSREnabled: false,
			RulesConfig: rules.Config{
				EndpointToHostAction: "RETURN",
			},
			BPFExtToServiceConnmark: 0,
			FeatureGates: map[string]string{
				"BPFConnectTimeLoadBalancingWorkaround": "enabled",
			},
			BPFPolicyDebugEnabled: true,
		},
		bpfmaps,
		regexp.MustCompile("cali"),
	)
	Expect(err).NotTo(HaveOccurred())

	veth12345 := createVethName("eth12345")
	defer deleteLink(veth12345)

	bpfEpMgr.OnUpdate(linux.NewIfaceUpdate("eth12345", ifacemonitor.StateUp, veth12345.Attrs().Index))
	bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("eth12345", "1.2.3.4"))
	bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
}
