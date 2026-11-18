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
	"encoding/json"

	"github.com/containernetworking/cni/pkg/skel"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/pkg/types"
)

// ipamAnnotationsCase is one applyIPAMAnnotations scenario: the stdin and annotations it starts
// from, and the IPAM config conf and stdin should both end up with.
type ipamAnnotationsCase struct {
	stdin       string
	pod         map[string]string
	namespace   map[string]string
	wantV4      bool
	wantV6      bool
	wantV4Pools []string
	wantV6Pools []string
}

var _ = Describe("applyIPAMAnnotations", func() {
	apply := func(stdin string, pod, namespace map[string]string) (types.NetConf, *skel.CmdArgs, error) {
		var conf types.NetConf
		Expect(json.Unmarshal([]byte(stdin), &conf)).To(Succeed())
		args := &skel.CmdArgs{StdinData: []byte(stdin)}
		err := applyIPAMAnnotations(&conf, args, pod, namespace, logrus.WithField("test", "annotations"))
		return conf, args, err
	}

	DescribeTable("sets conf to match the rewritten stdin",
		func(c ipamAnnotationsCase) {
			conf, args, err := apply(c.stdin, c.pod, c.namespace)
			Expect(err).NotTo(HaveOccurred())

			var fromStdin types.NetConf
			Expect(json.Unmarshal(args.StdinData, &fromStdin)).To(Succeed())
			Expect(conf.IPAM).To(Equal(fromStdin.IPAM), "conf disagrees with the stdin IPAM will be given")
			Expect(conf.IPAM.AssignsIPv4()).To(Equal(c.wantV4))
			Expect(conf.IPAM.AssignsIPv6()).To(Equal(c.wantV6))
			Expect(conf.IPAM.IPv4Pools).To(Equal(c.wantV4Pools))
			Expect(conf.IPAM.IPv6Pools).To(Equal(c.wantV6Pools))
		},
		Entry("no annotations leave the config alone", ipamAnnotationsCase{
			stdin:  dualStackStdin,
			wantV4: true, wantV6: true,
		}),
		Entry("a pod ipFamilies annotation turns IPv4 off", ipamAnnotationsCase{
			stdin:  dualStackStdin,
			pod:    map[string]string{"cni.projectcalico.org/ipFamilies": `["IPv6"]`},
			wantV6: true,
		}),
		Entry("a namespace ipFamilies annotation turns IPv6 on", ipamAnnotationsCase{
			stdin:     singleStackStdin,
			namespace: map[string]string{"cni.projectcalico.org/ipFamilies": `["IPv4","IPv6"]`},
			wantV4:    true, wantV6: true,
		}),
		Entry("the pod's annotations override the namespace's", ipamAnnotationsCase{
			stdin: dualStackStdin,
			pod: map[string]string{
				"cni.projectcalico.org/ipFamilies": `["IPv4"]`,
				"cni.projectcalico.org/ipv4pools":  `["pod-pool"]`,
			},
			namespace: map[string]string{
				"cni.projectcalico.org/ipFamilies": `["IPv6"]`,
				"cni.projectcalico.org/ipv4pools":  `["ns-pool"]`,
				"cni.projectcalico.org/ipv6pools":  `["ns-v6-pool"]`,
			},
			wantV4:      true,
			wantV4Pools: []string{"pod-pool"},
			wantV6Pools: []string{"ns-v6-pool"},
		}),
	)

	It("rejects an unknown family", func() {
		_, _, err := apply(dualStackStdin, map[string]string{"cni.projectcalico.org/ipFamilies": `["IPv5"]`}, nil)
		Expect(err).To(MatchError(ContainSubstring("error parsing ipFamilies")))
	})

	It("rejects stdin without an ipam object when an annotation applies", func() {
		_, _, err := apply(`{"name":"n"}`, map[string]string{"cni.projectcalico.org/ipv4pools": `["p"]`}, nil)
		Expect(err).To(MatchError("data on stdin was of unexpected type"))
	})
})
