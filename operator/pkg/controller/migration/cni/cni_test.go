// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

package cni

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const cniTemplate = `{
	"name": "k8s-pod-network",
	"cniVersion": "0.3.1",
	"plugins": [
	  {
		"type": "calico",
		"log_level": "info",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"mtu": __CNI_MTU__,
		"ipam": %s,
		"policy": {
			"type": "k8s"
		},
		"kubernetes": {
			"kubeconfig": "__KUBECONFIG_FILEPATH__"
		}
	  },
	  {
		"type": "portmap",
		"snat": true,
		"capabilities": {"portMappings": true}
	  }
	]
}`

var defaultCNI = fmt.Sprintf(cniTemplate, `{"type": "calico-ipam"}`)

var _ = Describe("CNI", func() {
	It("should unmarshal a valid cni conf list", func() {
		_, err := unmarshalCNIConfList(defaultCNI)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should parse basic calico cni", func() {
		c, err := Parse(defaultCNI)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.CalicoConfig).ToNot(BeNil())
		// check that any field was unmarshaled correctly.
		Expect(c.CalicoConfig.IPAM.Type).To(Equal("calico-ipam"), fmt.Sprintf("Got %+v", c.CalicoConfig))
	})

	It("should parse ranges and routes", func() {
		c, err := Parse(fmt.Sprintf(cniTemplate, `{
			"type": "host-local",
			"ranges": [
                [
                    { "subnet": "usePodCidr" }
                ],
                [
                    { "subnet": "2001:db8::/96" }
                ]
            ],
            "routes": [
                { "dst": "0.0.0.0/0" },
                { "dst": "2001:db8::/96" }
            ]
        }`))
		Expect(err).ToNot(HaveOccurred())
		Expect(c.CalicoConfig).ToNot(BeNil())
		Expect(c.CalicoConfig.IPAM.Type).To(Equal("host-local"), fmt.Sprintf("Got %+v", c.CalicoConfig))
		Expect(c.HostLocalIPAMConfig.Ranges).To(HaveLen(2))
		Expect(c.HostLocalIPAMConfig.Routes).To(HaveLen(2))
	})
	It("should raise error if IPAM with unknown field is detected", func() {
		_, err := Parse(fmt.Sprintf(cniTemplate, `{
			"type": "host-local",
			"unknown": "whocares"
        }`))
		Expect(err).To(HaveOccurred())
	})
})
