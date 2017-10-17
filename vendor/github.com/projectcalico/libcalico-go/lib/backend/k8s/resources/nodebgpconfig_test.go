// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package resources_test

import (
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Node BGP config conversion methods", func() {

	converter := resources.NodeBGPConfigConverter{}

	It("should convert an empty ListInterface", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPConfigListOptions{},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal(""))
		Expect(name).To(Equal(""))
	})

	It("should convert a List interface with a Node name only", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPConfigListOptions{
				Nodename: "node",
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal("node"))
		Expect(name).To(Equal(""))
	})

	It("should convert a List interface with a ConfigIP only", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPConfigListOptions{
				Name: "FooFoo",
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal(""))
		Expect(name).To(Equal("FooFoo"))
	})

	It("should convert a List interface with node and name", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPConfigListOptions{
				Nodename: "nodeX",
				Name:     "FooBar",
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal("nodeX"))
		Expect(name).To(Equal("FooBar"))
	})

	It("should convert a Key with node and name", func() {
		node, name, err := converter.KeyToNodeAndName(
			model.NodeBGPConfigKey{
				Nodename: "nodeY",
				Name:     "FooBaz",
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal("nodeY"))
		Expect(name).To(Equal("FooBaz"))
	})

	It("should convert a valid node name and resource name to a Key (IPv4)", func() {
		key, err := converter.NodeAndNameToKey("nodeA", "FooBaz")
		Expect(err).To(BeNil())
		Expect(key).To(Equal(model.NodeBGPConfigKey{
			Nodename: "nodeA",
			Name:     "FooBaz",
		}))
	})
})
