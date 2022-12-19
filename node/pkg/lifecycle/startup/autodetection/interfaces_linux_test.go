// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package autodetection

import (
	"net"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

type getInterfacesTestCase struct {
	getInterfaces       func() ([]net.Interface, error)
	expectFound         bool
	expectInterfaceName string
}

var _ = DescribeTable("GetInterfaces",
	func(tc getInterfacesTestCase) {
		found, err := GetInterfaces(tc.getInterfaces, nil, DEFAULT_INTERFACES_TO_EXCLUDE, 4)
		Expect(err).NotTo(HaveOccurred())
		if tc.expectFound {
			Expect(found).NotTo(BeEmpty())
		} else {
			Expect(found).To(BeEmpty())
		}
		if name := tc.expectInterfaceName; name != "" {
			Expect(found[0].Name).To(Equal(name))
		}
	},
	Entry("default interface", getInterfacesTestCase{
		getInterfaces: net.Interfaces,
		expectFound:   true,
	}),
	Entry("should not skip ibmveth", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "lo"}, {Index: 1, Name: "ibmvetha"}}, nil
		},
		expectFound:         true,
		expectInterfaceName: "ibmvetha",
	}),
	Entry("should skip veth", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "veth123126312783"}}, nil
		},
	}),
	Entry("should skip vxlan.calico", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "vxlan.calico"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip vxlan-v6.calico", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "vxlan-v6.calico"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip wireguard.cali", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "wireguard.cali"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip wg-v6.cali", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "wg-v6.cali"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip nodelocaldns", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "nodelocaldns"}}, nil
		},
		expectFound: false,
	}),
)
