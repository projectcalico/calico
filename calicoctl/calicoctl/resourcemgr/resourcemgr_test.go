// Copyright (c) 2019,2021 Tigera, Inc. All rights reserved.

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

package resourcemgr_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	DefaultIpPoolTemplate = `kind: IPPool
apiVersion: projectcalico.org/v3
metadata:
  name: {{NAME}}
spec:
  cidr: {{CIDR}}
  ipipMode: {{IPIPMODE}}
  vxlanMode: {{VXLANMODE}}
  natOutgoing: true
`
)

var _ = Describe("Create resource from file", func() {
	const CidrV6 = "2002::/64"
	const CidrV4 = "192.168.0.0/16"
	const PoolName = "my-ippool"
	const AnotherPoolName = "another-ippool"

	const VxlanModeNever = string(api.VXLANModeNever)
	const VxlanModeAlways = string(api.VXLANModeAlways)
	const IpipModeNever = string(api.IPIPModeNever)

	ipPoolV6WithNeverVxlan := ipPoolSpec(DefaultIpPoolTemplate, CidrV6, PoolName, VxlanModeNever, IpipModeNever)
	anotherIpPoolV6WithNeverVxlan := ipPoolSpec(DefaultIpPoolTemplate, CidrV6, AnotherPoolName, VxlanModeNever, IpipModeNever)
	ipPoolV4WithAlwaysVxlan := ipPoolSpec(DefaultIpPoolTemplate, CidrV4, PoolName, VxlanModeAlways, IpipModeNever)
	anotherIpPoolV4WithAlwaysVxlan := ipPoolSpec(DefaultIpPoolTemplate, CidrV4, AnotherPoolName, VxlanModeAlways, IpipModeNever)

	ipPoolV6 := ipPool(CidrV6, PoolName, api.VXLANModeNever)
	ipPoolV4 := ipPool(CidrV4, PoolName, api.VXLANModeAlways)
	anotherIpPoolV6 := ipPool(CidrV6, AnotherPoolName, api.VXLANModeNever)
	anotherIpPoolV4 := ipPool(CidrV4, AnotherPoolName, api.VXLANModeAlways)

	It("Should create IPPOOL V6 with Vxlan to Never", func() {
		resources, err := createResources(ipPoolV6WithNeverVxlan)
		Expect(err).NotTo(HaveOccurred())

		expectedIpPools := ipPools(ipPoolV6)
		expectResourcesToMatch(resources, expectedIpPools)
	})

	It("Should create IPPOOL V4 with Vxlan to Always", func() {
		resources, err := createResources(ipPoolV4WithAlwaysVxlan)
		Expect(err).NotTo(HaveOccurred())

		expectedIpPools := ipPools(ipPoolV4)
		expectResourcesToMatch(resources, expectedIpPools)
	})

	It("Should create 2 IPPOOL V6 with Vxlan to Never", func() {
		resources, err := createResources(ipPoolV6WithNeverVxlan, anotherIpPoolV6WithNeverVxlan)
		Expect(err).NotTo(HaveOccurred())

		expectedIpPools := ipPools(ipPoolV6, anotherIpPoolV6)
		expectResourcesToMatch(resources, expectedIpPools)
	})

	It("Should create 2 IPPOOL V6 - one with Vxlan to Never and one to Always", func() {
		resources, err := createResources(ipPoolV6WithNeverVxlan, anotherIpPoolV4WithAlwaysVxlan)
		Expect(err).NotTo(HaveOccurred())

		expectedIpPools := ipPools(ipPoolV6, anotherIpPoolV4)
		expectResourcesToMatch(resources, expectedIpPools)
	})

	It("Should create no resources from an empty Spec", func() {
		resources, err := createResources()
		Expect(err).NotTo(HaveOccurred())
		expectResourcesToMatch(resources, []*api.IPPool{})
	})

})

func expectResourcesToMatch(resources []runtime.Object, expectedIpPools []*api.IPPool) {
	Expect(len(expectedIpPools)).To(Equal(len(resources)))
	for index := range expectedIpPools {
		Expect(resources[index].DeepCopyObject()).To(Equal(expectedIpPools[index]))
	}
}

func ipPoolSpec(ipPoolSpec string, cidr string, name string, vxlanMode string, ipIpMode string) string {
	macros := map[string]string{
		"{{NAME}}":      name,
		"{{CIDR}}":      cidr,
		"{{VXLANMODE}}": vxlanMode,
		"{{IPIPMODE}}":  ipIpMode,
	}

	return replace(macros, ipPoolSpec)
}

func replace(macros map[string]string, spec string) string {
	for macro, replacement := range macros {
		spec = strings.Replace(spec, macro, replacement, 1)
	}
	return spec
}

func ipPool(cidr string, name string, vxlanMode api.VXLANMode) *api.IPPool {
	ipPool := api.NewIPPool()
	ipPool.Name = name
	ipPool.Spec = api.IPPoolSpec{CIDR: cidr, VXLANMode: vxlanMode, IPIPMode: api.IPIPModeNever, NATOutgoing: true}
	return ipPool
}

func ipPools(elements ...*api.IPPool) []*api.IPPool {
	return elements
}

func createResources(specs ...string) ([]runtime.Object, error) {
	By("Writing specs to a temporary location")
	content := strings.Join(specs, "\n---\n")
	file := writeSpec(content)
	By(fmt.Sprintf("Specs that will be used are: %s", content))
	defer os.Remove(file.Name())
	By(fmt.Sprintf("Creating resources from file %s", file.Name()))
	return resourcemgr.CreateResourcesFromFile(file.Name())
}

func writeSpec(spec string) *os.File {
	file, err := ioutil.TempFile("/tmp", "resource")
	Expect(err).NotTo(HaveOccurred())
	_, err = file.WriteString(spec)
	Expect(err).NotTo(HaveOccurred())
	return file
}
