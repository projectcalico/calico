// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

package ut_test

import (
	"fmt"
	"math/rand"
	"net"
	"path"
	"testing"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/utils"
)

func checkBTFEnabled() []bool {
	if utils.BTFEnabled {
		return []bool{false, true}
	}
	return []bool{false}
}

func TestPrecompiledBinariesAreLoadable(t *testing.T) {
	RegisterTestingT(t)

	bpffs, err := utils.MaybeMountBPFfs()
	Expect(err).NotTo(HaveOccurred())
	Expect(bpffs).To(Equal("/sys/fs/bpf"))

	defer func() {
		utils.BTFEnabled = utils.SupportsBTF()
	}()

	testObject := func(file string) {
		obj, err := libbpf.OpenObject(file)
		defer func() { _ = obj.Close() }()
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to open object %s", file))
		err = obj.Load()
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to load object %s", file))
	}

	// all unique objects
	objects := make(map[string]struct{})

	for _, at := range hook.ListAttachTypes() {
		objects[at.ObjectFile()] = struct{}{}
	}

	objects["tc_preamble_ingress.o"] = struct{}{}
	objects["tc_preamble_egress.o"] = struct{}{}
	objects["xdp_preamble.o"] = struct{}{}
	objects["conntrack_cleanup_debug_co-re_v4.o"] = struct{}{}
	objects["conntrack_cleanup_debug_co-re_v6.o"] = struct{}{}
	objects["conntrack_cleanup_no_log_co-re_v4.o"] = struct{}{}
	objects["conntrack_cleanup_no_log_co-re_v6.o"] = struct{}{}
	for _, logLevel := range []string{"debug", "no_log"} {
		for _, btf := range []bool{false, true} {
			for _, ipv := range []string{"v46", "v4", "v6"} {
				core := ""
				if btf {
					core = "_co-re"
				}
				filename := "connect_balancer_" + logLevel + core + fmt.Sprintf("_%s.o", ipv)
				objects[filename] = struct{}{}
			}
		}
	}

	for obj := range objects {
		log.Debugf("Object %s", obj)
		t.Run(obj, func(t *testing.T) {
			RegisterTestingT(t)
			testObject(path.Join(bpfdefs.ObjectDir, obj))
		})
	}
}

func createVeth() (string, netlink.Link) {
	vethName := fmt.Sprintf("test%xa", rand.Uint32())
	return vethName, createVethName(vethName)
}

func createVethName(name string) netlink.Link {
	la := netlink.NewLinkAttrs()
	la.Name = name
	la.Flags = net.FlagUp
	var veth netlink.Link = &netlink.Veth{
		LinkAttrs: la,
		PeerName:  name + "b",
	}
	err := netlink.LinkAdd(veth)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), fmt.Sprintf("failed to create test veth: %q", name))
	return veth
}

func createHostIf(name string) netlink.Link {
	la := netlink.NewLinkAttrs()
	la.Name = name
	la.Flags = net.FlagUp
	var hostIf netlink.Link = &netlink.Dummy{
		LinkAttrs: la,
	}
	err := netlink.LinkAdd(hostIf)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), fmt.Sprintf("failed to create test hostIf: %q", name))
	return hostIf
}

func deleteLink(veth netlink.Link) {
	err := netlink.LinkDel(veth)
	Expect(err).NotTo(HaveOccurred(), "failed to delete test veth")
}
