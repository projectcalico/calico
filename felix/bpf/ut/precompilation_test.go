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

package ut

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
	"github.com/projectcalico/calico/felix/bpf/bpfutils"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/utils"
)

func checkBTFEnabled() []bool {
	if bpfutils.BTFEnabled {
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
		bpfutils.BTFEnabled = bpfutils.SupportsBTF()
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

	for obj := range objects {
		log.Debugf("Object %s", obj)
		t.Run(obj, func(t *testing.T) {
			RegisterTestingT(t)
			testObject(path.Join(bpfdefs.ObjectDir, obj))
		})
	}

	testObject(path.Join(bpfdefs.ObjectDir, "tc_preamble.o"))
	testObject(path.Join(bpfdefs.ObjectDir, "xdp_preamble.o"))
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
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to create test veth")
	return veth
}

func deleteLink(veth netlink.Link) {
	err := netlink.LinkDel(veth)
	Expect(err).NotTo(HaveOccurred(), "failed to delete test veth")
}
