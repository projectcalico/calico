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
	"debug/elf"
	"encoding/binary"
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

// BPF helper-function IDs (uapi/linux/bpf.h). Programs that reference either of
// these carry the bpf_trace/bpf_trace_printk trace event, which the kernel tries
// to enable on every program load.
const (
	bpfFuncTracePrintk  = 6
	bpfFuncTraceVprintk = 177
)

func TestPrecompiledBinariesAreLoadable(t *testing.T) {
	RegisterTestingT(t)

	bpffs, err := utils.MaybeMountBPFfs()
	Expect(err).NotTo(HaveOccurred())
	Expect(bpffs).To(Equal("/sys/fs/bpf"))

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
	objects["tc_preamble_ingress_notrace.o"] = struct{}{}
	objects["tc_preamble_egress_notrace.o"] = struct{}{}
	objects["xdp_preamble_notrace.o"] = struct{}{}
	objects["conntrack_cleanup_debug_v4.o"] = struct{}{}
	objects["conntrack_cleanup_debug_v6.o"] = struct{}{}
	objects["conntrack_cleanup_no_log_v4.o"] = struct{}{}
	objects["conntrack_cleanup_no_log_v6.o"] = struct{}{}
	for _, logLevel := range []string{"debug", "no_log"} {
		for _, ipv := range []string{"v46", "v4", "v6"} {
			filename := "connect_balancer_" + logLevel + "_" + ipv + ".o"
			objects[filename] = struct{}{}
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

// TestPreambleNoTraceVariantsAreTracePrintkFree checks that the _notrace
// preamble objects carry no bpf_trace_printk/bpf_trace_vprintk helper call.
// These variants are loaded on nodes running with kernel lockdown=confidentiality,
// where ftrace is disabled at boot and loading any program that references the
// helper makes the kernel log "could not enable bpf_trace_printk events" on
// every load.
func TestPreambleNoTraceVariantsAreTracePrintkFree(t *testing.T) {
	RegisterTestingT(t)

	for _, obj := range []string{
		"tc_preamble_ingress_notrace.o",
		"tc_preamble_egress_notrace.o",
		"xdp_preamble_notrace.o",
	} {
		t.Run(obj, func(t *testing.T) {
			RegisterTestingT(t)
			calls, err := helperCallIDs(path.Join(bpfdefs.ObjectDir, obj))
			Expect(err).NotTo(HaveOccurred())
			Expect(calls).NotTo(HaveKey(int32(bpfFuncTracePrintk)),
				"notrace preamble must not call bpf_trace_printk")
			Expect(calls).NotTo(HaveKey(int32(bpfFuncTraceVprintk)),
				"notrace preamble must not call bpf_trace_vprintk")
		})
	}

	// Guard against the helper being stripped everywhere: the regular preambles
	// are expected to still carry it, so the checks above genuinely exercise the
	// _notrace build.
	for _, obj := range []string{"tc_preamble_ingress.o", "tc_preamble_egress.o"} {
		t.Run(obj+" (baseline)", func(t *testing.T) {
			RegisterTestingT(t)
			calls, err := helperCallIDs(path.Join(bpfdefs.ObjectDir, obj))
			Expect(err).NotTo(HaveOccurred())
			Expect(calls).To(HaveKey(int32(bpfFuncTracePrintk)),
				"regular preamble expected to call bpf_trace_printk")
		})
	}
}

// helperCallIDs returns the set of BPF helper-function IDs (with counts)
// invoked by a precompiled object. A helper call is opcode 0x85
// (BPF_JMP|BPF_CALL) with src register 0; its immediate is the helper ID.
// (src register 1 is a bpf-to-bpf call, 2 is a kfunc call — not helpers.)
// BPF instructions are 8-byte units; the second slot of a 16-byte wide load
// has a zero opcode byte, so stepping by 8 never mistakes it for a call.
func helperCallIDs(file string) (map[int32]int, error) {
	f, err := elf.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	calls := map[int32]int{}
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return nil, err
		}
		for off := 0; off+8 <= len(data); off += 8 {
			if data[off] != 0x85 || data[off+1]>>4 != 0 {
				continue
			}
			calls[int32(binary.LittleEndian.Uint32(data[off+4:off+8]))]++
		}
	}
	return calls, nil
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

func createNetkitName(name string) netlink.Link {
	la := netlink.NewLinkAttrs()
	la.Name = name
	la.Flags = net.FlagUp
	var nk netlink.Link = &netlink.Netkit{
		LinkAttrs: la,
		Mode:      netlink.NETKIT_MODE_L2,
	}
	err := netlink.LinkAdd(nk)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), fmt.Sprintf("failed to create test netkit: %q", name))
	return nk
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
