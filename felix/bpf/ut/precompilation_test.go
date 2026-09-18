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
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
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

// TestNoTracePrintkFlagStripsTraceHelper verifies the load-time dead-code
// elimination: a main program carries skb_log's bpf_trace_printk/bpf_trace_vprintk
// calls (the policy Log action) in its no_log build, but when Felix sets the
// .rodata.prog_flags no_trace_printk flag before load, the verifier folds the
// frozen constant and eliminates those code paths, so the loaded program
// references no trace helper at all. That is what stops the "could not enable
// bpf_trace_printk events" kernel-log spew under lockdown=confidentiality. With
// the flag clear, the helper is still present.
func TestNoTracePrintkFlagStripsTraceHelper(t *testing.T) {
	RegisterTestingT(t)

	bpffs, err := utils.MaybeMountBPFfs()
	Expect(err).NotTo(HaveOccurred())
	Expect(bpffs).To(Equal("/sys/fs/bpf"))

	// from_wep_no_log.o is a main program built at the "off" log level; it still
	// carries skb_log's trace calls (gated at runtime, not by log level).
	const obj = "from_wep_no_log.o"

	// traceRe matches a trace-printk helper *call instruction*, whether bpftool
	// renders the target by name (kallsyms/BTF available) or numerically by
	// helper id (6 / 177). The leading "(85) call" (BPF_JMP|BPF_CALL opcode)
	// distinguishes a real instruction from bpftool's interleaved source-line
	// annotations (which start with ";" and mention the helper by name).
	traceRe := regexp.MustCompile(`\(85\) call ((bpf_)?trace_v?printk|6\b|177\b)`)

	loadedTraceHelperRefs := func(noTrace bool) int {
		o, err := libbpf.OpenObject(path.Join(bpfdefs.ObjectDir, obj))
		Expect(err).NotTo(HaveOccurred())
		defer o.Close()

		// Set the per-object flag before load so libbpf freezes it read-only and
		// the verifier can fold it.
		flagSet := false
		for m, err := o.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
			if strings.HasSuffix(m.Name(), ".rodata.prog_flags") {
				Expect(m.SetProgFlags(noTrace)).NotTo(HaveOccurred())
				flagSet = true
			}
		}
		Expect(flagSet).To(BeTrue(), "object should carry a .rodata.prog_flags map")

		Expect(o.Load()).NotTo(HaveOccurred())

		pinDir := path.Join(bpffs, fmt.Sprintf("notrace-test-%x", rand.Uint32()))
		Expect(os.MkdirAll(pinDir, 0o755)).NotTo(HaveOccurred())
		defer os.RemoveAll(pinDir)
		Expect(o.PinPrograms(pinDir)).NotTo(HaveOccurred())
		defer func() { _ = o.UnpinPrograms(pinDir) }()

		entries, err := os.ReadDir(pinDir)
		Expect(err).NotTo(HaveOccurred())
		refs := 0
		for _, e := range entries {
			out, err := exec.Command("bpftool", "prog", "dump", "xlated", "pinned",
				path.Join(pinDir, e.Name())).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			refs += len(traceRe.FindAllString(string(out), -1))
		}
		return refs
	}

	// Baseline: without the flag the loaded program references the helper.
	Expect(loadedTraceHelperRefs(false)).To(BeNumerically(">", 0),
		"baseline: main program should reference a trace helper when no_trace_printk is clear")
	// With the flag set, the verifier must have eliminated every trace helper.
	Expect(loadedTraceHelperRefs(true)).To(BeZero(),
		"with no_trace_printk set, the loaded program must reference no trace helper")
}

// TestCallbackRefsStayInsideOptionalPrograms guards the one construct Felix
// cannot work around at load time. Passing a callback's address to a helper
// (bpf_loop, bpf_timer_set_callback, bpf_for_each_map_elem) emits a
// BPF_PSEUDO_FUNC reference, which only exists from kernel 5.13. Older kernels
// reject the whole object while validating BTF, before a single instruction is
// verified, so a bpf_core_enum_value_exists() gate cannot hide one -- the gate
// folds instructions, and the count that fails is over BTF func_info records.
// Felix's only lever is skipping an optional sub-program before load, so every
// such reference has to sit inside one.
//
// conntrack_cleanup_*.o is deliberately out of scope: it is a single-program
// object loaded on its own, with no optional-program mechanism to use.
func TestCallbackRefsStayInsideOptionalPrograms(t *testing.T) {
	RegisterTestingT(t)

	optional := map[string]bool{}
	for sp := hook.SubProgTCMain; sp <= hook.SubProgTCMainDebug; sp++ {
		if info := hook.GetOptionalSubProgInfo(sp); info != nil {
			optional[info.ProgName] = true
		}
	}
	Expect(optional).NotTo(BeEmpty(), "no optional sub-programs registered")

	objects := make(map[string]struct{})
	for _, at := range hook.ListAttachTypes() {
		objects[at.ObjectFile()] = struct{}{}
	}
	// These carry no optional sub-program at all, so a callback reference in
	// one is strictly worse than in a tc object.
	for _, o := range []string{
		"tc_preamble_ingress.o", "tc_preamble_egress.o", "xdp_preamble.o",
		"tc_preamble_ingress_notrace.o", "tc_preamble_egress_notrace.o", "xdp_preamble_notrace.o",
	} {
		objects[o] = struct{}{}
	}

	for obj := range objects {
		t.Run(obj, func(t *testing.T) {
			RegisterTestingT(t)
			refs, err := callbackRefs(path.Join(bpfdefs.ObjectDir, obj))
			Expect(err).NotTo(HaveOccurred())
			for _, r := range refs {
				Expect(optional).To(HaveKey(r.prog), fmt.Sprintf(
					"%s takes the address of %s; a kernel below 5.13 cannot load %s at all, "+
						"and disabling an optional program cannot help because %s is not one",
					r.prog, r.callback, obj, r.prog))
			}
		})
	}
}

// callbackRef is one BPF_PSEUDO_FUNC reference: the program holding it and the
// callback it points at.
type callbackRef struct {
	prog     string
	callback string
}

// callbackRefs finds the references by walking relocations rather than
// instructions: an ld_imm64 (opcode 0x18) is a callback address only when a
// relocation ties it to a function in .text, which is where clang emits the
// callbacks it never inlines. A reference whose holder is itself in .text is
// reported under that function's name, which is in no optional set, so it
// fails rather than passing unnoticed.
func callbackRefs(file string) ([]callbackRef, error) {
	f, err := elf.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	syms, err := f.Symbols()
	if err != nil {
		return nil, err
	}

	textIdx := -1
	for i, sec := range f.Sections {
		if sec.Name == ".text" {
			textIdx = i
			break
		}
	}
	if textIdx < 0 {
		return nil, nil // no out-of-line functions, so no callbacks
	}

	var refs []callbackRef
	for _, rel := range f.Sections {
		if rel.Type != elf.SHT_REL {
			continue
		}
		// .text is included on purpose: libbpf appends an out-of-line helper to
		// whichever program calls it, so a callback taken there reaches the
		// caller, which may not be optional.
		target := f.Sections[rel.Info]
		if target.Type != elf.SHT_PROGBITS || target.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		code, err := target.Data()
		if err != nil {
			return nil, err
		}
		data, err := rel.Data()
		if err != nil {
			return nil, err
		}
		// Elf64_Rel: 8-byte offset, 8-byte info whose high word is the symbol index.
		for off := 0; off+16 <= len(data); off += 16 {
			rOff := binary.LittleEndian.Uint64(data[off:])
			symIdx := int(binary.LittleEndian.Uint64(data[off+8:]) >> 32)
			if symIdx == 0 || symIdx > len(syms) {
				continue
			}
			sym := syms[symIdx-1]
			if int(sym.Section) != textIdx {
				continue
			}
			if rOff+8 > uint64(len(code)) || code[rOff] != 0x18 {
				continue
			}
			addend := sym.Value + uint64(binary.LittleEndian.Uint32(code[rOff+4:rOff+8]))
			refs = append(refs, callbackRef{
				prog:     funcAt(syms, rel.Info, rOff),
				callback: funcAt(syms, uint32(textIdx), addend),
			})
		}
	}
	return refs, nil
}

// funcAt names the function covering an offset in a section.
func funcAt(syms []elf.Symbol, sec uint32, off uint64) string {
	for _, s := range syms {
		if uint32(s.Section) == sec && elf.ST_TYPE(s.Info) == elf.STT_FUNC &&
			off >= s.Value && off < s.Value+s.Size {
			return s.Name
		}
	}
	return fmt.Sprintf("<section %d>+0x%x", sec, off)
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
