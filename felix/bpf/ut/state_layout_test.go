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

package ut_test

import (
	"debug/dwarf"
	"debug/elf"
	"net"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/events"
	"github.com/projectcalico/calico/felix/bpf/state"
)

// C members before the end of the mirrored part that state.State deliberately leaves out.
var stateNotMirrored = []string{
	"icmp_un",   // union with tun_ip
	"icmp_type", // union with dport
	"icmp_code",
}

type cMember struct {
	offset, size int64
}

// TestStateLayoutMatchesC reads struct cali_tc_state from the programs' DWARF, so Go must follow C changes.
func TestStateLayoutMatchesC(t *testing.T) {
	RegisterTestingT(t)

	v4, v4Leaves, v4Size := cStateLayout(t, "../../bpf-gpl/bin/to_wep_debug.o")
	v6, v6Leaves, v6Size := cStateLayout(t, "../../bpf-gpl/bin/to_wep_debug_v6.o")

	var s state.State
	Expect(int64(unsafe.Sizeof(s))).To(Equal(v6Size), "State must be padded to the IPv6 struct size")
	Expect(v4Size).To(BeNumerically("<=", v6Size))
	Expect(s.AsBytes()).To(HaveLen(int(unsafe.Sizeof(s))), "AsBytes must copy exactly the struct")
	Expect(v6Size).To(BeNumerically("<=", state.MapParameters.ValueSize))

	// Every tagged field must sit where C puts it in both families.
	mirrored := map[string]bool{}
	var mirroredEnd int64
	st := reflect.TypeOf(s)
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		name, ok := f.Tag.Lookup("c")
		if !ok {
			continue
		}
		mirrored[name] = true
		mirroredEnd = max(mirroredEnd, int64(f.Offset+f.Type.Size()))
		// Named untagged fields that follow continue this one, e.g. SrcAddr1-3 for an IPv6 address.
		span := int64(f.Type.Size())
		for j := i + 1; j < st.NumField(); j++ {
			g := st.Field(j)
			if _, tagged := g.Tag.Lookup("c"); tagged || g.Name == "_" {
				break
			}
			span += int64(g.Type.Size())
		}
		for fam, layout := range map[string]map[string]cMember{"IPv4": v4, "IPv6": v6} {
			m, found := layout[name]
			if !found {
				t.Errorf("State.%s: no %s C member %q", f.Name, fam, name)
				continue
			}
			if int64(f.Offset) != m.offset || int64(f.Type.Size()) > m.size || m.size > span {
				t.Errorf("State.%s is at %d, size %d (%d with continuations); %s C %s is at %d, size %d",
					f.Name, f.Offset, f.Type.Size(), span, fam, name, m.offset, m.size)
			}
		}
	}

	// Any C member inside the mirrored part must be mirrored or listed, e.g. a pad slot turned into a field.
	notMirrored := sliceSet(stateNotMirrored)
	for fam, c := range map[string]struct {
		layout map[string]cMember
		leaves []string
	}{"IPv4": {v4, v4Leaves}, "IPv6": {v6, v6Leaves}} {
		for _, leaf := range c.leaves {
			if c.layout[leaf].offset >= mirroredEnd {
				continue
			}
			if !coveredBy(leaf, mirrored) && !coveredBy(leaf, notMirrored) {
				t.Errorf("%s C member %s is neither mirrored in state.State nor listed in stateNotMirrored", fam, leaf)
			}
		}
	}

	// The policy verdict event is the state from after eventhdr to the end of rule_ids (events.h).
	for fam, layout := range map[string]map[string]cMember{"IPv4": v4, "IPv6": v6} {
		hdr := layout["eventhdr"].size
		end := layout["rule_ids"].offset + layout["rule_ids"].size
		checkPolicyVerdictParse(t, fam, fam == "IPv6", int(hdr), int(end))
	}
}

// checkPolicyVerdictParse round-trips a full verdict through the state bytes, cut to the length BPF sends.
func checkPolicyVerdictParse(t *testing.T, fam string, ipv6 bool, hdr, end int) {
	ipLen := 4
	if ipv6 {
		ipLen = 16
	}
	ip := func(b byte) []byte {
		v := make([]byte, ipLen)
		for i := range v {
			v[i] = b + byte(i)
		}
		return v
	}

	s := state.State{
		PolicyRC:       state.PolicyAllow,
		SrcPort:        1111,
		DstPort:        2222,
		PreNATDstPort:  3333,
		PostNATDstPort: 4444,
		IPProto:        17,
		RulesHit:       state.MaxRuleIDs,
	}
	for i := range s.RuleIDs {
		s.RuleIDs[i] = uint64(1000 + i)
	}
	b := s.AsBytes()
	copy(b[unsafe.Offsetof(s.SrcAddr):], ip(0x10))
	copy(b[unsafe.Offsetof(s.DstAddr):], ip(0x20))
	copy(b[unsafe.Offsetof(s.PreNATDstAddr):], ip(0x30))
	copy(b[unsafe.Offsetof(s.PostNATDstAddr):], ip(0x40))
	copy(b[unsafe.Offsetof(s.TunIP):], ip(0x50))
	b[unsafe.Offsetof(s.IPSize)], b[unsafe.Offsetof(s.IPSize)+1] = 0x05, 0xdc // big endian

	pv := events.ParsePolicyVerdict(b[hdr:end], ipv6)
	Expect(pv.SrcAddr).To(Equal(net.IP(ip(0x10))), fam)
	Expect(pv.DstAddr).To(Equal(net.IP(ip(0x30))), "%s: the event carries the pre-NAT destination", fam)
	Expect(pv.PostNATDstAddr).To(Equal(net.IP(ip(0x40))), fam)
	Expect(pv.NATTunSrcAddr).To(Equal(net.IP(ip(0x50))), fam)
	Expect(pv.PolicyRC).To(Equal(state.PolicyAllow), fam)
	Expect(pv.SrcPort).To(Equal(uint16(1111)), fam)
	Expect(pv.DstPort).To(Equal(uint16(3333)), fam)
	Expect(pv.PostNATDstPort).To(Equal(uint16(4444)), fam)
	Expect(pv.IPProto).To(Equal(uint8(17)), fam)
	Expect(pv.IPSize).To(Equal(uint16(1500)), fam)
	Expect(pv.RulesHit).To(Equal(uint32(state.MaxRuleIDs)), fam)
	Expect(pv.RuleIDs[state.MaxRuleIDs-1]).To(Equal(uint64(1000+state.MaxRuleIDs-1)), fam)
}

// cStateLayout returns every member of struct cali_tc_state by dotted path, the leaf paths and the struct size.
func cStateLayout(t *testing.T, obj string) (map[string]cMember, []string, int64) {
	f, err := elf.Open(obj)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	d := rawDWARF(f)

	r := d.Reader()
	for {
		e, err := r.Next()
		Expect(err).NotTo(HaveOccurred())
		if e == nil {
			t.Fatalf("struct cali_tc_state not found in %s", obj)
		}
		if e.Tag != dwarf.TagStructType || e.Val(dwarf.AttrName) != "cali_tc_state" || e.Val(dwarf.AttrDeclaration) != nil {
			continue
		}
		typ, err := d.Type(e.Offset)
		Expect(err).NotTo(HaveOccurred())
		members := map[string]cMember{}
		var leaves []string
		walkCStruct(typ.(*dwarf.StructType), "", 0, members, &leaves)
		return members, leaves, typ.Size()
	}
}

// walkCStruct flattens anonymous structs and unions into their parent and names nested members "parent.member".
func walkCStruct(st *dwarf.StructType, prefix string, base int64, members map[string]cMember, leaves *[]string) {
	for _, f := range st.Field {
		if strings.HasPrefix(f.Name, "__pad") {
			continue
		}
		off := base + f.ByteOffset
		inner, isStruct := stripCTypedefs(f.Type).(*dwarf.StructType)
		if f.Name == "" && isStruct {
			walkCStruct(inner, prefix, off, members, leaves)
			continue
		}
		path := prefix + f.Name
		members[path] = cMember{offset: off, size: f.Type.Size()}
		if isStruct {
			walkCStruct(inner, path+".", off, members, leaves)
		} else {
			*leaves = append(*leaves, path)
		}
	}
}

// rawDWARF loads DWARF without applying relocations, which debug/elf does not implement for
// BPF; in these REL objects the unrelocated values are already the right offsets.
func rawDWARF(f *elf.File) *dwarf.Data {
	sec := func(name string) []byte {
		s := f.Section(name)
		if s == nil {
			return nil
		}
		b, err := s.Data()
		Expect(err).NotTo(HaveOccurred(), "reading %s", name)
		return b
	}
	d, err := dwarf.New(sec(".debug_abbrev"), nil, nil, sec(".debug_info"), sec(".debug_line"), nil, nil, sec(".debug_str"))
	Expect(err).NotTo(HaveOccurred())
	for _, name := range []string{".debug_addr", ".debug_line_str", ".debug_str_offsets", ".debug_rnglists"} {
		if b := sec(name); b != nil {
			Expect(d.AddSection(name, b)).To(Succeed())
		}
	}
	return d
}

func stripCTypedefs(t dwarf.Type) dwarf.Type {
	for {
		switch tt := t.(type) {
		case *dwarf.TypedefType:
			t = tt.Type
		case *dwarf.QualType:
			t = tt.Type
		default:
			return t
		}
	}
}

// coveredBy reports whether path or one of its parent structs is in set.
func coveredBy(path string, set map[string]bool) bool {
	for p := path; ; {
		if set[p] {
			return true
		}
		i := strings.LastIndex(p, ".")
		if i < 0 {
			return false
		}
		p = p[:i]
	}
}

func sliceSet(s []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range s {
		m[v] = true
	}
	return m
}
