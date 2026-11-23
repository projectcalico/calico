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
	"reflect"
	"strings"
	"testing"
	"unsafe"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/state"
)

// C members of struct cali_tc_state that state.State deliberately does not mirror.
var stateNotMirrored = []string{
	"icmp_un",   // union with tun_ip
	"icmp_type", // union with dport
	"icmp_code",
	"nat_dest.pad",
	"fwd",
}

type cMember struct {
	offset, size int64
}

// TestStateLayoutMatchesC reads struct cali_tc_state from the programs' DWARF, so Go must follow C changes.
func TestStateLayoutMatchesC(t *testing.T) {
	RegisterTestingT(t)

	v4, v4Leaves, v4Size := cStateLayout(t, "../../bpf-gpl/bin/to_wep_debug.o")
	_, _, v6Size := cStateLayout(t, "../../bpf-gpl/bin/to_wep_debug_v6.o")

	var s state.State
	Expect(int64(unsafe.Sizeof(s))).To(Equal(v6Size), "State must be padded to the IPv6 struct size")
	Expect(v4Size).To(BeNumerically("<=", v6Size))
	Expect(s.AsBytes()).To(HaveLen(int(unsafe.Sizeof(s))), "AsBytes must copy exactly the struct")
	Expect(v6Size).To(BeNumerically("<=", state.MapParameters.ValueSize))

	mirrored := map[string]bool{}
	st := reflect.TypeOf(s)
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		name, ok := f.Tag.Lookup("c")
		if !ok {
			continue
		}
		mirrored[name] = true
		m, found := v4[name]
		if !found {
			t.Errorf("State.%s: no C member %q", f.Name, name)
			continue
		}
		if int64(f.Offset) != m.offset || int64(f.Type.Size()) != m.size {
			t.Errorf("State.%s is at %d, size %d; C %s is at %d, size %d",
				f.Name, f.Offset, f.Type.Size(), name, m.offset, m.size)
		}
	}

	for _, leaf := range v4Leaves {
		if !coveredBy(leaf, mirrored) && !coveredBy(leaf, sliceSet(stateNotMirrored)) {
			t.Errorf("C member %s is neither mirrored in state.State nor listed in stateNotMirrored", leaf)
		}
	}
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
