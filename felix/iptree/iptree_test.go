// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package iptree

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestMainline(t *testing.T) {
	for _, test := range []struct {
		Name          string
		CIDRsToAdd    []string
		CIDRsToExpect []string
	}{
		{"empty", nil, nil},
		{"zero", []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}},
		{"128.0.0.0/1", []string{"128.0.0.0/1"}, []string{"128.0.0.0/1"}},
		{"1.0.0.0/8", []string{"1.0.0.0/8"}, []string{"1.0.0.0/8"}},
		{"0.0.0.0/1 and 128.0.0.0/1",
			[]string{"128.0.0.0/1", "0.0.0.0/1"},
			[]string{"0.0.0.0/0"}},
		{"Covering a 24",
			[]string{"10.0.0.1", "10.0.0.2", "10.0.0.128/25", "10.0.0.64/26", "10.0.0.32/27",
				"10.0.0.16/28", "10.0.0.8/29", "10.0.0.4/30", "10.0.0.3", "10.0.0.0"},
			[]string{"10.0.0.0/24"}},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			RegisterTestingT(t)

			tree := New(4)
			for _, c := range test.CIDRsToAdd {
				tree.AddCIDRString(c)
			}
			var cidrsAsIface []interface{}
			for _, c := range test.CIDRsToExpect {
				cidrsAsIface = append(cidrsAsIface, c)
			}
			Expect(tree.CoveringCIDRStrings()).To(ConsistOf(cidrsAsIface...))
		})
	}
}

func TestIntesection(t *testing.T) {
	for _, test := range []struct {
		Name          string
		A, B          []string
		CIDRsToExpect []string
	}{
		{"empty", nil, nil, nil},
		{"zero", []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}},
		{"zero-0&128-1", []string{"0.0.0.0/0"}, []string{"128.0.0.0/1"}, []string{"128.0.0.0/1"}},
		{"zero-1&128-1", []string{"0.0.0.0/1"}, []string{"128.0.0.0/1"}, []string{}},
		{"128-1&zero-0", []string{"128.0.0.0/1"}, []string{"0.0.0.0/0"}, []string{"128.0.0.0/1"}},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			RegisterTestingT(t)

			treeA := New(4)
			for _, c := range test.A {
				treeA.AddCIDRString(c)
			}
			treeB := New(4)
			for _, c := range test.B {
				treeB.AddCIDRString(c)
			}

			intersection := Intersect(treeA, treeB)

			var cidrsAsIface []interface{}
			for _, c := range test.CIDRsToExpect {
				cidrsAsIface = append(cidrsAsIface, c)
			}
			Expect(intersection.CoveringCIDRStrings()).To(ConsistOf(cidrsAsIface...))
		})
	}
}

func TestSubtraction(t *testing.T) {
	for _, test := range []struct {
		Name          string
		A, B          []string
		CIDRsToExpect []string
	}{
		{"empty", nil, nil, nil},
		{"zero", []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}, []string{}},
		{"zero-0 - 128-1", []string{"0.0.0.0/0"}, []string{"128.0.0.0/1"}, []string{"0.0.0.0/1"}},
		{"zero-1 - 128-1", []string{"0.0.0.0/1"}, []string{"128.0.0.0/1"}, []string{"0.0.0.0/1"}},
		{"128-1 - zero-0", []string{"128.0.0.0/1"}, []string{"0.0.0.0/0"}, []string{}},
		{"coalesce child nodes",
			[]string{"10.0.0.0/25", "10.0.1.0/25"},
			[]string{"10.0.0.0/23"}, []string{}},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			RegisterTestingT(t)

			treeA := New(4)
			for _, c := range test.A {
				treeA.AddCIDRString(c)
			}
			treeB := New(4)
			for _, c := range test.B {
				treeB.AddCIDRString(c)
			}

			intersection := Subtract(treeA, treeB)

			var cidrsAsIface []interface{}
			for _, c := range test.CIDRsToExpect {
				cidrsAsIface = append(cidrsAsIface, c)
			}
			Expect(intersection.CoveringCIDRStrings()).To(ConsistOf(cidrsAsIface...))
		})
	}
}
