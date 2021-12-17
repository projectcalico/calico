// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package iptree

import (
	"net"

	"github.com/projectcalico/calico/felix/ip"
)

type IPTree struct {
	ipVersion int
	root      *node
}

type node struct {
	children [2]*node
}

func (n *node) addCoveringCIDRs(depth int, prefix []byte, cidrs []ip.CIDR) []ip.CIDR {
	if n == nil {
		return cidrs // This node is empty.
	}
	if n == all {
		// This node is a complete CIDR.
		prefixCopy := make([]byte, len(prefix))
		copy(prefixCopy, prefix)
		ipNet := net.IPNet{
			IP:   net.IP(prefixCopy),
			Mask: net.CIDRMask(depth, len(prefix)*8),
		}
		return append(cidrs, ip.CIDRFromIPNet(&ipNet))
	}
	// Look at our children.
	setNthBit(depth, prefix, false)
	cidrs = n.children[0].addCoveringCIDRs(depth+1, prefix, cidrs)
	setNthBit(depth, prefix, true)
	cidrs = n.children[1].addCoveringCIDRs(depth+1, prefix, cidrs)
	return cidrs
}

func (n *node) copy() *node {
	if n == nil {
		return nil
	}
	if n == all {
		return all
	}
	return &node{
		children: [2]*node{n.children[0].copy(), n.children[1].copy()},
	}
}

var all = &node{}

func New(ipVersion int) *IPTree {
	return &IPTree{ipVersion: ipVersion}
}

func Intersect(a, b *IPTree) *IPTree {
	tree := New(a.ipVersion)
	tree.root = intersectNodes(a.root, b.root)
	return tree
}

func Subtract(a, b *IPTree) *IPTree {
	tree := New(a.ipVersion)
	tree.root = subtractNodes(a.root, b.root)
	return tree
}

func intersectNodes(a, b *node) *node {
	if a == nil || b == nil {
		return nil
	}
	if a == all && b == all {
		return all
	}
	if a == all {
		return b.copy()
	}
	if b == all {
		return a.copy()
	}
	return &node{
		children: [2]*node{
			intersectNodes(a.children[0], b.children[0]),
			intersectNodes(a.children[1], b.children[1]),
		},
	}
}

func subtractNodes(a, b *node) *node {
	if a == nil {
		return nil
	}
	if b == nil {
		return a.copy()
	}
	if b == all {
		return nil
	}

	var node node

	if a == all {
		node.children[0] = subtractNodes(all, b.children[0])
		node.children[1] = subtractNodes(all, b.children[1])
	} else {
		node.children[0] = subtractNodes(a.children[0], b.children[0])
		node.children[1] = subtractNodes(a.children[1], b.children[1])
	}

	if node.children[0] == nil && node.children[1] == nil {
		return nil
	}

	return &node
}

func (t *IPTree) AddCIDRString(c string) {
	cidr := ip.MustParseCIDROrIP(c)
	t.AddCIDR(cidr)
}

func (t *IPTree) AddCIDR(cidr ip.CIDR) {

	var addr net.IP
	if t.ipVersion == 4 {
		addr = cidr.ToIPNet().IP.To4()
	} else {
		addr = cidr.ToIPNet().IP.To16()
	}
	if addr == nil {
		return
	}

	t.add(&t.root, 0, cidr.Prefix(), addr)
}

func (t *IPTree) add(nodePtr **node, d uint8, prefix uint8, addr net.IP) {
	if d == prefix {
		*nodePtr = all
		return
	}

	if *nodePtr == nil {
		*nodePtr = &node{}
	}

	bit := getNthBit(int(d), addr)
	child := &((*nodePtr).children[bit])

	t.add(child, d+1, prefix, addr)

	if (*nodePtr).children[0] == all && (*nodePtr).children[1] == all {
		*nodePtr = all
	}
}

func (t *IPTree) CoveringCIDRs() []ip.CIDR {
	var prefix []byte
	if t.ipVersion == 4 {
		prefix = make([]byte, 4)
	} else {
		prefix = make([]byte, 16)
	}
	return t.root.addCoveringCIDRs(0, prefix, nil)
}

func (t *IPTree) CoveringCIDRStrings() (out []string) {
	for _, c := range t.CoveringCIDRs() {
		out = append(out, c.String())
	}
	return
}

func getNthBit(d int, addr []byte) byte {
	byteIdx := d / 8
	bitIdx := uint(7 - (d % 8))
	bit := 1 & (addr[byteIdx] >> bitIdx)
	return bit
}

func setNthBit(d int, addr []byte, value bool) {
	byteIdx := d / 8
	bitIdx := uint(7 - (d % 8))
	mask := byte(1 << bitIdx)
	if value {
		addr[byteIdx] |= mask
	} else {
		addr[byteIdx] &^= mask
	}
}
