// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package ip

import (
	"encoding/binary"
	"math/bits"

	"github.com/sirupsen/logrus"
)

type CIDRTrie struct {
	root *CIDRNode
}

type CIDRNode struct {
	cidr     CIDR
	children [2]*CIDRNode
	data     interface{}
}

func (t *CIDRTrie) Delete(cidr CIDR) {
	if t.root == nil {
		// Trie is empty.
		return
	}
	if pfx := CommonPrefix(t.root.cidr, cidr); pfx != t.root.cidr {
		// Trie does not contain prefix.
		return
	}
	t.root = deleteInternal(t.root, cidr)
}

func deleteInternal(n *CIDRNode, cidr CIDR) *CIDRNode {
	if n.cidr.Version() != cidr.Version() {
		logrus.WithField("n.cidr", n.cidr).WithField("cidr", cidr).Panic("Mismatched CIDR IP versions")
	}

	if !n.cidr.Contains(cidr.Addr()) {
		// Not in trie.
		return n
	}

	if cidr == n.cidr {
		// Found the node.  If either child is nil then this was just an intermediate node
		// and it no longer has any data in it so we replace it by its remaining child.
		if n.children[0] == nil {
			// 0th child is nil, return the other child (or nil if both children were nil)
			return n.children[1]
		} else if n.children[1] == nil {
			// oth child non-nil but 1st child is nil, return oth child.
			return n.children[0]
		} else {
			// Intermediate node but it has two children so it is still required.
			n.data = nil
			return n
		}
	}

	// If we get here, then this node is a parent of the CIDR we're looking for.
	// Figure out which child to recurse on.
	childIdx := cidr.Addr().NthBit(uint(n.cidr.Prefix() + 1))
	oldChild := n.children[childIdx]
	if oldChild == nil {
		return n
	}
	newChild := deleteInternal(oldChild, cidr)
	n.children[childIdx] = newChild
	if newChild == nil {
		// One of our children has been deleted completely, check if this node is an intermediate node
		// that needs to be cleaned up.
		if n.data == nil {
			return n.children[1-childIdx]
		}
	}
	return n
}

type CIDRTrieEntry struct {
	CIDR CIDR
	Data interface{}
}

func (t *CIDRTrie) Get(cidr CIDR) interface{} {
	return t.root.get(cidr)
}

// LookupPath looks up the given CIDR in the trie.  It returns a slice containing a V4TrieEntry for each
// CIDR in the trie that encloses the given CIDR.  If buffer is non-nil, then it is used to store the entries;
// if it is too short append() is used to extend it and the updated slice is returned.
//
// If the CIDR is not in the trie then an empty slice is returned.
func (t *CIDRTrie) LookupPath(buffer []CIDRTrieEntry, cidr CIDR) []CIDRTrieEntry {
	return t.root.lookupPath(buffer[:0], cidr)
}

// LPM does a longest prefix match on the trie
func (t *CIDRTrie) LPM(cidr CIDR) (CIDR, interface{}) {
	n := t.root
	var match *CIDRNode

	for {
		if n == nil {
			break
		}

		if !n.cidr.Contains(cidr.Addr()) {
			break
		}

		if n.data != nil {
			match = n
		}

		if cidr == n.cidr {
			break
		}

		// If we get here, then this node is a parent of the CIDR we're looking for.
		// Figure out which child to recurse on.
		childIdx := cidr.Addr().NthBit(uint(n.cidr.Prefix() + 1))
		n = n.children[childIdx]
	}

	if match == nil || match.data == nil {
		switch cidr.Version() {
		case 4:
			return V4CIDR{}, nil
		case 6:
			return V6CIDR{}, nil
		default:
			logrus.WithField("cidr", cidr).Panic("Invalid CIDR IP version")
		}
	}
	return match.cidr, match.data
}

func (n *CIDRNode) lookupPath(buffer []CIDRTrieEntry, cidr CIDR) []CIDRTrieEntry {
	if n == nil {
		return buffer[:0]
	}

	if n.cidr.Version() != cidr.Version() {
		logrus.WithField("n.cidr", n.cidr).WithField("cidr", cidr).Panic("Mismatched CIDR IP versions")
	}

	if !n.cidr.Contains(cidr.Addr()) {
		// Not in trie.
		return nil
	}

	if n.data != nil {
		buffer = append(buffer, CIDRTrieEntry{CIDR: n.cidr, Data: n.data})
	}

	if cidr == n.cidr {
		if n.data == nil {
			// CIDR is an intermediate node with no data so CIDR isn't actually in the trie.
			return nil
		}
		return buffer
	}

	// If we get here, then this node is a parent of the CIDR we're looking for.
	// Figure out which child to recurse on.
	childIdx := cidr.Addr().NthBit(uint(n.cidr.Prefix() + 1))
	child := n.children[childIdx]
	return child.lookupPath(buffer, cidr)
}

func (n *CIDRNode) get(cidr CIDR) interface{} {
	if n == nil {
		return nil
	}

	if n.cidr.Version() != cidr.Version() {
		logrus.WithField("n.cidr", n.cidr).WithField("cidr", cidr).Panic("Mismatched CIDR IP versions")
	}

	if !n.cidr.Contains(cidr.Addr()) {
		// Not in trie.
		return nil
	}

	if cidr == n.cidr {
		if n.data == nil {
			// CIDR is an intermediate node with no data so CIDR isn't actually in the trie.
			return nil
		}
		return n.data
	}

	// If we get here, then this node is a parent of the CIDR we're looking for.
	// Figure out which child to recurse on.
	childIdx := cidr.Addr().NthBit(uint(n.cidr.Prefix() + 1))
	child := n.children[childIdx]
	return child.get(cidr)
}

func (t *CIDRTrie) CoveredBy(cidr CIDR) bool {
	pfx := CommonPrefix(t.root.cidr, cidr)
	return pfx == cidr
}

func (t *CIDRTrie) Covers(cidr CIDR) bool {
	return t.root.covers(cidr)
}

func (n *CIDRNode) covers(cidr CIDR) bool {
	if n == nil {
		return false
	}

	commonPfx := CommonPrefix(n.cidr, cidr)
	if commonPfx != n.cidr {
		// Not in trie.
		return false
	}

	if n.data != nil {
		return true
	}

	// If we get here, then this node is a parent of the CIDR we're looking for.
	// Figure out which child to recurse on.
	childIdx := cidr.Addr().NthBit(uint(n.cidr.Prefix() + 1))
	child := n.children[childIdx]
	return child.covers(cidr)
}

func (t *CIDRTrie) Intersects(cidr CIDR) bool {
	return t.root.intersects(cidr)
}

func (n *CIDRNode) intersects(cidr CIDR) bool {
	if n == nil {
		return false
	}

	common := CommonPrefix(n.cidr, cidr)

	if common == cidr {
		// This node's CIDR is contained within the target CIDR so we must have
		// some value that is inside the target CIDR.
		return true
	}

	if common != n.cidr {
		// The CIDRs are disjoint.
		return false
	}

	// If we get here, then this node is a parent of the CIDR we're looking for.
	// Figure out which child to recurse on.
	childIdx := cidr.Addr().NthBit(uint(n.cidr.Prefix() + 1))
	child := n.children[childIdx]
	return child.intersects(cidr)
}

func (n *CIDRNode) appendTo(s []CIDRTrieEntry) []CIDRTrieEntry {
	if n == nil {
		return s
	}
	if n.data != nil {
		s = append(s, CIDRTrieEntry{
			CIDR: n.cidr,
			Data: n.data,
		})
	}
	s = n.children[0].appendTo(s)
	s = n.children[1].appendTo(s)
	return s
}

func (n *CIDRNode) visit(f func(cidr CIDR, data interface{}) bool) bool {
	if n == nil {
		return true
	}

	if n.data != nil {
		keepGoing := f(n.cidr, n.data)
		if !keepGoing {
			return false
		}
	}
	keepGoing := n.children[0].visit(f)
	if !keepGoing {
		return false
	}
	return n.children[1].visit(f)
}

func (t *CIDRTrie) ToSlice() []CIDRTrieEntry {
	return t.root.appendTo(nil)
}

func (t *CIDRTrie) Visit(f func(cidr CIDR, data interface{}) bool) {
	t.root.visit(f)
}

func (t *CIDRTrie) Update(cidr CIDR, value interface{}) {
	if value == nil {
		logrus.Panic("Can't store nil in a CIDRTrie")
	}
	parentsPtr := &t.root
	thisNode := t.root

	for {
		if thisNode == nil {
			// We've run off the end of the tree, create new child to hold this data.
			newNode := &CIDRNode{
				cidr: cidr,
				data: value,
			}
			*parentsPtr = newNode
			return
		}

		if thisNode.cidr == cidr {
			// Found a node with exactly this CIDR, just update the data.
			thisNode.data = value
			return
		}

		// If we get here, there are three cases:
		// - CIDR of this node contains the new CIDR, in which case we need look for matching child
		// - The new CIDR contains this node, in which case we need to insert a new node as the parent of this one.
		// - The two CIDRs are disjoint, in which case we need to insert a new intermediate node as the parent of
		//   thisNode and the new CIDR.
		commonPrefix := CommonPrefix(cidr, thisNode.cidr)

		if commonPrefix.Prefix() == thisNode.cidr.Prefix() {
			// Common is this node's CIDR so this node is parent of the new CIDR. Figure out which child to recurse on.
			childIdx := cidr.Addr().NthBit(uint(commonPrefix.Prefix() + 1))
			parentsPtr = &thisNode.children[childIdx]
			thisNode = thisNode.children[childIdx]
			continue
		}

		if commonPrefix.Prefix() == cidr.Prefix() {
			// Common is new CIDR so this node is a child of the new CIDR. Insert new node.
			newNode := &CIDRNode{
				cidr: cidr,
				data: value,
			}
			childIdx := thisNode.cidr.Addr().NthBit(uint(commonPrefix.Prefix() + 1))
			newNode.children[childIdx] = thisNode
			*parentsPtr = newNode
			return
		}

		// Neither CIDR contains the other.  Create an internal node with this node and new CIDR as children.
		newInternalNode := &CIDRNode{
			cidr: commonPrefix,
		}
		childIdx := thisNode.cidr.Addr().NthBit(uint(commonPrefix.Prefix() + 1))
		newInternalNode.children[childIdx] = thisNode
		newInternalNode.children[1-childIdx] = &CIDRNode{
			cidr: cidr,
			data: value,
		}
		*parentsPtr = newInternalNode
		return
	}
}

func CommonPrefix(a, b CIDR) CIDR {
	if a.Version() != b.Version() {
		logrus.WithField("a", a).WithField("b", b).Panic("Mismatched CIDR IP versions")
	}

	var cidr CIDR
	switch a.Version() {
	case 4:
		cidr = V4CommonPrefix(a.(V4CIDR), b.(V4CIDR))
	case 6:
		cidr = V6CommonPrefix(a.(V6CIDR), b.(V6CIDR))
	default:
		logrus.WithField("a", a).Panic("Invalid CIDR IP version")
	}

	return cidr
}

func V4CommonPrefix(a, b V4CIDR) V4CIDR {
	var result V4CIDR
	var maxLen uint8
	if b.prefix < a.prefix {
		maxLen = b.prefix
	} else {
		maxLen = a.prefix
	}

	a32 := a.addr.AsUint32()
	b32 := b.addr.AsUint32()

	xored := a32 ^ b32 // Has a zero bit wherever the two values are the same.
	commonPrefixLen := uint8(bits.LeadingZeros32(xored))
	if commonPrefixLen > maxLen {
		result.prefix = maxLen
	} else {
		result.prefix = commonPrefixLen
	}

	mask := uint32(0xffffffff) << (32 - result.prefix)
	commonPrefix32 := mask & a32
	binary.BigEndian.PutUint32(result.addr[:], commonPrefix32)

	return result
}

func V6CommonPrefix(a, b V6CIDR) V6CIDR {
	var result V6CIDR
	var maxLen uint8

	if b.prefix < a.prefix {
		maxLen = b.prefix
	} else {
		maxLen = a.prefix
	}

	a_h, a_l := a.addr.AsUint64Pair()
	b_h, b_l := b.addr.AsUint64Pair()

	xored_h := a_h ^ b_h // Has a zero bit wherever the two values are the same.
	xored_l := a_l ^ b_l

	commonPrefixLen := uint8(bits.LeadingZeros64(xored_h))

	if xored_h == 0 {
		// This means a_h == b_h and commonPrefixLen will be > 64. The first
		// 8 bytes of the result will be equal to a_h (and b_h), last 8 will
		// be the common prefix of a_l and b_l.
		commonPrefixLen = 64 + uint8(bits.LeadingZeros64(xored_l))
		binary.BigEndian.PutUint64(result.addr[:8], a_h)
		if commonPrefixLen > maxLen {
			result.prefix = maxLen
		} else {
			result.prefix = commonPrefixLen
		}
		mask := uint64(0xffffffffffffffff) << (128 - result.prefix)
		commonPrefix64 := mask & a_l
		binary.BigEndian.PutUint64(result.addr[8:], commonPrefix64)
	} else {
		// This means commonPrefixLen will be < 64. Just the first 8 bytes of
		// the result will be filled with the common prefix of a_h and b_h,
		// last 8 will be 0.
		if commonPrefixLen > maxLen {
			result.prefix = maxLen
		} else {
			result.prefix = commonPrefixLen
		}
		mask := uint64(0xffffffffffffffff) << (64 - result.prefix)
		commonPrefix64 := mask & a_h
		binary.BigEndian.PutUint64(result.addr[:8], commonPrefix64)
	}

	return result
}
