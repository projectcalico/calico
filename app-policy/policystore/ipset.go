// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package policystore

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	syncapi "github.com/projectcalico/calico/app-policy/proto"

	envoyapi "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	log "github.com/sirupsen/logrus"
)

// IPSet is a data structure that contains IP addresses, or IP address/port pairs. It allows fast membership tests
// of Address objects from the authorization API.
type IPSet interface {
	// Idempotent add IP address to set.
	// ip depends on the IPSet type:
	// IP          - Each member is an IP address in dotted-decimal or IPv6 format.
	// IP_AND_PORT - Each member is "<IP>,(tcp|udp):<port-number>"
	// NET         - Each member is a CIDR (note individual IPs can be full-length prefixes)
	AddString(ip string)

	// Idempotent remove IP address from set.
	// ip depends on the IPSet type:
	// IP          - Each member is an IP address in dotted-decimal or IPv6 format.
	// IP_AND_PORT - Each member is "<IP>,(tcp|udp):<port-number>"
	// NET         - Each member is a CIDR. Only removes exact matches.
	RemoveString(ip string)

	// Test if the address is contained in the set.
	ContainsAddress(addr *envoyapi.Address) bool
}

// We'll use golang's map type under the covers here because it is simple to implement.
type ipMapSet map[string]bool
type ipPortMapSet map[string]bool

// NewIPSet creates an IPSet of the appropriate type given by t.
func NewIPSet(t syncapi.IPSetUpdate_IPSetType) IPSet {
	switch t {
	case syncapi.IPSetUpdate_IP:
		return ipMapSet{}
	case syncapi.IPSetUpdate_IP_AND_PORT:
		return ipPortMapSet{}
	case syncapi.IPSetUpdate_NET:
		return ipNetSet{v4: &trieNode{}, v6: &trieNode{}}
	}
	panic("Unrecognized IPSet type")
}

func (m ipMapSet) AddString(ip string) {
	m[ip] = true
}

func (m ipMapSet) RemoveString(ip string) {
	delete(m, ip)
}

func (m ipMapSet) ContainsAddress(addr *envoyapi.Address) bool {
	sck := addr.GetSocketAddress()
	key := sck.GetAddress()
	log.WithFields(log.Fields{
		"proto": addr.String(),
		"key":   key,
	}).Debug("Finding address in ipMapSet", addr)
	return m[key]
}

func (m ipPortMapSet) AddString(ip string) {
	m[ip] = true
}

func (m ipPortMapSet) RemoveString(ip string) {
	delete(m, ip)
}

func (m ipPortMapSet) ContainsAddress(addr *envoyapi.Address) bool {
	sck := addr.GetSocketAddress()
	p := strings.ToLower(sck.GetProtocol().String())
	key := fmt.Sprintf("%v,%v:%d", sck.GetAddress(), p, sck.GetPortValue())
	log.WithFields(log.Fields{
		"proto": addr.String(),
		"key":   key,
	}).Debug("Finding address in ipPortMapSet", addr)
	return m[key]
}

// ipNetSet implements an IPSet of type NET, where the members are CIDRs.  These sets are a combination of endpoint IPs
// and CIDRs from network sets. We expect at scale for there to be a large number of endpoint IPs and relatively few
// network set entries.
type ipNetSet struct {
	v4 *trieNode
	v6 *trieNode
}

// trieNode implements a modified trie. We use a traditional trie to store the network prefixes. For IP addresses, we
// use the trie down to the last 8-bits, but then switch to a bitmap after that. This is because we expect a large
// number of IPs, so don't want to balloon the bottom tier of the tree.
type trieNode struct {
	// member is true if this node is member of the set, i.e. the set contains a network CIDR corresponding to this
	// node.
	member bool

	// bitmap points to a networkBitmap.
	bitmap *networkBitmap

	// children points to the children of this node. A nil pointer indicates the child is not part of the tree.
	children [2]*trieNode
}

const BitmapSize = 4

type networkBitmap [BitmapSize]uint64

func (m ipNetSet) AddString(network string) {
	ip, mask := parseCIDR(network)
	ip4 := ip.To4()
	if ip4 != nil && mask <= 32 {
		m.v4.insert(ip4, 0, mask, 24)
	} else if mask <= 128 {
		m.v6.insert(ip, 0, mask, 120)
	} else {
		log.WithField("network", network).Panic("invalid CIDR mask length")
	}
}

func (m ipNetSet) RemoveString(network string) {
	ip, mask := parseCIDR(network)
	ip4 := ip.To4()
	if ip4 != nil && mask <= 32 {
		m.v4.remove(ip4, 0, mask)
	} else if mask <= 128 {
		m.v6.remove(ip, 0, mask)
	} else {
		log.WithField("network", network).Panic("invalid CIDR mask length")
	}
}

func (m ipNetSet) ContainsAddress(addr *envoyapi.Address) bool {
	ip := net.ParseIP(addr.GetSocketAddress().GetAddress())
	if ip == nil {
		// Envoy should not send us malformed IP addresses, but its possible we could get requests from non-IP
		// connections, like Pipes.
		log.WithField("addr", ip).Warn("could not parse IP")
		return false
	}
	ip4 := ip.To4()
	if ip4 != nil {
		return m.v4.containsIP(ip4, 0)
	} else {
		return m.v6.containsIP(ip, 0)
	}
}

func (n *trieNode) insert(ip net.IP, depth, mask, bitmapDepth uint64) {
	if depth == mask {
		// found!
		n.member = true
		return
	}
	if depth == bitmapDepth && mask == (bitmapDepth+8) {
		// This is an IP address (not prefix) and we are at the depth to use the bitmap.
		last := ip[len(ip)-1]
		n.bitmap.setAt(last, 1)
		return
	}
	// If we get here, we need to keep looking deeper in the trie.
	b := getBitAt(ip, depth)
	next := n.children[b]
	if next == nil {
		next = &trieNode{}
		n.children[b] = next
		if depth+1 == bitmapDepth {
			// initializing node at depth with bitmap.
			next.bitmap = &networkBitmap{}
		}
	}
	next.insert(ip, depth+1, mask, bitmapDepth)
}

func (n *trieNode) remove(ip net.IP, depth, mask uint64) {
	if depth == mask {
		// found!
		n.member = false
	} else if n.bitmap != nil && mask == (depth+8) {
		// We are at the bitmap depth and the mask has 8 more bits, so this must be an IP address.
		last := ip[len(ip)-1]
		n.bitmap.setAt(last, 0)
	} else {
		// keep looking deeper
		b := getBitAt(ip, depth)
		next := n.children[b]
		if next != nil {
			next.remove(ip, depth+1, mask)
			if next.okToRemove() {
				n.children[b] = nil
			}
		}
	}
}

// okToRemove checks if the trieNode can be removed from the trie
func (n *trieNode) okToRemove() bool {
	if n.member {
		return false
	}
	for _, c := range n.children {
		if c != nil {
			// Still has a child, can't remove
			return false
		}
	}
	if n.bitmap == nil {
		// not a bitmap node, so OK to remove.
		return true
	}
	return n.bitmap.isEmpty()
}

func (n *trieNode) containsIP(ip net.IP, depth uint64) bool {
	if n.member {
		return true
	}
	if n.bitmap != nil {
		last := ip[len(ip)-1]
		return n.bitmap.contains(last)
	}
	b := getBitAt(ip, depth)
	next := n.children[b]
	if next != nil {
		return next.containsIP(ip, depth+1)
	}
	return false
}

func (bm *networkBitmap) isEmpty() bool {
	for i := 0; i < BitmapSize; i++ {
		if bm[i] != 0 {
			// Still has IP addresses bitmapped
			return false
		}
	}
	return true
}

func (bm *networkBitmap) setAt(index, value byte) {
	ii := index / 64
	bi := index % 64
	if value == 0 {
		bm[ii] = bm[ii] &^ (1 << bi)
	} else {
		bm[ii] = bm[ii] | (1 << bi)
	}
}

func (bm *networkBitmap) contains(index byte) bool {
	ii := index / 64
	bi := index % 64
	return (bm[ii] & (1 << bi)) != 0
}

func getBitAt(ip net.IP, depth uint64) byte {
	by := depth / 8
	bi := 7 - depth%8
	return (ip[by] & (1 << bi)) >> bi
}

func parseCIDR(network string) (net.IP, uint64) {
	r := strings.Split(network, "/")
	addr := r[0]
	mask, err := strconv.ParseUint(r[1], 10, 64)
	if err != nil {
		log.WithField("network", network).Panic("bad CIDR")
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		log.WithField("network", network).Panic("bad CIDR IP")
	}
	return ip, mask
}
