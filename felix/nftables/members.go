// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
)

// SetMember represents a member of an nftables set.
type SetMember interface {
	ipsets.IPSetMember
	Key() []string
}

var (
	// Assert that all structs implement the SetMember interface.
	_ SetMember = simpleMember("")
	_ SetMember = v4IPPortMember{}
	_ SetMember = v6IPPortMember{}
	_ SetMember = netNet{}
	_ SetMember = unknownMember{}
)

type netNet struct {
	net1, net2 ip.CIDR
}

func (n netNet) Key() []string {
	// nftables doesn't support interval types (CIDRs) on concatenation sets, and thus we
	// can only represent the set as a concatenation of IP addresses. Conveniently, the only
	// current use of this type is for WorkloadEndpoint IP addresses which are always /32 or /128.
	if n.net1.Version() == 4 && n.net1.Prefix() != 32 || n.net1.Version() == 6 && n.net1.Prefix() != 128 {
		logrus.WithField("cidr", n.net1).Panic("Unexpected CIDR prefix")
	}
	if n.net2.Version() == 4 && n.net2.Prefix() != 32 || n.net2.Version() == 6 && n.net2.Prefix() != 128 {
		logrus.WithField("cidr", n.net2).Panic("Unexpected CIDR prefix")
	}
	return []string{n.net1.Addr().String(), n.net2.Addr().String()}
}

func (n netNet) String() string {
	return fmt.Sprintf("%s . %s", n.net1, n.net2)
}

// simpleMember represents a member of a simple, non-concatenated nftables set that is a single element.
type simpleMember string

func (m simpleMember) Key() []string {
	return []string{string(m)}
}

func (m simpleMember) String() string {
	return string(m)
}

// v4IPPortMember is a struct that represents an IPv4 address, protocol and port for IPv4, and implements
// the SetMember interface.
type v4IPPortMember struct {
	IP       ip.V4Addr
	Port     uint16
	Protocol string
}

func (p v4IPPortMember) Key() []string {
	return []string{p.IP.String(), p.Protocol, strconv.Itoa(int(p.Port))}
}

func (p v4IPPortMember) String() string {
	// This is a concatination of IP, protocol and port. Format it back into Felix's internal representation.
	return fmt.Sprintf("%s,%s:%d", p.IP, p.Protocol, p.Port)
}

// v6IPPortMember is a struct that represents an IPv6 address, protocol and port for IPv6, and implements
// the SetMember interface.
type v6IPPortMember struct {
	IP       ip.V6Addr
	Port     uint16
	Protocol string
}

func (p v6IPPortMember) Key() []string {
	return []string{p.IP.String(), p.Protocol, strconv.Itoa(int(p.Port))}
}

func (p v6IPPortMember) String() string {
	// This is a concatination of IP, protocol and port. Format it back into Felix's internal representation.
	return fmt.Sprintf("%s,%s:%d", p.IP, p.Protocol, p.Port)
}

func UnknownMember(k []string) SetMember {
	logrus.WithField("key", k).Warn("Unknown member type")
	return unknownMember{
		concat: strings.Join(k, " . "),
	}
}

// unknownMember is a struct that represents a set member that we do not know how to parse.
type unknownMember struct {
	concat string
}

func (u unknownMember) Key() []string {
	return strings.Split(u.concat, " . ")
}

func (u unknownMember) String() string {
	return u.concat
}
