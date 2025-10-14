// Copyright (c) 2017-2023 Tigera, Inc. All rights reserved.
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

package ipsets

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/proto"
)

const MaxIPSetNameLength = 31

const IPSetNamePrefix = "cali"

// IPSetType constants for the different kinds of IP set.
type IPSetType string

const (
	IPSetTypeHashIP     IPSetType = "hash:ip"
	IPSetTypeHashIPPort IPSetType = "hash:ip,port"
	IPSetTypeHashNet    IPSetType = "hash:net"
	IPSetTypeBitmapPort IPSetType = "bitmap:port"
	IPSetTypeHashNetNet IPSetType = "hash:net,net"
)

var AllIPSetTypes = []IPSetType{
	IPSetTypeHashIP,
	IPSetTypeHashIPPort,
	IPSetTypeHashNet,
	IPSetTypeBitmapPort,
	IPSetTypeHashNetNet,
}

type V4IPPort struct {
	IP       ip.V4Addr
	Port     uint16
	Protocol ipsetmember.Protocol
}

func (p V4IPPort) String() string {
	return fmt.Sprintf("%s,%s:%d", p.IP.String(), p.Protocol.String(), p.Port)
}

type V6IPPort struct {
	IP       ip.V6Addr
	Port     uint16
	Protocol ipsetmember.Protocol
}

func (p V6IPPort) String() string {
	return fmt.Sprintf("%s,%s:%d", p.IP.String(), p.Protocol.String(), p.Port)
}

type Port uint16

func (p Port) String() string {
	return fmt.Sprintf("%d", p)
}

func (t IPSetType) IsMemberIPV6(member string) bool {
	switch t {
	case IPSetTypeHashIP, IPSetTypeHashNet:
		return strings.Contains(member, ":")
	case IPSetTypeHashIPPort:
		return strings.Contains(strings.Split(member, ",")[0], ":")
	case IPSetTypeHashNetNet:
		cidrs := strings.Split(member, ",")
		if len(cidrs) != 2 {
			log.WithField("member", member).Panic("Is not type IPSetTypeHashNetNet")
		}
		cidr1 := strings.Contains(cidrs[0], ":")
		cidr2 := strings.Contains(cidrs[1], ":")

		if cidr1 != cidr2 {
			log.WithField("member", member).Panic("Each cidr has different version")
		}

		return cidr1
	case IPSetTypeBitmapPort:
		return strings.HasPrefix(member, "v6,")
	}
	log.WithField("type", string(t)).Panic("Unknown IPSetType")
	return false
}

type rawIPSetMember string

func (r rawIPSetMember) String() string {
	return string(r)
}

type IPSetMember interface {
	String() string
}

type netNet struct {
	cidr1, cidr2 ip.CIDR
}

func (nn netNet) String() string {
	return nn.cidr1.String() + "," + nn.cidr2.String()
}

func (t IPSetType) IsValid() bool {
	switch t {
	case IPSetTypeHashIP, IPSetTypeHashNet, IPSetTypeHashIPPort, IPSetTypeHashNetNet, IPSetTypeBitmapPort:
		return true
	}
	return false
}

// IPFamily constants for the names that the ipset command uses for the IP versions.
type IPFamily string

const (
	IPFamilyV4 = IPFamily("inet")
	IPFamilyV6 = IPFamily("inet6")
)

func (f IPFamily) IsValid() bool {
	switch f {
	case IPFamilyV4, IPFamilyV6:
		return true
	}
	return false
}

func (f IPFamily) Version() int {
	switch f {
	case IPFamilyV4:
		return 4
	case IPFamilyV6:
		return 6
	}
	return 0
}

// IPSetMetadata contains the metadata for a particular IP set, such as its name, type and size.
type IPSetMetadata struct {
	SetID      string
	Type       IPSetType
	UpdateType proto.IPSetUpdate_IPSetType
	MaxSize    int
	RangeMin   int
	RangeMax   int
}

// IPVersionConfig wraps up the metadata for a particular IP version.  It can be used by
// this and other components to calculate IP set names from IP set IDs, for example.
type IPVersionConfig struct {
	Family                IPFamily
	setNamePrefix         string
	tempSetNamePrefix     string
	mainSetNamePrefix     string
	ourNamePrefixesRegexp *regexp.Regexp
}

const (
	// mainIpsetToken is the character that we append to the versioned prefix "cali4" or "cali6" to
	// get the main IP set name prefix.   To minimise the length of the prefix (and hence preserve
	// as much entropy as possible in the IP set ID) we use this as a version number, and
	// increment it when making breaking changes to the IP set format.  In particular, this must
	// be changed if the type of the IP set is changed because the kernel doesn't support the
	// "ipset swap" operation unless the two IP sets to be swapped share a type.
	//
	// The first "version" used "-" for the token.
	mainIpsetToken = "0"
	// tempIpsetToken similarly, for the temporary copy of each IP set.  Typically, this doesn't
	// need to be changed because we delete and recreate the temporary IP set before using it.
	tempIpsetToken = "t"
)

func NewIPVersionConfig(
	family IPFamily,
	namePrefix string,
	allHistoricPrefixes []string,
	extraUnversionedIPSets []string,
) *IPVersionConfig {
	var version string
	switch family {
	case IPFamilyV4:
		version = "4"
	case IPFamilyV6:
		version = "6"
	}
	versionedPrefix := namePrefix + version
	var versionedPrefixes []string
	versionedPrefixes = append(versionedPrefixes, namePrefix+version)
	for _, prefix := range allHistoricPrefixes {
		versionedPrefixes = append(versionedPrefixes, prefix+version)
	}
	versionedPrefixes = append(versionedPrefixes, extraUnversionedIPSets...)
	for i, pfx := range versionedPrefixes {
		versionedPrefixes[i] = regexp.QuoteMeta(pfx)
	}
	ourNamesPattern := "^(" + strings.Join(versionedPrefixes, "|") + ")"
	log.WithField("regexp", ourNamesPattern).Debug("Calculated IP set name regexp.")
	ourNamesRegexp := regexp.MustCompile(ourNamesPattern)

	return &IPVersionConfig{
		Family:                family,
		setNamePrefix:         versionedPrefix,
		tempSetNamePrefix:     versionedPrefix + tempIpsetToken,
		mainSetNamePrefix:     versionedPrefix + mainIpsetToken,
		ourNamePrefixesRegexp: ourNamesRegexp,
	}
}

func (c IPVersionConfig) NameForTempIPSet(n uint) string {
	return fmt.Sprint(c.tempSetNamePrefix, n)
}

// NameForMainIPSet converts the given IP set ID (example: "qMt7iLlGDhvLnCjM0l9nzxbabcd"), to
// a name for use in the dataplane.  The return value will have the configured prefix and is
// guaranteed to be short enough to use as an ipset name (example:
// "cali60s:qMt7iLlGDhvLnCjM0l9nzxb").
func (c IPVersionConfig) NameForMainIPSet(setID string) string {
	// Since IP set IDs are chosen with a secure hash already, we can simply truncate them
	// to length to get maximum entropy.
	return combineAndTrunc(c.mainSetNamePrefix, setID, MaxIPSetNameLength)
}

// OwnsIPSet returns true if the given IP set name appears to belong to Felix.  i.e. whether it
// starts with an expected prefix.
func (c IPVersionConfig) OwnsIPSet(setName string) bool {
	return c.ourNamePrefixesRegexp.MatchString(setName)
}

func (c IPVersionConfig) IsTempIPSetName(setName string) bool {
	return strings.HasPrefix(setName, c.tempSetNamePrefix)
}

// combineAndTrunc concatenates the given prefix and suffix and truncates the result to maxLength.
func combineAndTrunc(prefix, suffix string, maxLength int) string {
	combined := prefix + suffix
	if len(combined) > maxLength {
		return combined[0:maxLength]
	} else {
		return combined
	}
}

func StripIPSetNamePrefix(ipSetName string) string {
	prefixLen := len(IPSetNamePrefix) + 2 // "cali40"
	if len(ipSetName) < prefixLen {
		return ""
	}
	return ipSetName[prefixLen:]
}

type UpdateListener interface {
	// CaresAboutIPSet allows for skipping notifications for IP sets that are
	// not of interest to the listener. If this method returns false for a
	// given IP set, no notifications will be sent for that IP set.
	CaresAboutIPSet(ipSetName string) bool
	OnMemberProgrammed(rawIPSetMember string)
}

// CanonicaliseMember converts the string representation of an IP set member to a canonical
// object of some kind.  The object is required to by hashable.
func CanonicaliseMember(t IPSetType, member string) IPSetMember {
	switch t {
	case IPSetTypeHashIP:
		// Convert the string into our ip.Addr type, which is backed by an array.
		ipAddr := ip.FromIPOrCIDRString(member)
		if ipAddr == nil {
			// This should be prevented by validation in libcalico-go.
			log.WithField("ip", member).Panic("Failed to parse IP")
		}
		return ipAddr
	case IPSetTypeHashIPPort:
		// The member should be of the format <IP>,(tcp|udp):<port number>
		parts := strings.Split(member, ",")
		if len(parts) != 2 {
			log.WithField("member", member).Panic("Failed to parse IP,port IP set member")
		}
		ipAddr := ip.FromString(parts[0])
		if ipAddr == nil {
			// This should be prevented by validation.
			log.WithField("member", member).Panic("Failed to parse IP part of IP,port member")
		}
		// parts[1] should contain "(tcp|udp|sctp):<port number>"
		parts = strings.Split(parts[1], ":")
		var proto ipsetmember.Protocol
		switch strings.ToLower(parts[0]) {
		case "udp":
			proto = ipsetmember.ProtocolUDP
		case "tcp":
			proto = ipsetmember.ProtocolTCP
		case "sctp":
			proto = ipsetmember.ProtocolSCTP
		default:
			log.WithField("member", member).Panic("Unknown protocol")
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			log.WithField("member", member).WithError(err).Panic("Bad port")
		}
		if port > math.MaxUint16 || port < 0 {
			log.WithField("member", member).Panic("Bad port range (should be between 0 and 65535)")
		}
		// Return a dedicated struct for V4 or V6.  This slightly reduces occupancy over storing
		// the address as an interface by storing one fewer interface headers.  That is worthwhile
		// because we store many IP set members.
		if ipAddr.Version() == 4 {
			return V4IPPort{
				IP:       ipAddr.(ip.V4Addr),
				Port:     uint16(port),
				Protocol: proto,
			}
		} else {
			return V6IPPort{
				IP:       ipAddr.(ip.V6Addr),
				Port:     uint16(port),
				Protocol: proto,
			}
		}
	case IPSetTypeHashNet:
		// Convert the string into our ip.CIDR type, which is backed by a struct.  When
		// pretty-printing, the hash:net ipset type prints IPs with no "/32" or "/128"
		// suffix.
		return ip.MustParseCIDROrIP(member)
	case IPSetTypeBitmapPort:
		// Trim the family if it exists
		if member[0] == 'v' {
			member = member[3:]
		}
		port, err := strconv.Atoi(member)
		if err == nil && port >= 0 && port <= 0xffff {
			return Port(port)
		}
	case IPSetTypeHashNetNet:
		cidrs := strings.Split(member, ",")
		return netNet{
			cidr1: ip.MustParseCIDROrIP(cidrs[0]),
			cidr2: ip.MustParseCIDROrIP(cidrs[1]),
		}
	}
	log.WithField("type", string(t)).Panic("Unknown IPSetType")
	return nil
}
