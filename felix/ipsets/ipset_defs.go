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
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex"
)

var (
	gaugeVecNumCalicoIpsets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_ipsets_calico",
		Help: "Number of active Calico IP sets.",
	}, []string{"ip_version"})
	gaugeNumTotalIpsets = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_ipsets_total",
		Help: "Total number of active IP sets.",
	})
	countNumIPSetCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_calls",
		Help: "Number of ipset commands executed.",
	})
	countNumIPSetErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_errors",
		Help: "Number of ipset command failures.",
	})
	countNumIPSetLinesExecuted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipset_lines_executed",
		Help: "Number of ipset operations executed.",
	})
	summaryExecStart = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_exec_time_micros",
		Help: "Summary of time taken to fork/exec child processes",
	})
)

func init() {
	prometheus.MustRegister(gaugeVecNumCalicoIpsets)
	prometheus.MustRegister(gaugeNumTotalIpsets)
	prometheus.MustRegister(countNumIPSetCalls)
	prometheus.MustRegister(countNumIPSetErrors)
	prometheus.MustRegister(countNumIPSetLinesExecuted)
	prometheus.MustRegister(summaryExecStart)
}

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
	Protocol labelindex.IPSetPortProtocol
}

func (p V4IPPort) String() string {
	return fmt.Sprintf("%s,%s:%d", p.IP.String(), p.Protocol.String(), p.Port)
}

type V6IPPort struct {
	IP       ip.V6Addr
	Port     uint16
	Protocol labelindex.IPSetPortProtocol
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
	SetID    string
	Type     IPSetType
	MaxSize  int
	RangeMin int
	RangeMax int
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
